/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstring>
#include <string>
#include <vector>

#include <l4/cxx/ref_ptr>
#include <l4/cxx/ref_ptr_list>
#include <l4/cxx/unique_ptr>
#include <l4/re/error_helper>
#include <l4/sys/factory>
#include <l4/sys/cxx/ipc_epiface>

#include <l4/libblock-device/debug.h>
#include <l4/libblock-device/device.h>
#include <l4/libblock-device/errand.h>
#include <l4/libblock-device/partition.h>
#include <l4/libblock-device/part_device.h>

namespace Block_device {

/**
 * Basic class that scans devices and handles client connections.
 *
 * \tparam IF Class that will handle the client.
 */
template <typename IF>
class Device_mgr
{
  using Client_type = IF;

  /**
   * A client that is waiting for a device (yet) unknown to the manager.
   */
  struct Pending_client
  {
    /** Device ID requested for the client. */
    std::string device_id;
    /** The name of the IPC gate assigned to the client. */
    L4::Cap<L4::Rcv_endpoint> gate;
    /** Number of dataspaces to allocate. */
    int num_ds;

    Pending_client() = default;

    Pending_client(L4::Cap<L4::Rcv_endpoint> g, std::string const &dev, int ds)
    : device_id(dev), gate(g), num_ds(ds)
    {}
  };

  class Connection : public cxx::Ref_obj_list_item<Connection>
  {
  public:
    explicit Connection(cxx::Ref_ptr<Device> &&dev)
    : _device(cxx::move(dev))
    {}

    L4::Cap<void> cap() const
    { return _interface ? _interface->obj_cap() : L4::Cap<void>(); }

    void start_disk_scan(Errand::Callback const &callback)
    {
      _device->start_device_scan(
        [=]()
          {
            auto reader = cxx::make_ref_obj<Partition_reader>(_device.get());
            reader->read(
              [=]()
                {
                  add_partitions(*reader.get());
                  callback();
                });
          });
    }

    void unregister_interfaces(L4::Registry_iface *registry) const
    {
      if (_interface)
        registry->unregister_obj(_interface.get());

      for (auto *sub : _subs)
        sub->unregister_interfaces(registry);
    }

    int create_interface_for(Pending_client *c,
                             L4::Registry_iface *registry)
    {
      if (_interface)
        return contains_device(c->device_id) ? -L4_EBUSY : -L4_ENODEV;

      // check for match in partitions

      bool busy = false;
      for (auto *sub : _subs)
        {
          if (sub->_interface)
            busy = true;

          int ret = sub->create_interface_for(c, registry);

          if (ret != -L4_ENODEV) // includes L4_EOK
            return ret;
        }

      if (!match_hid(c->device_id))
        return -L4_ENODEV;

      if (busy)
        return -L4_EBUSY;

      auto clt = cxx::make_unique<Client_type>(_device, c->num_ds);

      if (c->gate.is_valid())
        {
          if (!clt->register_obj(registry, c->gate).is_valid())
            return -L4_ENOMEM;
        }
      else
        {
          c->gate = L4::cap_reinterpret_cast<L4::Rcv_endpoint>(
                      clt->register_obj(registry));
          if (!c->gate.is_valid())
            return -L4_ENOMEM;
        }

      _interface.reset(clt.release());

      return L4_EOK;
    }

  private:
    /**
     * Create sub devices from a partition list.
     *
     * \param reader  Partition reader to read the partition info from.
     *
     * For more information of partition devices, see Partitioned_device.
     */
    void add_partitions(Partition_reader const &reader)
    {
      l4_size_t sz = reader.table_size();

      for (l4_size_t i = 1; i <= sz; ++i)
        {
          Partition_info info;
          if (reader.get_partition(i, &info) < 0)
            continue;

          Device *pdev = new Partitioned_device(_device, i, info);
          auto conn = cxx::make_ref_obj<Connection>(cxx::Ref_ptr<Device>(pdev));
          _subs.push_front(std::move(conn));
        }
    }

    bool contains_device(std::string const &name) const
    {
      if (match_hid(name))
        return true;

      for (auto *sub : _subs)
        if (sub->contains_device(name))
          return true;

      return false;
    }

    bool match_hid(std::string const &name) const
    { return _device->match_hid(cxx::String(name.c_str(), name.length())); }

    /// The device itself.
    cxx::Ref_ptr<Device> _device;
    /// Client interface.
    cxx::unique_ptr<L4::Epiface> _interface;
    /// Partitions of the device.
    cxx::Ref_ptr_list<Connection> _subs;
  };

public:
  Device_mgr(L4::Registry_iface *registry)
  : _registry(registry)
  {}

  virtual ~Device_mgr()
  {
    for (auto *c : _connpts)
      c->unregister_interfaces(_registry);
  }

  int add_static_client(char const *description)
  {
    char const *capname = description;
    char *sep = strchr(capname, ',');
    if (!sep)
      {
        Dbg::info().printf("Missing disk_id in static cap specification.");
        return -1;
      }
    int capnamelen = sep - capname;

    char const *devname = sep + 1;
    sep = strchr(devname, ',');
    if (!sep)
      {
        Dbg::info().printf("Missing number of dataspaces for static capability.");
        return -1;
      }
    std::string device(devname, sep - devname);

    char *endp;
    long numds = strtol(sep + 1, &endp, 10);
    if (!*(sep + 1) || *endp)
      {
        Err().printf("Cannot parse number of dataspaces in static capability.\n");
        return -L4_EINVAL;
      }

    if (numds <= 0 || numds > 255)
      {
        Err().printf("Number of dataspaces out of range in static capability.\n");
        return -L4_EINVAL;
      }

    auto cap = L4Re::Env::env()->get_cap<L4::Rcv_endpoint>(capname, capnamelen);
    if (!cap.is_valid())
      {
        Err().printf("Client capability '%.*s' not valid.\n",
                     capnamelen, capname);
        return -L4_ENODEV;
      }

    _pending_clients.emplace_back(cap, device, numds);

    return L4_EOK;
  }

  int add_static_client(L4::Cap<L4::Rcv_endpoint> client, const char *device,
                        int partno, int num_ds)
  {
    char _buf[30];
    const char *buf;

    if (partno == 0)
      {
        Err().printf("Invalid partition number 0.\n");
        return -L4_ENODEV;
      }

    if (partno != -1)
      {
        /* Could we avoid to make a string here and parsing this again
         * deeper in the stack? */
        snprintf(_buf, sizeof(_buf), "%s:%d", device, partno);
        buf = _buf;
      }
    else
      buf = device;

    _pending_clients.emplace_back(client, buf, num_ds);

    return L4_EOK;
  }

  int create_dynamic_client(std::string const &device, int partno, int num_ds,
                            L4::Cap<void> *cap)
  {
    Pending_client clt;

    // Maximum number of dataspaces that can be registered.
    clt.num_ds = num_ds;

    clt.device_id = device;

    if (partno > 0)
      {
        clt.device_id += ':';
        clt.device_id += std::to_string(partno);
      }

    for (auto *c : _connpts)
      {
        int ret = c->create_interface_for(&clt, _registry);

        if (ret == -L4_ENODEV)
          continue;

        if (ret < 0)
          return ret;

        // found the requested device
        *cap = clt.gate;
        return L4_EOK;
      }

    return -L4_ENODEV;
  }


  void add_disk(cxx::Ref_ptr<Device> &&device, Errand::Callback const &callback)
  {
    auto conn = cxx::make_ref_obj<Connection>(std::move(device));

    conn->start_disk_scan(
      [=]()
        {
          _connpts.push_front(conn);
          connect_static_clients(conn.get());
          callback();
        });
  }

private:
  void connect_static_clients(Connection *con)
  {
    for (auto &c : _pending_clients)
      {
        Dbg::trace().printf("Checking existing client %s\n", c.device_id.c_str());
        if (!c.gate.is_valid())
          continue;

        int ret = con->create_interface_for(&c, _registry);

        if (ret == L4_EOK)
          {
            c.gate = L4::Cap<L4::Rcv_endpoint>();
            // There might be other clients waiting for other partitions.
            // Continue search.
            continue;
          }

        if (ret != -L4_ENODEV)
          break;
      }
  }


  /// Registry new client connections subscribe to.
  L4::Registry_iface *_registry;
  /// List of devices with their potential clients.
  cxx::Ref_ptr_list<Connection> _connpts;
  /// List of clients waiting for a device to appear.
  std::vector<Pending_client> _pending_clients;
};

/**
 * Mixin that provides a factory interface for a device manager.
 *
 * \tparam Base class, must inherit from Device_mgr().
 *
 * Implements a create function that expects the following parameters:
 *
 *   create(L4virtio::Device cap, l4_mword_t num_ds, char const *device)
 *
 * where `num_ds` is the maximum number of dataspaces the client may create
 * and `device` the name of the device. If the client should use an entire
 * disk, then the name corresponds to the name of the disk. To connect to
 * a single partition, either the UUID of the partition or a name of the
 * form <diskid>:<partitionid>  may be used. In the latter case, partitions
 * are taken in the order found in the partition table with the first
 * partition starting at 1.
 */
template <typename BASE>
class Device_factory
: public L4::Epiface_t<Device_factory<BASE>, L4::Factory>
{
public:
  long op_create(L4::Factory::Rights,
                 L4::Ipc::Cap<void> &res, l4_mword_t,
                 L4::Ipc::Varg_list_ref valist)
  {
    Dbg::trace().printf("Client requests connection.\n");

    L4::Ipc::Varg param = valist.next();

    if (!param.is_of<l4_mword_t>())
      {
        Dbg::warn().printf("Expect number of dataspaces in first parameter.\n");
        return -L4_EINVAL;
      }

    // Maximum number of dataspaces that can be registered.
    int num_ds = param.value<l4_mword_t>();
    if (num_ds <= 0 || num_ds > 256) // sanity check with arbitrary limit
      {
        Dbg::warn().printf("Number of dataspaces in first parameter must be between 1 and 256.\n");
        return -L4_EINVAL;
      }

    param = valist.next();

    // Name of device.
    if (!param.is_of<char const *>())
      {
        Dbg::warn().printf("Expect device name as second parameter.\n");
        return -L4_EINVAL;
      }

    std::string device_id(param.value<char const *>(),
                          strnlen(param.value<char const *>(), param.length() - 1));

    L4::Cap<void> cap;
    int ret = mgr()->create_dynamic_client(
        std::string(param.value<char const *>(), param.length() - 1),
        -1, num_ds, &cap);

    if (ret >= 0)
      res = L4::Ipc::make_cap(cap, L4_CAP_FPAGE_RWSD);

    return (ret == -L4_ENODEV && _scan_in_progress) ? -L4_EAGAIN : ret;
  }

  void scan_finished()
  { _scan_in_progress = false; }

private:
  BASE *mgr() { return static_cast<BASE *>(this); }

  bool _scan_in_progress = true;
};

} // name space
