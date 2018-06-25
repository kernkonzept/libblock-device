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
#include <l4/re/util/object_registry>
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
class Device_mgr : public L4::Epiface_t<Device_mgr<IF>, L4::Factory>
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

    void unregister_interfaces(L4Re::Util::Object_registry *registry) const
    {
      if (_interface)
        registry->unregister_obj(_interface.get());

      for (auto *sub : _subs)
        sub->unregister_interfaces(registry);
    }

    int create_interface_for(Pending_client *c,
                             L4Re::Util::Object_registry *registry)
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
  Device_mgr(L4Re::Util::Object_registry *registry)
  : _registry(registry), _available_devices(0)
  {}

  virtual ~Device_mgr()
  {
    for (auto *c : _connpts)
      c->unregister_interfaces(_registry);

    _registry->unregister_obj(this);
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

      Dbg::trace().printf("Adding static client. cap: %.*s device: %s, numds: %li\n",
                          capnamelen, capname, device.c_str(), numds);

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

  void add_disk(cxx::Ref_ptr<Device> &&device)
  {
    auto conn = cxx::make_ref_obj<Connection>(std::move(device));

    ++_available_devices;

    conn->start_disk_scan(
      [=]()
        {
          _connpts.push_front(conn);
          ++_static_clients;
          connect_static_clients(conn.get());
        });
  }

  long op_create(L4::Factory::Rights,
                 L4::Ipc::Cap<void> &res, l4_mword_t,
                 L4::Ipc::Varg_list_ref valist)
  {
    Dbg::trace().printf("Client requests connection.\n");

    L4::Ipc::Varg param = valist.next();

    if (!param.is_of<l4_mword_t>())
      return -L4_EINVAL;

    Pending_client clt;

    // Maximum number of dataspaces that can be registered.
    clt.num_ds = param.value<l4_mword_t>();
    if (clt.num_ds <= 0 || clt.num_ds > 256) // sanity check with arbitrary limit
      return -L4_EINVAL;

    param = valist.next();

    // Name of device. This must either be the serial number of the disk,
    // when the entire disk is requested or for partitions their UUID.
    if (!param.is_of<char const *>())
      return -L4_EINVAL;

    clt.device_id = std::string(param.value<char const *>(), param.length() - 1);

    for (auto *c : _connpts)
      {
        int ret = c->create_interface_for(&clt, _registry);

        if (ret == -L4_ENODEV)
          continue;

        if (ret < 0)
          return ret;

        // found the requested device
        res = L4::Ipc::make_cap(clt.gate, L4_CAP_FPAGE_RWSD);
        return L4_EOK;
      }

    return (_available_devices > _static_clients) ? -L4_EAGAIN : -L4_ENODEV;
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

    if (_available_devices == _static_clients)
      if (_registry->register_obj(this, "svr") < 0)
        Dbg::warn()
          .printf("Capability 'svr' not found. No dynamic clients accepted.\n");
  }


  /// Registry new client connections subscribe to.
  L4Re::Util::Object_registry *_registry;
  /// List of devices with their potential clients.
  cxx::Ref_ptr_list<Connection> _connpts;
  /// List of clients waiting for a device to appear.
  std::vector<Pending_client> _pending_clients;
  /// Number of static clients.
  unsigned _static_clients;
  /// Number of devices being scanned.
  l4_size_t _available_devices;
};

} // name space
