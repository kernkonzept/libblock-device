/*
 * Copyright (C) 2018-2020, 2022-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *            Manuel von Oltersdorff-Kalettka <manuel.kalettka@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <cassert>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <l4/cxx/ref_ptr>
#include <l4/cxx/ref_ptr_list>
#include <l4/cxx/unique_ptr>
#include <l4/re/error_helper>
#include <l4/sys/factory>
#include <l4/sys/cxx/ipc_epiface>

#include <l4/libblock-device/debug.h>
#include <l4/libblock-device/errand.h>
#include <l4/libblock-device/partition.h>
#include <l4/libblock-device/part_device.h>
#include <l4/libblock-device/virtio_client.h>
#include <l4/libblock-device/scheduler.h>

namespace Block_device {

template <typename DEV>
struct Simple_factory
{
  using Device_type = DEV;
  using Client_type = Virtio_client<Device_type>;

  static cxx::unique_ptr<Client_type>
  create_client(cxx::Ref_ptr<Device_type> const &dev,
                unsigned numds, bool readonly)
  { return cxx::make_unique<Client_type>(dev, numds, readonly); }
};

template <typename BASE_DEV>
struct Partitionable_factory
{
  using Device_type = BASE_DEV;
  using Client_type = Virtio_client<Device_type>;

  static cxx::unique_ptr<Client_type>
  create_client(cxx::Ref_ptr<Device_type> const &dev,
                unsigned numds, bool readonly)
  {
    return cxx::make_unique<Client_type>(dev, numds, readonly);
  }

  static cxx::Ref_ptr<Device_type>
  create_partition(cxx::Ref_ptr<Device_type> const &dev, unsigned partition_id,
                   Partition_info const &pi)
  {
    return cxx::Ref_ptr<Device_type>(
        new Partitioned_device<Device_type>(dev, partition_id, pi));
  }
};


/**
 * Basic class that scans devices and handles client connections.
 *
 * \tparam DEV        Base class for all devices.
 * \tparam FACTORY    Class that creates clients and partitions. See
 *                    Simple_factory for an example of the required interface.
 * \tparam SCHEDULER  Class that schedules VIRTIO block requests from all
 *                    clients.
 *
 */
template <typename DEV, typename FACTORY = Simple_factory<DEV>,
          typename SCHEDULER = Rr_scheduler<typename FACTORY::Device_type>>
class Device_mgr
{
  using Device_factory_type = FACTORY;
  using Client_type = typename Device_factory_type::Client_type;
  using Device_type = typename Device_factory_type::Device_type;
  using Scheduler_type = SCHEDULER;

  using Ds_vector = std::vector<L4::Cap<L4Re::Dataspace>>;

  using Pairing_callback = std::function<void(Device_type *)>;

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
    /** Read-only access for the client. */
    bool readonly;

    bool enable_trusted_ds_validation;

    std::shared_ptr<Ds_vector const> trusted_dataspaces;

    /** Callback to be called when a client is paired with a device. */
    Pairing_callback pairing_cb;

    Pending_client() = default;

    Pending_client(L4::Cap<L4::Rcv_endpoint> g, std::string const &dev, int ds,
                   bool ro, bool enable_trusted_ds_validation,
                   std::shared_ptr<Ds_vector const> trusted_dataspaces,
                   Pairing_callback cb)
    : device_id(dev), gate(g), num_ds(ds), readonly(ro),
      enable_trusted_ds_validation(enable_trusted_ds_validation),
      trusted_dataspaces(trusted_dataspaces), pairing_cb(cb)
    {}
  };

  class Connection : public cxx::Ref_obj_list_item<Connection>
  {
  public:
    explicit Connection(Device_mgr *mgr, cxx::Ref_ptr<Device_type> &&dev)
    : _shutdown_state(Shutdown_type::Running),
      _device(cxx::move(dev)),
      _mgr(mgr)
    {}

    L4::Cap<void> cap() const
    { return _interface ? _interface->obj_cap() : L4::Cap<void>(); }

    void start_disk_scan(Errand::Callback const &callback)
    {
      _device->start_device_scan(
        [=]()
          {
            scan_disk_partitions(callback, 0);
          });
    }

    void unregister_interfaces(L4::Registry_iface *registry) const
    {
      if (_interface)
        registry->unregister_obj(_interface.get());

      for (auto *sub : _subs)
        sub->unregister_interfaces(registry);
    }

    int create_interface_for(Pending_client *c, L4::Registry_iface *registry)
    {
      if (_shutdown_state != Shutdown_type::Running)
        return -L4_EIO;

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

      auto clt = Device_factory_type::create_client(_device, c->num_ds,
                                                    c->readonly);

      clt->add_trusted_dataspaces(c->trusted_dataspaces);
      if (c->enable_trusted_ds_validation)
        clt->enable_trusted_ds_validation();

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

      _mgr->_scheduler->add_client(clt.get());
      _interface.reset(clt.release());

      // Let it be known that the client and the device paired
      if (c->pairing_cb)
        c->pairing_cb(_device.get());
      return L4_EOK;
    }

    void check_clients(L4::Registry_iface *registry)
    {
      if (_interface)
        {
          if (_interface->obj_cap() && !_interface->obj_cap().validate().label())
            remove_client(registry);

          return;
        }

      // Sub-devices only need to be checked when the parent device was free.
      for (auto *sub : _subs)
        sub->check_clients(registry);
    }

    /** Process a shutdown event on the connection */
    void shutdown_event(Shutdown_type type)
    {
      // Set new shutdown state
      _shutdown_state = type;
      for (auto const &sub: _subs)
        sub->shutdown_event(type);
      if (_interface)
        _interface->shutdown_event(type);
    }

  private:
    /**
     * Scan the device for sub partitions.
     *
     * \param callback  Function to call when the scanning is done.
     * \param int       Dummy parameter to ensure template deduction prefers
     *                  this function. (Always set to '0' when calling
     *                  this function.)
     *
     * This function is compiled in when the device factory has a function
     * create_partition() defined.
     */
    template <typename T = Device_factory_type>
    auto scan_disk_partitions(Errand::Callback const &callback, int)
     -> decltype((T::create_partition)(cxx::Ref_ptr<Device_type>(), 0, Partition_info()), void())
    {
      auto reader = cxx::make_ref_obj<Partition_reader<Device_type>>(_device.get());
      // The reference to reader will be captured in the lambda passed to
      // reader's own read() method. At the same time, reader will store
      // the reference to the lambda.
      reader->read(
        [=]()
          {
            l4_size_t sz = reader->table_size();

            for (l4_size_t i = 1; i <= sz; ++i)
              {
                Partition_info info;
                if (reader->get_partition(i, &info) < 0)
                  continue;

                auto conn = cxx::make_ref_obj<Connection>(
                  _mgr,
                  Device_factory_type::create_partition(_device, i, info));
                _subs.push_front(std::move(conn));
              }

            callback();

            // Prolong the life-span of reader until we are sure the reader is
            // not currently invoked (i.e. capture the last reference to it in
            // an independent timeout callback).
            Errand::schedule([reader](){}, 0);
          });
    }

    /**
     * Dummy scan function for devices without partition.
     *
     * When the device factory does not have a function to create partitions,
     * then this function is compiled in and the partition scanning is
     * skipped completely.
     */
    template <typename T = Device_factory_type>
    void scan_disk_partitions(Errand::Callback const &callback, long)
    { callback(); }

    /**
     * Disconnect the existing client.
     */
    void remove_client(L4::Registry_iface *registry)
    {
      assert(_interface);

      // This operation is idempotent.
      _interface->shutdown_event(Shutdown_type::Client_gone);

      if (_interface->busy())
        {
          Dbg::trace().printf("Deferring dead client removal.\n");

          // Cannot remove the client while it still has active I/O requests.
          // This means that the device did not abort its inflight requests in
          // its reset() callback. It is still desirable though to wait for
          // those requests to finish and defer the dead client removal until
          // later.
          Errand::schedule([this, registry]() { remove_client(registry); },
                           10000);
          return;
        }

      _interface->unregister_obj(registry);
      _mgr->_scheduler->remove_client(_interface.get());
      _interface.reset();
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


    /// Current shutdown state
    Shutdown_type _shutdown_state;
    /// The device itself.
    cxx::Ref_ptr<Device_type> _device;
    /// Client interface.
    cxx::unique_ptr<Client_type> _interface;
    /// Partitions of the device.
    cxx::Ref_ptr_list<Connection> _subs;

    Device_mgr *_mgr;
  };

public:
  Device_mgr(L4::Registry_iface *registry)
  : _registry(registry)
  {
    _scheduler = cxx::make_unique<Scheduler_type>(registry);
  }

  virtual ~Device_mgr()
  {
    for (auto *c : _connpts)
      c->unregister_interfaces(_registry);
  }

  /**
   * Parse and verify a device string parameter.
   *
   * \param[in]  param   Device string name parameter.
   * \param[out] device  Device name extracted from parameter.
   * \returns L4 error code.
   *
   * This function tests if 'param' contains one of the following variants of a
   * device name and extracts it into 'device':
   *  - "partlabel:<label>":
   *    'device' contains "<label>" without conversion.
   *  - "partuuid:<uuid>":
   *    Check if "<uuid>" is a valid UUID and return with error if not. In case
   *    of success, 'device' contains "<uuid>" with all characters converted to
   *    upper case.
   *  - "<string>":
   *    Check if "<string>" is a valid UUID. If so, 'device' contains "<string>"
   *    with all characters converted to upper case. Otherwise, 'device'
   *    contains the unmodified "<string>".
   */
  static int parse_device_name(std::string const &param, std::string &device)
  {
    std::string const partlabel("partlabel:");
    std::string const partuuid("partuuid:");

    if (param.size() > partlabel.size()
        && param.compare(0, partlabel.size(), partlabel) == 0)
      {
        device = param.substr(partlabel.size());
        return L4_EOK;
      }
    else if (param.size() > partuuid.size()
             && param.compare(0, partuuid.size(), partuuid) == 0)
      {
        auto device_partuuid = param.substr(partuuid.size());
        if (!is_uuid(device_partuuid.c_str()))
          {
            Dbg::trace().printf("The 'partuuid:' parameter expects a UUID.\n");
            return -L4_EINVAL;
          }

        device = device_partuuid;
        std::transform(device.begin(), device.end(), device.begin(),
                       [](unsigned char c){ return std::toupper(c); });
        return L4_EOK;
      }
    else
      {
        device = param;
        if (is_uuid(param.c_str()))
          std::transform(device.begin(), device.end(), device.begin(),
                         [](unsigned char c) { return std::toupper(c); });
        return L4_EOK;
      }
  }

  int add_static_client(L4::Cap<L4::Rcv_endpoint> client, const char *device,
                        int partno, int num_ds, bool readonly = false,
                        Pairing_callback cb = nullptr,
                        bool enable_trusted_ds_validation = false,
                        std::shared_ptr<Ds_vector const> trusted_dataspaces
                          = nullptr)
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

    _pending_clients.emplace_back(client, buf, num_ds, readonly,
                                  enable_trusted_ds_validation,
                                  trusted_dataspaces, cb);

    return L4_EOK;
  }

  int create_dynamic_client(std::string const &device, int partno, int num_ds,
                            L4::Cap<void> *cap, bool readonly = false,
                            Pairing_callback cb = nullptr,
                            bool enable_trusted_ds_validation = false,
                            std::shared_ptr<Ds_vector const> trusted_dataspaces
                              = nullptr)
  {
    Pending_client clt;

    // Maximum number of dataspaces that can be registered.
    clt.num_ds = num_ds;

    clt.readonly = readonly;

    clt.device_id = device;

    clt.pairing_cb = cb;

    clt.trusted_dataspaces = trusted_dataspaces;

    clt.enable_trusted_ds_validation = enable_trusted_ds_validation;

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

  /**
   * Remove clients where the client IPC gate is no longer valid.
   */
  void check_clients()
  {
    for (auto *c : _connpts)
      c->check_clients(_registry);
  }

  void add_disk(cxx::Ref_ptr<Device_type> &&device, Errand::Callback const &callback)
  {
    auto conn = cxx::make_ref_obj<Connection>(this, std::move(device));

    conn->start_disk_scan(
      [=]()
        {
          _connpts.push_front(conn);
          connect_static_clients(conn.get());
          callback();
        });
  }

  /** Process a shutdown event on all connections */
  void shutdown_event(Shutdown_type type)
  {
    l4_assert(type != Client_gone);
    l4_assert(type != Client_shutdown);

    for (auto const &con : _connpts)
      con->shutdown_event(type);
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

  static constexpr bool is_uuid(char const *s)
  {
    for (unsigned i = 0; i < 36; ++i)
      if (i == 8 || i == 13 || i == 18 || i == 23)
        {
          if (s[i] != '-')
            return false;
        }
      else
        {
          if (!isxdigit(s[i]))
            return false;
        }
    return s[36] == '\0';
  }

  /// Registry new client connections subscribe to.
  L4::Registry_iface *_registry;
  /// List of devices with their potential clients.
  cxx::Ref_ptr_list<Connection> _connpts;
  /// List of clients waiting for a device to appear.
  std::vector<Pending_client> _pending_clients;
  /// I/O scheduler
  cxx::unique_ptr<Scheduler_type> _scheduler;
};

} // name space
