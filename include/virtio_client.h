/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/cxx/unique_ptr_list>
#include <l4/cxx/utils>

#include <l4/l4virtio/server/virtio-block>

#include <l4/libblock-device/debug.h>
#include <l4/libblock-device/device.h>
#include <l4/libblock-device/types.h>
#include <l4/libblock-device/request_queue.h>

namespace Block_device {

class Virtio_client
: public L4virtio::Svr::Block_dev_base<Mem_region_info>,
  public L4::Epiface_t<Virtio_client, L4virtio::Device>
{
protected:
  class Generic_pending_request : public Pending_request
  {
  protected:
    int check_error(int result, Virtio_client *client)
    {
      if (result < 0 && result != -L4_EBUSY)
        client->handle_request_error(result, this);

      return result;
    }

  public:
    explicit Generic_pending_request(cxx::unique_ptr<Request> &&req)
    : request(cxx::move(req))
    {}

    void fail_request(Virtio_client *owner) override
    {
      owner->finalize_request(cxx::move(request), 0, L4VIRTIO_BLOCK_S_IOERR);
    }

    cxx::unique_ptr<Request> request;
  };

  struct Pending_inout_request : public Generic_pending_request
  {
    Inout_block blocks;

    using Generic_pending_request::Generic_pending_request;

    L4Re::Dma_space::Direction dir() const
    {
      return request->header().type == L4VIRTIO_BLOCK_T_OUT
             ? L4Re::Dma_space::Direction::To_device
             : L4Re::Dma_space::Direction::From_device;
    }

    int handle_request(Virtio_client *client) override
    { return check_error(client->inout_request(this), client); }

  };

  struct Pending_flush_request : public Generic_pending_request
  {
    using Generic_pending_request::Generic_pending_request;

    int handle_request(Virtio_client *client) override
    { return check_error(client->flush_request(this), client); }
  };

public:
  /**
   * Create a new interface for an existing device.
   *
   * \param dev       Device to drive with this interface. The device must
   *                  have been initialized already.
   * \param numds     Maximum number of dataspaces the client is allowed to share.
   * \param readonly  If true the client will have read-only access.
   */
  Virtio_client(cxx::Ref_ptr<Device> const &dev, unsigned numds, bool readonly)
  : L4virtio::Svr::Block_dev_base<Mem_region_info>(L4VIRTIO_VENDOR_KK, 0x100,
                                                   dev->capacity() >> 9,
                                                   dev->is_read_only()
                                                     || readonly),
    _numds(numds),
    _device(dev),
    _pending(dev->request_queue())
  {
    reset_client();
  }

  /**
   * Reset the hardware device driven by this interface.
   */
  void reset_device() override
  {
    if (_pending)
      _pending->drain_queue_for(this, false);
    _device->reset();
    _negotiated_features.raw = 0;
  }

  /**
   * Reinitialize the client.
   */
  bool reset_client() override
  {
    init_mem_info(_numds);
    set_seg_max(_device->max_segments());
    set_size_max(0x400000); // 4MB XXX???
    set_flush();
    set_config_wce(0); // starting in write-through mode
    _shutdown_state = Shutdown_type::Running;
    _negotiated_features.raw = 0;
    return true;
  }

  bool queue_stopped() override
  { return false; }

  bool process_request(cxx::unique_ptr<Request> &&req) override;
  void task_finished(Generic_pending_request *preq, int error, l4_size_t sz);

  /**
   * Process a shutdown event on the client
   */
  void shutdown_event(Shutdown_type type)
  {
    // Transitions from Client_gone are not allowed as the client must be
    // destroyed before another shutdown event handling
    l4_assert(_shutdown_state != Client_gone);

    // Transitions from System_shutdown are also not allowed, the initiator
    // should take care of graceful handling of this.
    l4_assert(_shutdown_state != System_shutdown);
    // If we are transitioning from System_suspend, it must be only to Running,
    // the initiator should handle this gracefully.
    l4_assert(_shutdown_state != System_suspend
              || type == Shutdown_type::Running);

    // Update shutdown state of the client
    _shutdown_state = type;

    if (type == Shutdown_type::Client_shutdown)
      {
        reset();
        reset_client();
        // Client_shutdown must transit to the Running state
        l4_assert(_shutdown_state == Shutdown_type::Running);
      }

    if (type != Shutdown_type::Running)
      {
        if (_pending)
          _pending->drain_queue_for(this, type != Client_gone);
        _device->reset();
      }
  }

  /**
   * Attach device to an object registry.
   *
   * \param registry Object registry that will be responsible for dispatching
   *                 requests.
   * \param service  Name of an existing capability the device should use.
   *
   * This functions registers the general virtio interface as well as the
   * interrupt handler which is used for receiving client notifications.
   *
   * The caller is responsible to call `unregister_obj()` before destroying
   * the client object.
   */
  L4::Cap<void> register_obj(L4::Registry_iface *registry,
                             char const *service = 0)
  {
    L4Re::chkcap(registry->register_irq_obj(this->irq_iface()));
    L4::Cap<void> ret;
    if (service)
      ret = registry->register_obj(this, service);
    else
      ret = registry->register_obj(this);
    L4Re::chkcap(ret);

    return ret;
  }

  L4::Cap<void> register_obj(L4::Registry_iface *registry,
                             L4::Cap<L4::Rcv_endpoint> ep)
  {
    L4Re::chkcap(registry->register_irq_obj(this->irq_iface()));

    return L4Re::chkcap(registry->register_obj(this, ep));
  }

  /**
   * Detach device from object registry.
   *
   * \param registry  Object registry previously used for `register_obj()`.
   */
  void unregister_obj(L4::Registry_iface *registry)
  {
    registry->unregister_obj(this->irq_iface());
    registry->unregister_obj(this);
  }

protected:
  L4::Ipc_svr::Server_iface *server_iface() const override
  {
    return this->L4::Epiface::server_iface();
  }

private:
  void release_dma(Pending_inout_request *req)
  {
    // unmap DMA regions
    Inout_block *cur = &req->blocks;
    while (cur)
      {
        if (cur->num_sectors)
          _device->dma_unmap(cur->dma_addr, cur->num_sectors, req->dir());
        cur = cur->next.get();
      }
  }

  int build_inout_blocks(Pending_inout_request *preq);

  int inout_request(Pending_inout_request *preq)
  {
    auto *req = preq->request.get();
    l4_uint64_t sector = req->header().sector / (_device->sector_size() >> 9);

    return _device->inout_data(sector, preq->blocks,
                               [this, preq](int error, l4_size_t sz) {
                                 release_dma(preq);
                                 task_finished(preq, error, sz);
                               },
                               preq->dir());
  }

  int check_flush_request(Pending_flush_request *preq)
  {
    if (!_negotiated_features.flush())
        return -L4_ENOSYS;

    auto *req = preq->request.get();

    // sector must be zero for FLUSH
    if (req->header().sector)
      return -L4_ENOSYS;

    return L4_EOK;
  }

  int flush_request(Pending_flush_request *preq)
  {
    return _device->flush([this, preq](int error, l4_size_t sz) {
      task_finished(preq, error, sz);
    });
  }

  bool check_features(void) override
  {
    _negotiated_features = negotiated_features();
    return true;
  }

protected:
  template <typename REQ>
  bool handle_request_result(int error, cxx::unique_ptr<REQ> &&pending)
  {
    if (error == -L4_EBUSY && _pending)
      {
        Dbg::trace("virtio").printf("Port busy, queueing request.\n");
        _pending->add_to_queue(this, cxx::move(cxx::unique_ptr<Pending_request>(pending.release())));
      }
    else if (error < 0)
      handle_request_error(error, pending.get());
    else
      // request has been successfully sent to hardware
      // which now has ownership of Request pointer, so release here
      pending.release();

    return true;
  }

  // only use on errors that are not busy
  void handle_request_error(int error, Generic_pending_request *pending)
  {
    auto trace = Dbg::trace("virtio");

    if (error == -L4_ENOSYS)
      {
        trace.printf("Unsupported operation.\n");
        finalize_request(cxx::move(pending->request), 0,
                         L4VIRTIO_BLOCK_S_UNSUPP);
      }
    else
      {
        trace.printf("Got IO error: %d\n", error);
        finalize_request(cxx::move(pending->request), 0, L4VIRTIO_BLOCK_S_IOERR);
      }
  }

protected:
  unsigned _numds;
  Shutdown_type _shutdown_state;
  cxx::Ref_ptr<Device> _device;
  Request_queue *_pending;

  L4virtio::Svr::Block_features _negotiated_features;
};

template <typename T>
class Client_discard_mixin: public T
{
  struct Pending_cmd_request : public T::Generic_pending_request
  {
    Inout_block blocks;

    using T::Generic_pending_request::Generic_pending_request;

    int handle_request(Virtio_client *client) override
    {
      return this->check_error(
          static_cast<Client_discard_mixin *>(client)->cmd_request(this), client);
    }
  };

  int build_cmd_blocks(Pending_cmd_request *preq)
  {
    auto *req = preq->request.get();
    bool discard = (req->header().type == L4VIRTIO_BLOCK_T_DISCARD);

    if (this->device_features().ro())
        return -L4_EIO;

    // sector is used only for inout requests, it must be zero for WzD
    if (req->header().sector)
      return -L4_ENOSYS;

    if (discard)
      {
        if (!T::negotiated_features().discard())
          return -L4_ENOSYS;
      }
    else
      {
        if (!T::negotiated_features().write_zeroes())
          return -L4_ENOSYS;
      }

    auto *d = static_cast<Device_discard_mixin<Device> *>(T::_device.get());

    size_t seg = 0;
    size_t max_seg = discard ? _di.max_discard_seg : _di.max_write_zeroes_seg;

    l4_size_t sps = d->sector_size() >> 9;
    l4_uint64_t sectors = d->capacity() / d->sector_size();

    Inout_block *last_blk = nullptr;

    while (req->has_more())
      {
        typename T::Request::Data_block b;

        try
          {
            b = req->next_block();
          }
        catch (L4virtio::Svr::Bad_descriptor const &e)
          {
            return -L4_EIO;
          }

        auto *payload = reinterpret_cast<l4virtio_block_discard_t *>(b.addr);

        size_t items = b.len / sizeof(payload[0]);
        if (items * sizeof(payload[0]) != b.len)
          return -L4_EIO;

        if (seg + items > max_seg)
          return -L4_EIO;
        seg += items;

        for (auto i = 0u; i < items; i++)
          {
            auto p = cxx::access_once<l4virtio_block_discard_t>(&payload[i]);

            // Check sector size alignment. Discard sector alignment is not
            // strictly enforced as it is merely a hint to the driver.
            if (p.sector % sps != 0)
              return -L4_EIO;
            if (p.num_sectors % sps != 0)
              return -L4_EIO;

            // Convert to the device sector size
            p.sector /= sps;
            p.num_sectors /= sps;

            // Check bounds
            if (p.num_sectors > sectors)
              return -L4_EIO;
            if (p.sector > sectors - p.num_sectors)
              return -L4_EIO;

            if (p.flags & L4VIRTIO_BLOCK_DISCARD_F_RESERVED)
              return -L4_ENOSYS;

            if (discard)
              {
                if (p.flags & L4VIRTIO_BLOCK_DISCARD_F_UNMAP)
                  return -L4_ENOSYS;
                if (p.num_sectors > _di.max_discard_sectors)
                  return -L4_EIO;
              }
            else
              {
                if (p.flags & L4VIRTIO_BLOCK_DISCARD_F_UNMAP
                    && !_di.write_zeroes_may_unmap)
                  return -L4_ENOSYS;
                if (p.num_sectors > _di.max_write_zeroes_sectors)
                  return -L4_EIO;
              }

            Inout_block *blk;
            if (last_blk)
              {
                last_blk->next = cxx::make_unique<Inout_block>();
                blk = last_blk->next.get();
              }
            else
              blk = &preq->blocks;

            blk->sector = p.sector;
            blk->num_sectors = p.num_sectors;
            if (p.flags & L4VIRTIO_BLOCK_DISCARD_F_UNMAP)
              blk->flags = Inout_f_unmap;

            last_blk = blk;
          }
      }

    return L4_EOK;
  }

  int cmd_request(Pending_cmd_request *preq)
  {
    auto *req = preq->request.get();
    bool discard = (req->header().type == L4VIRTIO_BLOCK_T_DISCARD);

    return static_cast<Device_discard_mixin<Device> *>(T::_device.get())
      ->discard(0, preq->blocks,
                [this, preq](int error, l4_size_t sz) {
                  T::task_finished(preq, error, sz);
                },
                discard);
  }

  bool process_request(cxx::unique_ptr<typename T::Request> &&req) override
  {
    auto trace = Dbg::trace("virtio");

    if (this->_shutdown_state != Shutdown_type::Running)
      {
        trace.printf("Failing requests as the client is shutting down\n");
        this->finalize_request(cxx::move(req), 0, L4VIRTIO_BLOCK_S_IOERR);
        return false;
      }

    switch (req->header().type)
      {
      case L4VIRTIO_BLOCK_T_WRITE_ZEROES:
      case L4VIRTIO_BLOCK_T_DISCARD:
        {
          auto pending = cxx::make_unique<Pending_cmd_request>(cxx::move(req));

          int ret = build_cmd_blocks(pending.get());
          if (ret >= 0)
            {
              if (this->_pending && !this->_pending->empty())
                ret = -L4_EBUSY; // make sure to keep request order
              else
                ret = cmd_request(pending.get());
            }
          return this->handle_request_result(ret, cxx::move(pending));
        }
      default:
        return T::process_request(cxx::move(req));
      }

    return true;
  }

public:
  template <typename... Args>
  Client_discard_mixin(cxx::Ref_ptr<Device> const &dev, Args &&... args)
  : T(dev, cxx::forward<Args>(args)...)
  {
    auto *d = static_cast<Device_discard_mixin<Device> *>(dev.get());
    _di = d->discard_info();

    // Convert sector sizes to virtio 512-byte sectors.
    size_t sps = d->sector_size() >> 9;
    if (_di.max_discard_sectors)
      T::set_discard(_di.max_discard_sectors * sps, _di.max_discard_seg,
                     _di.discard_sector_alignment * sps);
    if (_di.max_write_zeroes_sectors)
      T::set_write_zeroes(_di.max_write_zeroes_sectors * sps,
                          _di.max_write_zeroes_seg, _di.write_zeroes_may_unmap);
  }

private:
  Device_discard_mixin<Device>::Discard_info _di;
};

} //name space
