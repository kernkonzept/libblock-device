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

template <typename DEV>
class Virtio_client
: public L4virtio::Svr::Block_dev_base<Mem_region_info>,
  public L4::Epiface_t<Virtio_client<DEV>, L4virtio::Device>,
  public Pending_request::Owner
{
protected:
  class Generic_pending_request : public Pending_request
  {
  protected:
    int check_error(int result)
    {
      if (result < 0 && result != -L4_EBUSY)
        client->handle_request_error(result, this);

      return result;
    }

  public:
    explicit Generic_pending_request(Virtio_client *c, cxx::unique_ptr<Request> &&req)
    : request(cxx::move(req)), client(c)
    {}

    void fail_request() override
    {
      client->finalize_request(cxx::move(request), 0, L4VIRTIO_BLOCK_S_IOERR);
    }

    bool is_owner(Pending_request::Owner *owner) override
    { return static_cast<Pending_request::Owner *>(client) == owner; }

    cxx::unique_ptr<Request> request;
    Virtio_client *client;
  };

  struct Pending_inout_request : public Generic_pending_request
  {
    Inout_block blocks;

    using Generic_pending_request::Generic_pending_request;

    L4Re::Dma_space::Direction dir() const
    {
      return this->request->header().type == L4VIRTIO_BLOCK_T_OUT
             ? L4Re::Dma_space::Direction::To_device
             : L4Re::Dma_space::Direction::From_device;
    }

    int handle_request() override
    { return this->check_error(this->client->inout_request(this)); }

  };

  struct Pending_flush_request : public Generic_pending_request
  {
    using Generic_pending_request::Generic_pending_request;

    int handle_request() override
    { return this->check_error(this->client->flush_request(this)); }
  };

  struct Pending_cmd_request : public Generic_pending_request
  {
    Inout_block blocks;

    using Generic_pending_request::Generic_pending_request;

    int handle_request() override
    {
      return this->check_error(this->client->discard_cmd_request(this, 0));
    }
  };

public:
  using Device_type = DEV;

  /**
   * Create a new interface for an existing device.
   *
   * \param dev       Device to drive with this interface. The device must
   *                  have been initialized already.
   * \param numds     Maximum number of dataspaces the client is allowed to share.
   * \param readonly  If true the client will have read-only access.
   */
  Virtio_client(cxx::Ref_ptr<Device_type> const &dev, unsigned numds, bool readonly)
  : L4virtio::Svr::Block_dev_base<Mem_region_info>(L4VIRTIO_VENDOR_KK, 0x100,
                                                   dev->capacity() >> 9,
                                                   dev->is_read_only()
                                                     || readonly),
    _numds(numds),
    _device(dev),
    _pending(dev->request_queue())
  {
    reset_client();
    init_discard_info(0);
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
  void reset_client()
  {
    init_mem_info(_numds);
    set_seg_max(_device->max_segments());
    set_size_max(_device->max_size());
    set_flush();
    set_config_wce(0); // starting in write-through mode
    _shutdown_state = Shutdown_type::Running;
    _negotiated_features.raw = 0;
  }

  bool queue_stopped() override
  { return false; }

  bool process_request(cxx::unique_ptr<Request> &&req) override
  {
    auto trace = Dbg::trace("virtio");

    if (_shutdown_state != Shutdown_type::Running)
      {
        trace.printf("Failing requests as the client is shutting down\n");
        this->finalize_request(cxx::move(req), 0, L4VIRTIO_BLOCK_S_IOERR);
        return false;
      }

    trace.printf("request received: type 0x%x, sector 0x%llx\n",
                 req->header().type, req->header().sector);
    switch (req->header().type)
      {
      case L4VIRTIO_BLOCK_T_OUT:
      case L4VIRTIO_BLOCK_T_IN:
        {
          auto pending = cxx::make_unique<Pending_inout_request>(this, cxx::move(req));
          int ret = build_inout_blocks(pending.get());
          if (ret >= 0)
            {
              if (_pending && !_pending->empty())
                ret = -L4_EBUSY; // make sure to keep request order
              else
                ret = inout_request(pending.get());
            } else
              release_dma(pending.get());
          return handle_request_result(ret, cxx::move(pending));
        }
      case L4VIRTIO_BLOCK_T_FLUSH:
        {
          auto pending = cxx::make_unique<Pending_flush_request>(this, cxx::move(req));
          int ret = check_flush_request(pending.get());
          if (ret == L4_EOK)
            {
              if (_pending && !_pending->empty())
                ret = -L4_EBUSY; // make sure to keep request order
              else
                ret = flush_request(pending.get());
            }
          return handle_request_result(ret, cxx::move(pending));
        }
      case L4VIRTIO_BLOCK_T_WRITE_ZEROES:
      case L4VIRTIO_BLOCK_T_DISCARD:
        {
          auto pending = cxx::make_unique<Pending_cmd_request>(this, cxx::move(req));
          return handle_discard(cxx::move(pending), 0);
        }
      default:
        finalize_request(cxx::move(req), 0, L4VIRTIO_BLOCK_S_UNSUPP);
      }

    return true;
  }

  void task_finished(Generic_pending_request *preq, int error, l4_size_t sz)
  {
    // move on to the next request

    // Only finalize if the client is still alive
    if (_shutdown_state != Client_gone)
      finalize_request(cxx::move(preq->request), sz, error);

    if (_pending)
      _pending->process_pending();

    // pending request can be dropped
    cxx::unique_ptr<Pending_request> ureq(preq);
  }

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

  int build_inout_blocks(Pending_inout_request *preq)
  {
    auto *req = preq->request.get();
    l4_size_t sps = _device->sector_size() >> 9;
    l4_uint64_t current_sector = req->header().sector / sps;
    l4_uint64_t sectors = _device->capacity() / _device->sector_size();
    auto dir = preq->dir();

    l4_uint32_t flags = 0;
    if (req->header().type == L4VIRTIO_BLOCK_T_OUT)
      {
        // If RO was offered, every write must fail
        if (device_features().ro())
          return -L4_EIO;

        // Figure out whether the write has a write-through or write-back semantics
        if (_negotiated_features.config_wce())
          {
            if (get_writeback() == 1)
              flags = Block_device::Inout_f_wb;
          }
        else if (_negotiated_features.flush())
          flags = Block_device::Inout_f_wb;
      }

    // Check alignment of the first sector
    if (current_sector * sps != req->header().sector)
      return -L4_EIO;

    Inout_block *last_blk = nullptr;

    size_t seg = 0;

    while (req->has_more())
      {
        Request::Data_block b;

        if (++seg > _device->max_segments())
          return -L4_EIO;

        try
          {
            b = req->next_block();
          }
        catch (L4virtio::Svr::Bad_descriptor const &e)
          {
            return -L4_EIO;
          }

        l4_size_t off = b.mem->ds_offset() + (l4_addr_t) b.addr
                        - (l4_addr_t) b.mem->local_base();

        l4_size_t sz = b.len / _device->sector_size();

        if (sz * _device->sector_size() != b.len)
          {
            Dbg::warn().printf("Bad block size 0x%x\n", b.len);
            return -L4_EIO;
          };

        // Check bounds
        if (sz > sectors)
          return -L4_EIO;
        if (current_sector > sectors - sz)
          return -L4_EIO;

        Inout_block *blk;
        if (last_blk)
          {
            last_blk->next = cxx::make_unique<Inout_block>();
            blk = last_blk->next.get();
          }
        else
          blk = &preq->blocks;

        L4Re::Dma_space::Dma_addr phys;
        long ret = _device->dma_map(b.mem, off, sz, dir, &phys);
        if (ret < 0)
          return ret;

        blk->dma_addr = phys;
        blk->virt_addr = (void *) ((l4_addr_t)b.mem->local_base() + off);
        blk->num_sectors = sz;
        current_sector += sz;
        blk->flags = flags;

        last_blk = blk;
      }

    return L4_EOK;
  }

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

  template <typename T = Device_type>
  void init_discard_info(long) {}

  template <typename T = Device_type>
  auto init_discard_info(int)
    -> decltype(((T*)0)->discard_info(), void())
  {
    _di = _device->discard_info();

    // Convert sector sizes to virtio 512-byte sectors.
    size_t sps = _device->sector_size() >> 9;
    if (_di.max_discard_sectors)
      set_discard(_di.max_discard_sectors * sps, _di.max_discard_seg,
                     _di.discard_sector_alignment * sps);
    if (_di.max_write_zeroes_sectors)
      set_write_zeroes(_di.max_write_zeroes_sectors * sps,
                          _di.max_write_zeroes_seg, _di.write_zeroes_may_unmap);
  }

  bool handle_discard(cxx::unique_ptr<Pending_cmd_request> &&pending, int)
  {
    int ret = build_discard_cmd_blocks(pending.get());
    if (ret >= 0)
      {
        if (this->_pending && !this->_pending->empty())
          ret = -L4_EBUSY; // make sure to keep request order
        else
          ret = discard_cmd_request(pending.get(), 0);
      }

    return this->handle_request_result(ret, cxx::move(pending));
  }

  int build_discard_cmd_blocks(Pending_cmd_request *preq)
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
        if (!_negotiated_features.discard())
          return -L4_ENOSYS;
      }
    else
      {
        if (!_negotiated_features.write_zeroes())
          return -L4_ENOSYS;
      }

    auto *d = _device.get();

    size_t seg = 0;
    size_t max_seg = discard ? _di.max_discard_seg : _di.max_write_zeroes_seg;

    l4_size_t sps = d->sector_size() >> 9;
    l4_uint64_t sectors = d->capacity() / d->sector_size();

    Inout_block *last_blk = nullptr;

    while (req->has_more())
      {
        Request::Data_block b;

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

  template <typename T = Device_type>
  int discard_cmd_request(Pending_cmd_request *, long)
  { return -L4_EIO; }

  template <typename T = Device_type>
  auto discard_cmd_request(Pending_cmd_request *preq, int)
    -> decltype(((T*)0)->discard_info(), int())
  {
    auto *req = preq->request.get();
    bool discard = (req->header().type == L4VIRTIO_BLOCK_T_DISCARD);

    return _device->discard(0, preq->blocks,
                [this, preq](int error, l4_size_t sz) {
                  task_finished(preq, error, sz);
                },
                discard);
  }

  template <typename REQ>
  bool handle_request_result(int error, cxx::unique_ptr<REQ> &&pending)
  {
    if (error == -L4_EBUSY && _pending)
      {
        Dbg::trace("virtio").printf("Port busy, queueing request.\n");
        _pending->add_to_queue(cxx::unique_ptr<Pending_request>(pending.release()));
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
  cxx::Ref_ptr<Device_type> _device;
  Request_queue *_pending;
  Device_discard_feature::Discard_info _di;

  L4virtio::Svr::Block_features _negotiated_features;
};

} //name space
