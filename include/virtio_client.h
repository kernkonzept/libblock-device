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

namespace Block_device {

class Virtio_client
: public L4virtio::Svr::Block_dev<L4virtio::Svr::No_custom_data>
{
  using Base = L4virtio::Svr::Block_dev<L4virtio::Svr::No_custom_data>;

protected:
  struct Pending_request
  : cxx::Unique_ptr_list_item<Pending_request>
  {
    explicit Pending_request(cxx::unique_ptr<Request> &&req)
    : request(std::move(req))
    {}

    virtual ~Pending_request() = default;

    virtual int handle_request(Virtio_client *client) = 0;
    cxx::unique_ptr<Request> request;
  };

  struct Pending_inout_request : public Pending_request
  {
    Inout_block blocks;

    using Pending_request::Pending_request;

    L4Re::Dma_space::Direction dir() const
    {
      return request->header().type == L4VIRTIO_BLOCK_T_OUT
             ? L4Re::Dma_space::Direction::To_device
             : L4Re::Dma_space::Direction::From_device;
    }

    int handle_request(Virtio_client *client) override
    {
      return client->inout_request(this);
    }

  };

  struct Pending_flush_request : public Pending_request
  {
    using Pending_request::Pending_request;
    int handle_request(Virtio_client *client) override
    {
      return client->flush_request(this);
    }
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
  : Base(0x44, 0x100, dev->capacity() >> 9, dev->is_read_only() || readonly),
    _device(dev)
  {
    init_mem_info(numds);
    set_seg_max(dev->max_segments());
    set_size_max(0x400000); // 4MB XXX???
    set_flush();
    set_config_wce(0); // starting in write-through mode
  }

  /**
   * Reset the hardware device driven by this interface.
   */
  void reset_device() override
  { _device->reset(); }

  bool queue_stopped() override
  { return !_pending.empty(); }

  bool process_request(cxx::unique_ptr<Request> &&req) override;
  void task_finished(Pending_request *preq, int error, l4_size_t sz);

private:
  int build_inout_blocks(Pending_inout_request *preq);

  int inout_request(Pending_inout_request *preq)
  {
    auto *req = preq->request.get();
    l4_uint64_t sector = req->header().sector / (_device->sector_size() >> 9);

    return _device->inout_data(sector, preq->blocks,
                               [this, preq](int error, l4_size_t sz) {
                                 // unmap DMA regions
                                 Inout_block *cur = &preq->blocks;
                                 while (cur)
                                   {
                                     _device->dma_unmap(cur->dma_addr,
                                                        cur->num_sectors,
                                                        preq->dir());
                                     cur = cur->next.get();
                                   }
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
  void check_pending();

  template <typename REQ>
  bool handle_request_error(int error, cxx::unique_ptr<REQ> pending)
  {
    auto trace = Dbg::trace("virtio");
    if (error == -L4_EBUSY)
      {
        trace.printf("Port busy, queueing request.\n");
        _pending.push_back(cxx::unique_ptr<Pending_request>(pending.release()));
        return false;
      }
    else if (error == -L4_ENOSYS)
      {
        trace.printf("Unsupported operation.\n");
        finalize_request(cxx::move(pending->request), 0,
                         L4VIRTIO_BLOCK_S_UNSUPP);
      }
    else if (error < 0)
      {
        trace.printf("Got IO error: %d\n", error);
        finalize_request(cxx::move(pending->request), 0, L4VIRTIO_BLOCK_S_IOERR);
      }
    else
      // request has been successfully sent to hardware
      // which now has ownership of Request pointer, so release here
      pending.release();

    return true;
  }

protected:
  cxx::Ref_ptr<Device> _device;
  cxx::Unique_ptr_list<Pending_request> _pending;

  L4virtio::Svr::Block_features _negotiated_features;
};

template <typename T>
class Client_discard_mixin: public T
{
  struct Pending_cmd_request : public T::Pending_request
  {
    Inout_block blocks;

    using T::Pending_request::Pending_request;

    int handle_request(Virtio_client *client) override
    {
      return static_cast<Client_discard_mixin *>(client)->cmd_request(this);
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

            // Check alignment
            auto align = (discard || p.flags & L4VIRTIO_BLOCK_DISCARD_F_UNMAP)
                           ? sps * _di.discard_sector_alignment
                           : sps;
            if (p.sector % align != 0)
              return -L4_EIO;
            if (p.num_sectors % align != 0)
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
    switch (req->header().type)
      {
      case L4VIRTIO_BLOCK_T_WRITE_ZEROES:
      case L4VIRTIO_BLOCK_T_DISCARD:
        {
          auto pending = cxx::make_unique<Pending_cmd_request>(cxx::move(req));

          int ret = build_cmd_blocks(pending.get());
          if (ret >= 0)
            ret = cmd_request(pending.get());
          return this->handle_request_error(ret, cxx::move(pending));
        }
      default:
        return T::process_request(cxx::move(req));
      }

    return true;
  }

public:
  template <typename... Args>
  Client_discard_mixin(cxx::Ref_ptr<Device> const &dev, Args &&... args)
  : T(dev, std::forward<Args>(args)...)
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
