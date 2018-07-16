/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <functional>

#include <l4/cxx/ref_ptr>
#include <l4/cxx/unique_ptr_list>

#include <l4/l4virtio/server/virtio-block>

#include <l4/libblock-device/debug.h>
#include <l4/libblock-device/device.h>
#include <l4/libblock-device/types.h>

namespace Block_device {

class Virtio_client
: public L4virtio::Svr::Block_dev<L4virtio::Svr::No_custom_data>
{
  using Base = L4virtio::Svr::Block_dev<L4virtio::Svr::No_custom_data>;

  struct Pending_request : cxx::Unique_ptr_list_item<Pending_request>
  {
    Inout_block blocks;
    cxx::unique_ptr<Request> request;

    L4Re::Dma_space::Direction dir() const
    {
      return request->header().type == L4VIRTIO_BLOCK_T_OUT
             ? L4Re::Dma_space::Direction::To_device
             : L4Re::Dma_space::Direction::From_device;
    }

    explicit Pending_request(cxx::unique_ptr<Request> &&req)
    : request(std::move(req))
    {}
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
  int build_datablocks(Pending_request *preq);
  void check_pending();

  int inout_request(Pending_request *preq)
  {
    auto *req = preq->request.get();
    l4_uint64_t sector = req->header().sector / (_device->sector_size() >> 9);

    using namespace std::placeholders;
    auto callback = std::bind(&Virtio_client::task_finished, this, preq, _1, _2);

    return _device->inout_data(sector, preq->blocks, callback, preq->dir());
  }

  cxx::Ref_ptr<Device> _device;
  cxx::Unique_ptr_list<Pending_request> _pending;
};

} //name space
