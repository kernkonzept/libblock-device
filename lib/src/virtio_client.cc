/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/libblock-device/virtio_client.h>

bool
Block_device::Virtio_client::process_request(cxx::unique_ptr<Request> &&req)
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
        auto pending = cxx::make_unique<Pending_inout_request>(cxx::move(req));
        int ret = build_inout_blocks(pending.get());
        if (ret >= 0)
          ret = inout_request(pending.get());
        else
          release_dma(pending.get());
        return handle_request_error(ret, cxx::move(pending));
      }
    case L4VIRTIO_BLOCK_T_FLUSH:
      {
        auto pending = cxx::make_unique<Pending_flush_request>(cxx::move(req));
        int ret = check_flush_request(pending.get());
        if (ret == L4_EOK)
          ret = flush_request(pending.get());
        return handle_request_error(ret, cxx::move(pending));
      }
    default:
      finalize_request(cxx::move(req), 0, L4VIRTIO_BLOCK_S_UNSUPP);
    }

  return true;
}

void
Block_device::Virtio_client::task_finished(Pending_request *preq, int error,
                                           l4_size_t sz)
{
  // move on to the next request

  // Only finalize if the client is still alive
  if (_shutdown_state != Client_gone)
    finalize_request(cxx::move(preq->request), sz, error);
  check_pending();

  // pending request can be dropped
  cxx::unique_ptr<Pending_request> ureq(preq);
}

int
Block_device::Virtio_client::build_inout_blocks(Pending_inout_request *preq)
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

void
Block_device::Virtio_client::check_pending()
{
  if (_pending.empty())
    return;

  while (!_pending.empty())
    {
      int ret = _pending.front()->handle_request(this);
      if (ret == -L4_EBUSY)
        return; // still no unit available, keep element in queue

      // remove element from queue
      auto pending = _pending.pop_front();

      if (ret == -L4_ENOSYS)
        // the device does not understand the request, send a response to the
        // client immediately
        finalize_request(cxx::move(pending->request), 0,
                         L4VIRTIO_BLOCK_S_UNSUPP);
      else if (ret < 0)
        // on any other error, send a response to the client immediately
        finalize_request(cxx::move(pending->request), 0, L4VIRTIO_BLOCK_S_IOERR);
      else
        // request has been successfully sent to hardware
        // which now has ownership of Request pointer, so release here
        pending.release();
    }

  // clean out requests in the virtqueue
  kick();
}

/**
 * Drain the pending queue
 *
 * @param finalize  If true, pending requests will be finalized with error. In
 *                  that case, the client memory must be still accessible.
 *                  If false, pending requests will not be finalized, because the
 *                  client memory (virtqueue and buffers) is expected not to be
 *                  accessible.
 */
void Block_device::Virtio_client::drain_pending(bool finalize)
{
  while (!_pending.empty())
    {
      // remove element from queue
      auto pending = _pending.pop_front();

      if (finalize)
        finalize_request(cxx::move(pending->request), 0, L4VIRTIO_BLOCK_S_IOERR);

      // If pending still points to the request, it will be destroyed as we go
      // out of scope or pending is reassigned in the next iteration
    }
}
