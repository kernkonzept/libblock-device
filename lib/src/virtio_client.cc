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
  trace.printf("request received: type 0x%x, sector 0x%llx\n",
               req->header().type, req->header().sector);
  switch (req->header().type)
    {
    case L4VIRTIO_BLOCK_T_OUT:
      if (device_features().ro())
        {
          trace.printf("Failing the write request via a read-only client.\n");
          finalize_request(cxx::move(req), 0, L4VIRTIO_BLOCK_S_IOERR);
          break;
        }
      /* FALLTHRU */
    case L4VIRTIO_BLOCK_T_IN:
      {
        auto pending = cxx::make_unique<Pending_request>(std::move(req));

        int ret = build_datablocks(pending.get());
        if (ret >= 0)
          ret = inout_request(pending.get());
        if (ret == -L4_EBUSY)
          {
            trace.printf("Port busy, queueing request.\n");
            _pending.push_back(cxx::move(pending));
            return false;
          }
        else if (ret < 0)
          {
            trace.printf("Got IO error: %d\n", ret);
            finalize_request(cxx::move(pending->request), 0, L4VIRTIO_BLOCK_S_IOERR);
          }
        else
          // request has been successfully sent to hardware
          // which now has ownership of Request pointer, so release here
          pending.release();
        break;
      }
    default:
      finalize_request(cxx::move(req), 0, L4VIRTIO_BLOCK_S_UNSUPP);
    }

  return true;
}

void
Block_device::Virtio_client::task_finished(Pending_request *preq,
                                           int error, l4_size_t sz)
{
  // unmap DMA regions
  Inout_block *cur = &preq->blocks;
  while (cur)
    {
      _device->dma_unmap(cur->dma_addr, cur->num_sectors, preq->dir());
      cur = cur->next.get();
    }

  // move on to the next request
  finalize_request(cxx::move(preq->request), sz, error);
  check_pending();

  // pending request can be dropped
  cxx::unique_ptr<Pending_request> ureq(preq);
}

int
Block_device::Virtio_client::build_datablocks(Pending_request *preq)
{
  auto *req = preq->request.get();
  auto dir = preq->dir();

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

      l4_size_t off = b.mem->ds_offset() + (l4_addr_t) b.addr
                      - (l4_addr_t) b.mem->local_base();

      l4_size_t sz = b.len / _device->sector_size();

      if (sz * _device->sector_size() != b.len)
        {
          Dbg::warn().printf("Bad block size 0x%x\n", b.len);
          return -L4_EIO;
        };

      L4Re::Dma_space::Dma_addr phys;
      long ret = _device->dma_map(b.mem->ds(), off, sz, dir, &phys);
      if (ret < 0)
        return ret;

      Inout_block *blk;
      if (last_blk)
        {
          last_blk->next = cxx::make_unique<Inout_block>();
          blk = last_blk->next.get();
        }
      else
        blk = &preq->blocks;

      blk->dma_addr = phys;
      blk->virt_addr = (void *) ((l4_addr_t)b.mem->local_base() + off);
      blk->num_sectors = sz;

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
      int ret = inout_request(_pending.front());
      if (ret == -L4_EBUSY)
        return; // still no unit available, keep element in queue

      // remove element from queue
      auto pending = _pending.pop_front();

      if (ret < 0)
        // on any other error, send a response to the client immediately
        finalize_request(cxx::move(pending->request), 0,
                         L4VIRTIO_BLOCK_S_IOERR);
      else
        // request has been successfully sent to hardware
        // which now has ownership of Request pointer, so release here
        pending.release();
    }

  // clean out requests in the virtqueue
  kick();
}
