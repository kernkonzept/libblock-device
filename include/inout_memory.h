/*
 * Copyright (C) 2014 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/re/error_helper>
#include <l4/re/env>
#include <l4/re/util/unique_cap>
#include <l4/re/rm>
#include <l4/re/dma_space>
#include <l4/cxx/ref_ptr>

#include <l4/libblock-device/device.h>
#include <l4/libblock-device/types.h>

namespace Block_device {

/**
 *  Helper class that temporarily allocates memory that can be used
 *  for in/out operations with the device.
 */
class Inout_memory : public cxx::Ref_obj
{
public:
  Inout_memory() : _paddr(0) {}
  Inout_memory(l4_uint32_t num_sectors, Device *dev,
               L4Re::Dma_space::Direction dir)
  : _device(dev), _paddr(0), _dir(dir), _num_sectors(num_sectors)
  {
    auto lcap = L4Re::chkcap(L4Re::Util::make_unique_cap<L4Re::Dataspace>(),
                             "Allocate dataspace capability for IO memory.");

    auto *e = L4Re::Env::env();
    long sz = num_sectors * _device->sector_size();
    L4Re::chksys(e->mem_alloc()->alloc(sz, lcap.get(),
                                       L4Re::Mem_alloc::Continuous
                                       | L4Re::Mem_alloc::Pinned),
                 "Allocate pinned memory.");

    L4Re::chksys(e->rm()->attach(&_region, sz, L4Re::Rm::Search_addr,
                                 L4::Ipc::make_cap_rw(lcap.get()), 0,
                                 L4_PAGESHIFT),
                 "Attach IO memory.");

    _cap = cxx::move(lcap);

    L4Re::chksys(_device->dma_map(_cap.get(), 0, _num_sectors, dir, &_paddr),
                 "Lock memory region for DMA.");
  }

  Inout_memory(Inout_memory const &) = delete;
  Inout_memory(Inout_memory &&) = delete;

  Inout_memory &operator=(Inout_memory &&rhs)
  {
    if (this != &rhs)
      {
        _device = rhs._device;
        _cap = cxx::move(rhs._cap);
        _region = cxx::move(rhs._region);
        _paddr = rhs._paddr;
        _dir = rhs._dir;
        _num_sectors = rhs._num_sectors;
        rhs._paddr = 0;
      }

    return *this;
  }

  ~Inout_memory()
  {
    if (_paddr)
      unmap();
  }


  void unmap()
  {
    L4Re::chksys(_device->dma_unmap(_paddr, _num_sectors, _dir));
    _paddr = 0;
  }

  Inout_block inout_block() const
  {
    Inout_block blk;

    blk.dma_addr = _paddr;
    blk.virt_addr = _region.get();
    blk.num_sectors = _num_sectors;
    blk.next.reset();

    return blk;
  }

  template <class T>
  T *get(unsigned offset) const
  { return reinterpret_cast<T *>(_region.get() + offset); }

private:
  Device *_device;
  L4Re::Util::Unique_cap<L4Re::Dataspace> _cap;
  L4Re::Rm::Unique_region<char *> _region;
  L4Re::Dma_space::Dma_addr _paddr;
  L4Re::Dma_space::Direction _dir;
  l4_uint32_t _num_sectors;
};

} // name space
