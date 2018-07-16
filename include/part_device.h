/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>

#include <l4/libblock-device/device.h>
#include <l4/libblock-device/partition.h>

namespace Block_device {

class Partitioned_device : public Device
{
public:
  Partitioned_device(cxx::Ref_ptr<Device> const &dev,
                     unsigned partition_id, Partition_info const &pi)
  : _parent(dev),
    _start(pi.first),
    _size(pi.last - pi.first + 1)
  {
    if (pi.last < pi.first)
      L4Re::chksys(-L4_EINVAL,
                   "Last sector of partition before first sector.");

    if (partition_id > 999)
      L4Re::chksys(-L4_EINVAL,
                   "Partition ID must be smaller than 1000.");

    snprintf(_partition_id, sizeof(_partition_id), "%d", partition_id);

    strncpy(_guid, pi.guid, sizeof(_guid));
    _guid[sizeof(_guid) - 1] = 0;
  }

  bool is_read_only() const override
  { return _parent->is_read_only(); }

  bool match_hid(cxx::String const &hid) const override
  {
    if (hid == cxx::String(_guid, 36))
      return true;

    // check for identifier of form: <device_name>:<partition id>
    char const *delim = ":";
    char const *pos = hid.rfind(delim);

    if (pos == hid.end() || !_parent->match_hid(cxx::String(hid.start(), pos)))
      return false;

    return cxx::String(pos + 1, hid.end()) == cxx::String(_partition_id);
  }

  l4_uint64_t capacity() const override
  { return _size * _parent->sector_size(); }

  l4_size_t sector_size() const override
  { return _parent->sector_size(); }

  unsigned max_segments() const override
  { return _parent->max_segments(); }

  unsigned max_in_flight() const override
  { return _parent->max_in_flight(); }

  void reset() override
  {}

  int dma_map(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
              l4_size_t num_sectors, L4Re::Dma_space::Direction dir,
              L4Re::Dma_space::Dma_addr *phys) override
  { return _parent->dma_map(ds, offset, num_sectors, dir, phys); }

  int dma_unmap(L4Re::Dma_space::Dma_addr phys, l4_size_t num_sectors,
                L4Re::Dma_space::Direction dir) override
  { return _parent->dma_unmap(phys, num_sectors, dir); }

  int inout_data(l4_uint64_t sector, Inout_block const &blocks,
                 Inout_callback const &cb,
                 L4Re::Dma_space::Direction dir) override
  {
    if (sector >= _size)
      return -L4_EINVAL;

    l4_uint64_t total = 0;
    Inout_block const *cur = &blocks;
    while (cur)
      {
        total += cur->num_sectors;
        cur = cur->next.get();
      }

    if (total > _size - sector)
      return -L4_EINVAL;

    Dbg::trace("partition").printf("Sector on disk: 0x%llx\n", sector + _start);
    return _parent->inout_data(sector + _start, blocks, cb, dir);
  }

  void start_device_scan(Block_device::Errand::Callback const &callback) override
  { callback(); }

private:
  char _guid[37];
  char _partition_id[4];
  cxx::Ref_ptr<Device> _parent;
  l4_uint64_t _start;
  l4_uint64_t _size;
};

} // name space