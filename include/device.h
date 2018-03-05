/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/cxx/string>
#include <l4/re/dataspace>
#include <l4/re/dma_space>

#include <l4/libblock-device/errand.h>
#include <l4/libblock-device/types.h>

namespace Block_device {

struct Device : public cxx::Ref_obj
{
  virtual ~Device() = 0;

  /// Returns if this is a read-only device.
  virtual bool is_read_only() const = 0;
  /// check if the given string identifies the device.
  virtual bool match_hid(cxx::String const &hid) const = 0;
  /// Returns the total capacity of this device in bytes.
  virtual l4_uint64_t capacity() const = 0;
  /// Returns the size of physical hardware sectors.
  virtual l4_size_t sector_size() const = 0;
  /// Returns the number of segments allowed for scatter-gather-operations.
  virtual unsigned max_segments() const = 0;
  /// Returns the maximum number of requests the device can handle in parallel.
  virtual unsigned max_in_flight() const = 0;

  /// Resets the device into a good known state.
  virtual void reset() = 0;

  /// Prepares the given data space for DMA with the device.
  virtual int dma_map(L4::Cap<L4Re::Dataspace> ds, l4_addr_t offset,
                      l4_size_t num_sectors, L4Re::Dma_space::Direction dir,
                      L4Re::Dma_space::Dma_addr *phys) = 0;

  /// Releases the given DMA region.
  virtual int dma_unmap(L4Re::Dma_space::Dma_addr phys, l4_size_t num_sectors,
                        L4Re::Dma_space::Direction dir) = 0;

  /// Reads or writes one or more of blocks.
  virtual int inout_data(l4_uint64_t sector,
                         Block_device::Inout_block const &blocks,
                         Block_device::Inout_callback const &cb,
                         L4Re::Dma_space::Direction dir) = 0;

  /// Initialises the device.
  virtual void start_device_scan(Block_device::Errand::Callback const &callback) = 0;
};

inline Device::~Device() = default;

} // name space
