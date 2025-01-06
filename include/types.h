/*
 * Copyright (C) 2018-2019, 2023-2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <functional>

#include <l4/cxx/unique_ptr>
#include <l4/re/dma_space>
#include <l4/l4virtio/server/l4virtio>

namespace Block_device {

/** Flags used in Inout_block */
enum Inout_flags
  {
    Inout_f_wb = 1,     ///< Assume write-back cache.
    Inout_f_unmap = 2,  ///< Discard functionality desired.
  };

enum Shutdown_type
{
  /// No shutdown in progress or waking up from suspend.
  Running = 0,
  /// The client capability has abruptly disappeared, presumably because the
  //  client had crashed.
  Client_gone,
  /// The client issued a shutdown RPC.
  Client_shutdown,
  /// The system is shutting down.
  System_shutdown,
  /// The system is suspending.
  System_suspend
};

/**
 * Base class used by the driver implementation to derive its own DMA mapping
 * tracking structure.
 */
struct Dma_region_info
{
  virtual ~Dma_region_info() = default;
};

/**
 * Additional info stored in each L4virtio::Svr::Driver_mem_region_t used for
 * tracking dataspace-wide DMA mappings.
 */
struct Mem_region_info
{
  cxx::unique_ptr<Dma_region_info> dma_info;
};

using Mem_region =
  L4virtio::Svr::Driver_mem_region_t<Mem_region_info>;

/**
 * Description of an inout block to be sent to the device.
 *
 * Block may be scatter gather in which case they are chained
 * via the next pointer.
 */
struct Inout_block
{
  L4Re::Dma_space::Dma_addr dma_addr = 0;
  void *virt_addr = nullptr;
  /// Initial sector. Used only by DISCARD / WRITE_ZEROES requests.
  l4_uint64_t sector = 0;
  l4_uint32_t num_sectors = 0;
  /// Flags from Inout_flags.
  l4_uint32_t flags = 0;
  cxx::unique_ptr<Inout_block> next;
};

typedef std::function<void(int, l4_size_t)> Inout_callback;

} // name space
