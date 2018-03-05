/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <functional>

#include <l4/cxx/unique_ptr>
#include <l4/re/dma_space>

namespace Block_device {

/**
 * Description of a block to be sent to the device.
 *
 * Block may be scatter gather in which case they are chained
 * via the next pointer.
 */
struct Inout_block
{
  L4Re::Dma_space::Dma_addr dma_addr;
  void *virt_addr;
  l4_uint32_t num_sectors;
  cxx::unique_ptr<Inout_block> next;
};

typedef std::function<void(int, l4_size_t)> Inout_callback;

} // name space
