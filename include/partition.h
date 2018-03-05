/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <cstring>

#include <l4/cxx/ref_ptr>

#include <l4/l4virtio/virtio_block.h>

#include <l4/libblock-device/device.h>
#include <l4/libblock-device/errand.h>
#include <l4/libblock-device/inout_memory.h>

namespace Block_device {

/**
 * Information about a single partition.
 */
struct Partition_info
{
  char           guid[37];  ///< ID of the partition.
  l4_uint64_t    first;     ///< First valid sector.
  l4_uint64_t    last;      ///< Last valid sector.
  l4_uint64_t    flags;     ///< Additional flags, depending on partition type.
};


/**
 * Partition table reader for block devices.
 */
class Partition_reader : public cxx::Ref_obj
{
  enum
  {
    Max_partitions = 1024  ///< Maximum number of partitions to be scanned.
  };

public:
  Partition_reader(Device *dev)
  : _num_partitions(0),
    _dev(dev),
    _header(2, dev, L4Re::Dma_space::Direction::From_device)
  {}

  void read(Errand::Callback const &callback);

  l4_size_t table_size() const
  { return _num_partitions; }

  int get_partition(l4_size_t idx, Partition_info *inf) const;

private:
  void get_gpt(int error, l4_size_t);
  void done_gpt(int error, l4_size_t);

  void read_sectors(l4_uint64_t sector,
                    void (Partition_reader::*func)(int, l4_size_t));

  l4_size_t _num_partitions;
  Inout_block _db;
  Device *_dev;
  Inout_memory _header;
  Inout_memory _parray;
  Errand::Callback _callback;
};

}
