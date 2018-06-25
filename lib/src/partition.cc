/*
 * Copyright (C) 2018 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */

#include <l4/cxx/minmax>

#include <l4/libblock-device/debug.h>
#include <l4/libblock-device/partition.h>

namespace {

  struct Gpt_header
  {
    char         signature[8];
    l4_uint32_t  version;
    l4_uint32_t  header_size;
    l4_uint32_t  crc;
    l4_uint32_t  _reserved;
    l4_uint64_t  current_lba;
    l4_uint64_t  backup_lba;
    l4_uint64_t  first_lba;
    l4_uint64_t  last_lba;
    char         disk_guid[16];
    l4_uint64_t  partition_array_lba;
    l4_uint32_t  partition_array_size;
    l4_uint32_t  entry_size;
    l4_uint32_t  crc_array;
  };

  struct Gpt_entry
  {
    unsigned char type_guid[16];
    unsigned char partition_guid[16];
    l4_uint64_t   first;
    l4_uint64_t   last;
    l4_uint64_t   flags;
    l4_uint16_t   name[36];
  };

  char const *
  render_guid(void const *guid_p, char buf[])
  {
    auto *p = static_cast<unsigned char const *>(guid_p);
    snprintf(buf, 37,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             p[3],  p[2], p[1],  p[0], p[5],  p[4], p[7],  p[6],
             p[8],  p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

    return buf;
  }

}

void
Block_device::Partition_reader::read(Errand::Callback const &callback)
{
  _num_partitions = 0;
  _callback = callback;

  // preparation: read the first two sectors
  _db = _header.inout_block();
  read_sectors(0, &Partition_reader::get_gpt);
}

int
Block_device::Partition_reader::get_partition(l4_size_t idx,
                                              Partition_info *inf) const
{
  if (idx == 0 || idx > _num_partitions)
    return -L4_ERANGE;

  unsigned secsz = _dev->sector_size();
  auto *header = _header.get<Gpt_header const>(secsz);

  Gpt_entry *e = _parray.get<Gpt_entry>((idx - 1) * header->entry_size);

  if (*((l4_uint64_t *) &e->partition_guid) == 0ULL)
    return -L4_ENODEV;

  render_guid(e->partition_guid, inf->guid);

  inf->first = e->first;
  inf->last = e->last;
  inf->flags = e->flags;

  auto info = Dbg::info();
  if (info.is_active())
    {
      info.printf("%3zu: %10lld %10lld  %5gMiB [%.37s]\n",
                  idx, e->first, e->last,
                  (e->last - e->first + 1.0) * secsz / (1 << 20),
                  inf->guid);

      char buf[37];
      info.printf("   : Type: %s\n", render_guid(e->type_guid, buf));
    }

  return L4_EOK;
}

void
Block_device::Partition_reader::get_gpt(int error, l4_size_t)
{
  _header.unmap();

  if (error < 0)
    {
      // can't read from device, we are done
      _callback();
      return;
    }

  // prepare reading of the table from disk
  unsigned secsz = _dev->sector_size();
  auto *header = _header.get<Gpt_header const>(secsz);

  if (strncmp(header->signature, "EFI PART", 8) != 0)
    {
      _callback();
      return;
    }

  // XXX check CRC32 of header
  auto info = Dbg::info();
  auto trace = Dbg::trace();

  info.printf("GUID partition header found with up to %d partitions.\n",
              header->partition_array_size);
  char buf[37];
  info.printf("GUID: %s\n", render_guid(header->disk_guid, buf));
  trace.printf("Header positions: %llx (Backup: %llx)\n",
               header->current_lba, header->backup_lba);
  trace.printf("First + last: %llx and %llx\n",
               header->first_lba, header->last_lba);
  trace.printf("Partition table at %llx\n",
               header->partition_array_lba);
  trace.printf("Size of a partition entry: %d\n",
               header->entry_size);

  info.printf("GUID partition header found with %d partitions.\n",
              header->partition_array_size);

  _num_partitions = cxx::min<l4_uint32_t>(header->partition_array_size,
                                          Max_partitions);

  l4_size_t arraysz = _num_partitions * header->entry_size;
  l4_size_t numsec = (arraysz - 1 + secsz) / secsz;

  _parray = Inout_memory(numsec, _dev, L4Re::Dma_space::Direction::From_device);
  trace.printf("Reading GPT table @ 0x%p\n", _parray.get<void>(0));

  _db = _parray.inout_block();
  read_sectors(header->partition_array_lba, &Partition_reader::done_gpt);
}

void
Block_device::Partition_reader::done_gpt(int error, l4_size_t)
{
  _parray.unmap();

  // XXX check CRC32 of table

  if (error < 0)
    _num_partitions = 0;

  _callback();
}

void
Block_device::Partition_reader::read_sectors(
    l4_uint64_t sector, void (Partition_reader::*func)(int, l4_size_t))
{
  using namespace std::placeholders;
  auto next = std::bind(func, this, _1, _2);

  Errand::poll(10, 10000,
               [=]()
                 {
                   int ret = _dev->inout_data(sector, _db, next,
                                              L4Re::Dma_space::Direction::From_device);
                   if (ret < 0 && ret != -L4_EBUSY)
                     _callback();
                   return ret != -L4_EBUSY;
                 },
               [=](bool ret) { if (!ret) _callback(); }
              );
}
