/*
 * Copyright (C) 2018-2022, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/cxx/ref_ptr>

#include <l4/libblock-device/device.h>
#include <l4/libblock-device/partition.h>

#include <string>
#include <locale>
#include <codecvt>

namespace Block_device {

namespace Impl {

  /**
   * Dummy class used when the device class is not derived from
   * Device_discard_feature.
   */
  template <typename PART_DEV, typename BASE_DEV,
            bool = std::is_base_of<Device_discard_feature, BASE_DEV>::value>
  class Partitioned_device_discard_mixin : public BASE_DEV {};

  /**
   * Mixin implementing discard for partition devices.
   *
   * \tparam PART_DEV  Class of the partition device
   * \tparam BASE_DEV  Class implementing the Device interface.
   */
  template <typename PART_DEV, typename BASE_DEV>
  class Partitioned_device_discard_mixin<PART_DEV, BASE_DEV, true>
  : public BASE_DEV
  {
    using Base = BASE_DEV;
    using Part_device = PART_DEV;

  public:
    typename Base::Discard_info discard_info() const override
    {
      return dev()->parent()->discard_info();
    }

    int discard(l4_uint64_t offset, Inout_block const &blocks,
                Inout_callback const &cb, bool discard) override
    {
      auto sz = dev()->partition_size();

      if (offset > sz)
        return -L4_EINVAL;

      Inout_block const *cur = &blocks;
      while (cur)
        {
          if (cur->sector >= sz - offset)
            return -L4_EINVAL;
          if (cur->num_sectors > sz)
            return -L4_EINVAL;
          if (offset + cur->sector > sz - cur->num_sectors)
            return -L4_EINVAL;

          cur = cur->next.get();
        }

      auto start = offset + dev()->partition_start();
      Dbg::trace("partition")
        .printf("Starting sector on disk: 0x%llx\n", start);
      return dev()->parent()->discard(start, blocks, cb, discard);
    }

  private:
    Part_device const *dev() const
    { return static_cast<Part_device const *>(this); }
  };

}

/**
 * A partition device for the given device interface.
 *
 * \tparam  BASE_DEV  Class defining the device interface.
 *                    Attention: this is not the class implementing the
 *                    device iteself.
 */
template <typename BASE_DEV = Device>
class Partitioned_device
: public Impl::Partitioned_device_discard_mixin<Partitioned_device<BASE_DEV>, BASE_DEV>
{
public:
  using Device_type = BASE_DEV;

  Partitioned_device(cxx::Ref_ptr<Device_type> const &dev,
                     unsigned partition_id, Partition_info const &pi)
  : _name(pi.name),
    _parent(dev),
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

    static_assert(sizeof(_guid) == sizeof(pi.guid), "String size mismatch");
    memcpy(_guid, pi.guid, sizeof(_guid));
  }

  Notification_domain const *notification_domain() const override
  { return _parent->notification_domain(); }

  bool is_read_only() const override
  { return _parent->is_read_only(); }

  bool match_hid(cxx::String const &hid) const override
  {
    if (hid == cxx::String(_guid, 36))
      return true;

    _Pragma("GCC diagnostic push");
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"");
    std::u16string whid =
      std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>{}
        .from_bytes(std::string(hid.start(), hid.len()));
    _Pragma("GCC diagnostic pop");
    if (whid == _name)
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

  l4_size_t max_size() const override
  { return _parent->max_size(); }

  unsigned max_segments() const override
  { return _parent->max_segments(); }

  void reset() override
  {}

  int dma_map(Block_device::Mem_region *region, l4_addr_t offset,
              l4_size_t num_sectors, L4Re::Dma_space::Direction dir,
              L4Re::Dma_space::Dma_addr *phys) override
  { return _parent->dma_map(region, offset, num_sectors, dir, phys); }

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

  int flush(Inout_callback const &cb) override
  {
    return _parent->flush(cb);
  }

  void start_device_scan(Block_device::Errand::Callback const &callback) override
  { callback(); }

  l4_uint64_t partition_size() const
  { return _size; }

  l4_uint64_t partition_start() const
  { return _start; }

  Device_type *parent() const
  { return _parent.get(); }


private:
  char _guid[37];
  std::u16string  _name;
  char _partition_id[4];
  cxx::Ref_ptr<Device_type> _parent;
  l4_uint64_t _start;
  l4_uint64_t _size;
};

} // name space
