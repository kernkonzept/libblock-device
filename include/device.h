/*
 * Copyright (C) 2018-2020, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/cxx/ref_ptr>
#include <l4/cxx/string>
#include <l4/re/dataspace>
#include <l4/re/dma_space>

#include <l4/libblock-device/errand.h>
#include <l4/libblock-device/types.h>

namespace Block_device {

/**
 * Opaque type for representing a notification domain
 *
 * Notification domains must be assigned to devices such that all devices that
 * require a shared pool of resources to process their requests, also find
 * themselves in the same notification domain. In particular, if two devices
 * access common resources, then they must be in the same domain. An example
 * of this are two partitions sharing the same parent device because processing
 * of requests for one partition might depend on completion of request
 * processing in another partition. On the other hand, independent disk devices
 * will typically not share the same notification domain because their requests
 * are completely independent of each other.
 */
struct Notification_domain
{
};

struct Device : public cxx::Ref_obj
{
  virtual ~Device() = 0;

  /// Returns the device notification domain.
  virtual Notification_domain const *notification_domain() const = 0;

  /// Returns if this is a read-only device.
  virtual bool is_read_only() const = 0;
  /// check if the given string identifies the device.
  virtual bool match_hid(cxx::String const &hid) const = 0;
  /// Returns the total capacity of this device in bytes.
  virtual l4_uint64_t capacity() const = 0;
  /// Returns the size of physical hardware sectors.
  virtual l4_size_t sector_size() const = 0;
  /// Returns the maximum size of one segment.
  virtual l4_size_t max_size() const = 0;
  /// Returns the number of segments allowed for scatter-gather-operations.
  virtual unsigned max_segments() const = 0;

  /// Resets the device into a good known state.
  virtual void reset() = 0;

  /// Prepares the given data space for DMA with the device.
  virtual int dma_map(Block_device::Mem_region *region, l4_addr_t offset,
                      l4_size_t num_sectors, L4Re::Dma_space::Direction dir,
                      L4Re::Dma_space::Dma_addr *phys) = 0;

  /// Releases the given DMA region.
  virtual int dma_unmap(L4Re::Dma_space::Dma_addr phys, l4_size_t num_sectors,
                        L4Re::Dma_space::Direction dir) = 0;

  /**
   * Read or write one or more blocks to/from the device.
   *
   * \param sector  Number of the first sector to use for the operation.
   * \param blocks  Linked list of blocks with payload data.
   * \param cb      (Optional) callback called when the request is finished.
   *                The callback is called only, when the function has
   *                previously successfully returned.
   * \param dir     Direction of the operation (read or write).
   *
   * \retval L4_EOK     Request was successfully issued.
   * \retval -L4_EBUSY  Device is busy with other requests, try again later.
   * \retval <0         Other non-recoverable error.
   */
  virtual int inout_data(l4_uint64_t sector,
                         Block_device::Inout_block const &blocks,
                         Block_device::Inout_callback const &cb,
                         L4Re::Dma_space::Direction dir) = 0;

  /** Flush device internal caches.
   *
   * \param cb      (Optional) callback called when the request is finished.
   *                The callback is called only, when the function has
   *                previously successfully returned.
   *
   * \retval L4_EOK     Request was successfully issued.
   * \retval -L4_EBUSY  Device is busy with other requests, try again later.
   * \retval <0         Other non-recoverable error.
   */
  virtual int flush(Block_device::Inout_callback const &cb) = 0;

  /// Initialises the device.
  virtual void start_device_scan(Block_device::Errand::Callback const &callback) = 0;
};

inline Device::~Device() = default;

/**
 * Device with a per-device notification domain.
 */
template <typename DEV>
struct Device_with_notification_domain : DEV
{
  Notification_domain dom;
  Notification_domain const *notification_domain() const override
  { return &dom; }
};

/**
 * Partial interface for devices that offer discard functionality.
 */
struct Device_discard_feature
{
  struct Discard_info
  {
    unsigned max_discard_sectors = 0;
    unsigned max_discard_seg = 0;
    unsigned discard_sector_alignment = 1;
    unsigned max_write_zeroes_sectors = 0;
    unsigned max_write_zeroes_seg = 0;
    bool write_zeroes_may_unmap = false;
  };

  virtual Discard_info discard_info() const = 0;

  /// Issues one or more WRITE_ZEROES or DISCARD commands.
  virtual int discard(l4_uint64_t offset,
                      Block_device::Inout_block const &blocks,
                      Block_device::Inout_callback const &cb, bool discard) = 0;

protected:
  ~Device_discard_feature() = default;
};

} // name space
