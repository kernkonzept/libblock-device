# L4Re block device library

libblock-device is a library used by block device servers. It takes
care of processing requests from L4virtio block clients, queuing them and
dispatching them to the associated device.  It also scans devices for
partitions and pairs clients with the found disks and partitions.

The library provides an abstraction for a block device. Block device
implementations must be provided by the user of the library, but the library
provides an implementation for partitioned devices on top of user block
device implementations.

# Documentation

This package is part of the L4Re operating system. For documentation and
build instructions see the
[L4Re wiki](https://kernkonzept.com/L4Re/guides/l4re).

# Contributions

We welcome contributions. Please see our contributors guide on
[how to contribute](https://kernkonzept.com/L4Re/contributing/l4re).

# License

Detailed licensing and copyright information can be found in
the [LICENSE](LICENSE.spdx) file.
