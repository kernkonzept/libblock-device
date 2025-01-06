/*
 * Copyright (C) 2014, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#include <l4/libblock-device/errand.h>

L4::Ipc_svr::Server_iface *Block_device::Errand::_sif;
