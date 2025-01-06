/*
 * Copyright (C) 2018, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/re/util/debug>

namespace Block_device {

class Err : public L4Re::Util::Err
{
public:
  explicit
  Err(Level l = Normal) : L4Re::Util::Err(l, "") {}
};

class Dbg : public L4Re::Util::Dbg
{
  enum Level
  {
    Blk_warn  = 1,
    Blk_info  = 2,
    Blk_trace = 4,
    Blk_steptrace = 8
  };

public:
  Dbg(unsigned long l = Blk_info, char const *subsys = "")
  : L4Re::Util::Dbg(l, "libblock", subsys) {}

  static Dbg warn(char const *subsys = "")
  { return Dbg(Blk_warn, subsys); }

  static Dbg info(char const *subsys = "")
  { return Dbg(Blk_info, subsys); }

  static Dbg trace(char const *subsys = "")
  { return Dbg(Blk_trace, subsys); }

  static Dbg steptrace(char const *subsys = "")
  { return Dbg(Blk_steptrace, subsys); }
};

} // name space

