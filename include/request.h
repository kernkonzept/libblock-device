/*
 * Copyright (C) 2019-2020, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

namespace Block_device {

/**
 * Interface for pending requests.
 */
struct Pending_request
{
  virtual ~Pending_request() = 0;

  /**
   * Callback used when the request is ready for processing.
   *
   * \retval L4_EOK     Request successfully issued. The callee has taken
   *                    ownership of the request.
   * \retval -L4_EBUSY  Device is still busy. The callee must not requeue
   *                    the request as it will remain in the queue.
   * \retval < 0        Other fatal error. The caller may dispose of the
   *                    request.
   */
  virtual int handle_request() = 0;

  /**
   * Callback used when a request is dropped from the queue.
   *
   * The function is called for notification only. The request will be
   * destroyed.
   */
  virtual void fail_request() = 0;
};

inline Pending_request::~Pending_request() = default;

} // namespace
