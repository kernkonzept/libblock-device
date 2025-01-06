/*
 * Copyright (C) 2014, 2020, 2024 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */
#pragma once

#include <l4/re/env.h>
#include <l4/re/util/object_registry>
#include <l4/re/util/br_manager>
#include <l4/cxx/ipc_timeout_queue>
#include <l4/cxx/ref_ptr>
#include <l4/cxx/exceptions>
#include <l4/libblock-device/debug.h>

#include <functional>

namespace Block_device { namespace Errand {

/// Server interface used to schedule all deferred tasks
extern L4::Ipc_svr::Server_iface *_sif;

/**
 * Errand handling function.
 */
typedef std::function<void()> Callback;

/**
 * Wrapper for a regularly repeated task.
 */
class Poll_errand
: public L4::Ipc_svr::Timeout_queue::Timeout,
  public cxx::Ref_obj
{
public:
  void expired() final
  {
    // Recapture the reference pointer from the timeout queue.
    cxx::Ref_ptr<Poll_errand> p(this, false);

    try
      {
        if (_poll())
          _callback(true);
        else
            if (--_retries <= 0)
              _callback(false);
            else
              reschedule();
      }
    catch (L4::Runtime_error const &e)
      {
        Err().printf("Polling task failed: %s\n", e.str());
      }
  }


  void reschedule()
  {
    // create a place holder reference pointer for the timeout queue
    cxx::Ref_ptr<Poll_errand> p(this);

    _sif->add_timeout(p.release(), l4_kip_clock(l4re_kip()) + _interval);
  }

  // Class can only be instantiated as a reference counting object.
  template< typename T, typename... Args >
  friend
  cxx::Ref_ptr<T> cxx::make_ref_obj(Args &&... args);

private:
  Poll_errand(int retries, int interval,
              std::function<bool()> const &poll_func,
              std::function<void(bool)> const &callback)
  : _retries(retries),
    _interval(interval),
    _poll(poll_func),
    _callback(callback)
  {}

  int _retries;
  int _interval;
  std::function<bool()> _poll;
  std::function<void(bool)> _callback;
};

/**
 * Wrapper for a small task executed asynchronously in the server loop.
 *
 * Errands are implemented as timeout tasks. They might be queued
 * with the current timestamp, so that they are executed as soon as possible
 * on the next iteration of the server loop or they might be scheduled with
 * a timeout, which is particularly useful if the driver has to do a
 * busy wait on the hardware.
 *
 */
class Errand
: public L4::Ipc_svr::Timeout_queue::Timeout,
  public cxx::Ref_obj
{
public:
  void expired() final
  {
    // Recapture the reference pointer from the timeout queue.
    cxx::Ref_ptr<Errand> p(this, false);

    if (_callback)
      {
        try
          {
            _callback();
          }
        catch (L4::Runtime_error const &e)
          {
            Err().printf("Asynchronous task failed: %s\n", e.str());
          }
      }
  }

  void reschedule(unsigned interval = 0)
  {
    // create a placeholder reference pointer for the timeout queue
    cxx::Ref_ptr<Errand> p(this);

    _sif->add_timeout(p.release(), l4_kip_clock(l4re_kip()) + interval);
  }

  // Class can only be instantiated as a reference counting object.
  template< typename T, typename... Args >
  friend
  cxx::Ref_ptr<T> cxx::make_ref_obj(Args &&... args);

private:
  Errand(Callback const &callback) : _callback(callback) {}

  Callback _callback; ///< Function to execute on timeout.
};

struct Loop_hooks
: L4::Ipc_svr::Timeout_queue_hooks<Loop_hooks, L4Re::Util::Br_manager>,
  L4::Ipc_svr::Ignore_errors
{
  l4_kernel_clock_t now() { return l4_kip_clock(l4re_kip()); }
};

using Errand_server = L4Re::Util::Registry_server<Loop_hooks>;

/**
 * Set the global server interface used for scheduling any deferred task.
 *
 * \param sif Server interface to use.
 */
inline void set_server_iface(L4::Ipc_svr::Server_iface *sif) { _sif = sif; }

/**
 * Schedule a function for later execution.
 *
 * \param callback  Function to execute.
 * \param interval  Minimum interval to wait before the function runs
 *                  (in microseconds, the unit of the KIP clock).
 *
 * The function will be enqueued in the timeout queue of the main server loop.
 *
 */
inline void schedule(Callback const &callback, int interval)
{
  cxx::make_ref_obj<Errand>(callback)->reschedule(interval);
}

/**
 * Repeatedly execute a function.
 *
 * \param retries   Maximum number of times the poll function will be executed.
 * \param interval  Minimum sleep time in microseconds (unit of the KIP clock)
 *                  between runs of the poll function. The function will be
 *                  requeued with the given interval after it has finished a
 *                  single execution round.
 * \param poll_func Polling function, see below.
 * \param callback  Function called after polling has finished, see below.
 *
 * The poll function is repeatedly scheduled for execution in the timeout queue
 * of the main server loop. How often it is run depends on two factors: first
 * of all, the poll function needs to return a boolean. If the return value is
 * true, then the poll function is assumed to have finished. Second, the total
 * number of executions is limited by the retries parameter.
 *
 * After the last execution, the callback function is called with the last
 * return value of the poll function.
 */
inline void poll(int retries, int interval,
                 std::function<bool()> const &poll_func,
                 std::function<void(bool)> const &callback)
{
  if (poll_func())
    callback(true);
  else
    cxx::make_ref_obj<Poll_errand>(retries, interval, poll_func,
                                   callback)->reschedule();
}


} } // name space
