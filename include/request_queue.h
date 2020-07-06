/*
 * Copyright (C) 2019 Kernkonzept GmbH.
 * Author(s): Sarah Hoffmann <sarah.hoffmann@kernkonzept.com>
 *
 * This file is distributed under the terms of the GNU General Public
 * License, version 2.  Please see the COPYING-GPL-2 file for details.
 */
#pragma once

#include <functional>
#include <deque>

#include <l4/cxx/unique_ptr>

namespace Block_device {

/**
 * Interface for pending requests that can be queued.
 */
struct Pending_request
{
  /**
   * Base class for object that can be owner of a pending request.
   *
   * The queue does not use the type itself or keep track of the owner.
   * The implementation needs to provide a function to check a given object
   * for ownership of the request.
   */
  struct Owner {};

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

  /**
   * Check if somebody is owner of this request.
   *
   * \param owner  Pointer to owner to check against.
   *
   * \return True, if the given object owns the request.
   */
  virtual bool is_owner(Owner *owner) = 0;
};

inline Pending_request::~Pending_request() = default;

struct Request_queue
{
  virtual ~Request_queue() = 0;

  /**
   * Add a new request to the pending queue.
   *
   * \param request  The pending request. The queue has ownership while the
   *                 request is pending.
   */
  virtual void add_to_queue(cxx::unique_ptr<Pending_request> &&request) = 0;

  /**
   * Remove all items of the given client from the pending queue.
   *
   * \param owner     Object to drain queue for. All pending requests with the
   *                  same owner pointer are removed.
   * \param finalize  If true, pending requests will be finalized with error. In
   *                  that case, the client memory must be still accessible.
   *                  If false, pending requests will not be finalized, because the
   *                  client memory (virtqueue and buffers) is expected not to be
   *                  accessible.
   */
  virtual void drain_queue_for(Pending_request::Owner *owner, bool finalize) = 0;

  /**
   * Process as many items from the pending queue as possible.
   */
  virtual void process_pending() = 0;

  /// Check if the queue contains any pending requests.
  virtual bool empty() const = 0;
};

inline Request_queue::~Request_queue() = default;

/**
 * Simple request queue implementation based on a linked list.
 */
class Simple_request_queue : public Request_queue
{
public:
  bool empty() const override { return _queue.empty(); }

  void add_to_queue(cxx::unique_ptr<Pending_request> &&request) override
  { _queue.emplace_back(std::move(request)); }

  void drain_queue_for(Pending_request::Owner *owner, bool finalize) override
  {
    for (auto it = _queue.begin(); it != _queue.end();)
      {
        if ((*it)->is_owner(owner))
          {
            if (finalize)
              (*it)->fail_request();
            it = _queue.erase(it);
          }
        else
          ++it;
      }
  }

  void process_pending() override
  {
    while (!_queue.empty())
      {
        auto &front = _queue.front();
        int ret = front->handle_request();

        if (ret == -L4_EBUSY)
          // still no processing unit available, keep element in queue
          return;

        if (ret >= 0)
          // request has been sent to hardware
          front.release();

        // element was processed, remove it from queue
        _queue.pop_front();
      }
  }

private:
  std::deque<cxx::unique_ptr<Pending_request>> _queue;
};

} // namespace
