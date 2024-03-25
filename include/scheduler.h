/*
 * Copyright (C) 2024 Kernkonzept GmbH.
 * Author(s): Jakub Jermar <jakub.jermar@kernkonzept.com>
 *
 * License: see LICENSE.spdx (in this directory or the directories above)
 */

#pragma once

#include <vector>

#include <l4/cxx/unique_ptr>
#include <l4/re/error_helper>
#include <l4/sys/cxx/ipc_epiface>

#include <l4/libblock-device/debug.h>
#include <l4/libblock-device/virtio_client.h>

namespace Block_device {

/**
 * Scheduler base class.
 *
 * Derive from this class and override `get_weight()` and `get_cost()` to
 * implement the desired scheduling algorithm.
 *
 * The interpretation of the weight function depends on the definition of the
 * cost function. For example, if the cost of each request is fixed to be
 * 1, the weight then says how many requests per scheduling round the client
 * can process. If the weight of each client is also fixed to be 1, it will
 * result in the Round Robin scheduler. If the request cost derives from the
 * size of data the request operates on, the weight determines a data limit.
 */
template <typename DEV>
class Scheduler_base
{
protected:
  using Device_type = DEV;
  using Client_type = Virtio_client<Device_type>;

private:
  class Irq_object : public L4::Irqep_t<Irq_object>
  {
  public:
    Irq_object(Scheduler_base *parent) : _parent(parent) {}

    void handle_irq() { _parent->schedule(); }

  private:
    Scheduler_base *_parent;
  };
  Irq_object _irq_handler;

  struct Context
  {
    cxx::unique_ptr<Pending_request> pending;
    Client_type *client;

    bool device_busy;
    l4_size_t cost;

    Context(Client_type *client) : client(client), device_busy(false), cost(0)
    {}

    bool same_notification_domain(Client_type const *c) const
    { return c->notification_domain() == client->notification_domain(); }
  };

  using Queue_type = std::vector<cxx::unique_ptr<Context>>;
  using Iterator_type = typename Queue_type::const_iterator;

public:
  Scheduler_base(L4::Registry_iface *registry)
  : _irq_handler(this), _registry(registry), _next(_clients.cend())
  {
    L4Re::chkcap(registry->register_irq_obj(&_irq_handler),
                 "Registering device notify IRQ object.");
  }

  virtual ~Scheduler_base()
  {
    // We need to explicitly delete the IRQ object created in register_irq_obj()
    // ourselves. Even though unregister_obj() will unmap the cap, it might stay
    // alive because it was given out to the client. Hence it might be
    // dispatched even after unregister_obj() returned!
    L4::Cap<L4::Task>(L4Re::This_task)
      ->unmap(_irq_handler.obj_cap().fpage(),
              L4_FP_ALL_SPACES | L4_FP_DELETE_OBJ);
    _registry->unregister_obj(&_irq_handler);
  }

  /**
   * Return the weight of the client.
   */
  virtual l4_size_t get_weight(Client_type const *) = 0;

  /**
   * Return the cost of the pending request.
   */
  virtual l4_size_t get_cost(Pending_request const &) = 0;

  void add_client(Client_type *client)
  {
    Dbg::trace().printf("Adding client %p to request scheduler.\n", client);

    // make sure the client uses the request scheduler's device_notify_irq
    client->set_device_notify_irq(
      L4::cap_cast<L4::Irq>(_irq_handler.obj_cap()));

    client->set_client_invalidate_cb([this, client](bool fail_pending) {
      client_invalidate(client, fail_pending);
    });

    client->set_client_idle_cb([this, client]() { client_idle(client); });

    _clients.push_back(cxx::make_unique<Context>(client));
    _next = _clients.cend();
  }

  void remove_client(Client_type *client)
  {
    Dbg::trace().printf("Removing client %p from request scheduler.\n", client);
    _clients.erase(std::remove_if(_clients.begin(), _clients.end(),
                                  [client](cxx::unique_ptr<Context> &c) {
                                    return c->client == client;
                                  }));
    _next = _clients.cend();
  }

  Queue_type const &clients()
  { return _clients; }

private:
  /** Invalidate client state stored in the scheduler. */
  void client_invalidate(Client_type *client, bool fail_pending)
  {
    for (auto &c : _clients)
      if (c->client == client)
        {
          c->device_busy = false;
          c->cost = 0;
          if (c->pending)
            {
              if (fail_pending)
                c->pending->fail_request();
              c->pending.reset();
            }
        }
  }

  /** Act upon client's device becoming not busy. */
  void client_idle(Client_type *client)
  {
    bool resched = false;
    for (auto &c : _clients)
      if (c->device_busy && c->same_notification_domain(client))
        {
          c->device_busy = false;
          resched = true;
        }

    if (resched)
      {
        // By triggering the scheduler asynchronously we make synchronous
        // request processing in the device implementation possible. In
        // any case we need to be careful not to start scheduling the
        // pending request which is being currently handled.
        L4::cap_cast<L4::Irq>(this->_irq_handler.obj_cap())->trigger();
      }
  }

  /**
   * Handle one pending request.
   *
   * \retval  True if the pending request was successfully sent to the device
   *          or failed immediately or the accumulated client's request cost
   *          would exceed the client's weight.
   * \retval  False if the pending request could not be handled and remains
   *          pending.
   */
  bool handle_pending(Context *c)
  {
    auto cost = get_cost(*(c->pending));

    if (c->cost + cost > get_weight(c->client))
      {
        Dbg::trace().printf("Preempting client %p (cost=%zu+%zu, weight=%zu)\n",
                            c->client, c->cost, cost, get_weight(c->client));

        // Charge client's entire weight to force schedule() to give another
        // client a chance.
        c->cost = get_weight(c->client);
        return true;
      }

    // Keep the pending request in its place while handling the request.
    // This helps to make sure that the scheduler will not try to schedule
    // new requests while handling the pending one.
    int ret = c->pending->handle_request();
    if (ret == -L4_EBUSY)
      {
        c->device_busy = true;
        return false;
      }

    c->cost += cost;

    if (ret < 0)
      c->pending.reset();
    else
      c->pending.release();
    return true;
  }

  /**
   * Schedule one client.
   *
   * If the client has a pending request, possible new requests are not
   * processed. Instead, an attempt is made to handle the pending request.
   * If the client has no pending request but has a new request, it first
   * processes the new request (creating a pending request) and immediately
   * attempts to handle it.
   *
   * \retval  True if the client made forward progress and it should be checked
   *          again in the next round.
   * \retval  False if the client didn't make forward progress (e.g. had a
   *          pending request and still has a pending request; had a new request
   *          which became a pending request, but that pending request cannot
   *          be processed now; or there were no new requests for it).
   */
  bool schedule_client(Context *c)
  {
    if (c->pending)
      {
        if (c->device_busy)
          {
            Dbg::trace().printf(
              "Skipping pending request of client %p (busy).\n", c->client);
            return false;
          }

        Dbg::trace().printf("Handling pending request of client %p.\n",
                            c->client);
        // The client has a pending request, we need to handle it first
        // before new requests can be processed. If we manage to handle it,
        // we need to check again in the next round for new requests.
        return handle_pending(c);
      }

    if (c->client->check_for_new_requests())
      {
        auto req = c->client->get_request();
        if (req)
          {
            Dbg::trace().printf("Scheduling request from client %p.\n",
                                c->client);
            c->pending = c->client->start_request(cxx::move(req));
            if (c->pending)
              {
                // We processed one new request by turning it into a pending
                // one and possibly sending it to the device (or not). We
                // need to recheck only if the request was successfully sent
                // to the device.
                return handle_pending(c);
              }
            // We processed one new request immediately (e.g. failed
            // sanity check, runtime error or client state).
            return true;
          }
      }

    return false;
  }

  /**
   * Perform one scheduling step.
   *
   * Traverses the list of all clients and attempts to schedule those that
   * can make some forward progress. Depending on the implementation of the
   * `get_cost` and `get_weight` functions it is permissible for one client to
   * keep processing its queue as long as the accumulated cost of processed
   * requests within the scheduling step does not exceed the client's weight.
   * When all clients are visited and none of them can make forward progress,
   * the scheduling step ends. The next scheduling step will begin with the next
   * client (the traversal wraps around at the end of the list).
   */
  void schedule()
  {
    if (_clients.empty())
      return;

    if (_next == _clients.cend())
      _next = _clients.cbegin();

    (*_next)->cost = 0;

    Iterator_type start(_next);
    bool recheck = false;
    for (;;)
      {
        bool progress = schedule_client(_next->get());
        // Move onto the next client only after the current client has depleted
        // its chances to process its queue or if it didn't make any forward
        // progress
        if (!progress || ((*_next)->cost >= get_weight((*_next)->client)))
          {
            ++_next;
            if (_next == _clients.cend())
              _next = _clients.cbegin();
            (*_next)->cost = 0;
          }
        recheck |= progress;
        if (_next == start)
          {
            if (!recheck)
              {
                // already processed all clients and requests, start with
                // the next client next time
                ++_next;
                break;
              }
            else
              recheck = false;
          }
      }
  }

  L4::Registry_iface *_registry;
  Queue_type _clients;
  Iterator_type _next;
};

/**
 * Round Robin scheduler class.
 *
 * All clients have fixed weight of 1 and all requests have fixed cost of 1,
 * giving thus each client one scheduling chance per scheduling round.
 */
template <typename DEV>
struct Rr_scheduler : Scheduler_base<DEV>
{
  using Scheduler_base<DEV>::Scheduler_base;

  l4_size_t
  get_weight(typename Scheduler_base<DEV>::Client_type const *) override
  { return 1; }

  l4_size_t get_cost(Pending_request const &) override
  { return 1; }
};


} // name space
