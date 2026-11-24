/*
 * Copyright (C) 2026 Jan Vidar Krey, janvidar@extatic.org
 * See the file "COPYING" for licensing details.
 */

#ifndef HAVE_DROP_PUMP_H
#define HAVE_DROP_PUMP_H

#include <samurai/eventloop.h>
#include <samurai/io/net/socketmonitor.h>

#include <chrono>

namespace Drop {

/**
 * Drive a loop's sockets and timers until a condition holds or time runs out.
 *
 * This is what makes the synchronous entry points work, and it is the same
 * shape as Samurai's own HTTP::fetch(). It carries the same warning: it
 * dispatches the event loop re-entrantly, so it MUST NOT be called from inside
 * an event handler, where a handler running inside another handler can destroy
 * the socket whose callback is on the stack. Like fetch() it leaves posted
 * messages for the loop's owner to deliver, since a listener receiving one from
 * in here would be running inside whatever called this.
 *
 * @return whether the condition holds, which is false only on the timeout.
 */
template<typename Predicate>
bool pump(Samurai::EventLoop& loop, Predicate done, std::chrono::milliseconds timeout)
{
	const auto deadline = std::chrono::steady_clock::now() + timeout;

	while (!done())
	{
		if (std::chrono::steady_clock::now() > deadline)
			return done();

		/* A short slice rather than the whole remaining budget: a timer that
		   comes due while the monitor is waiting should fire close to when it
		   was meant to, not whenever a socket next becomes readable. */
		loop.monitor().wait(5);
	}
	return true;
}

}

#endif // HAVE_DROP_PUMP_H
