# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-13110, USA.

# Author: Serg G. Brester (sebres)
# 
# This module was written as part of ban time increment feature.

__author__ = "Serg G. Brester (sebres)"
__copyright__ = "Copyright (c) 2014 Serg G. Brester"
__license__ = "GPL"

import threading
from collections import OrderedDict, deque
from .jailthread import JailThread
from .failmanager import FailManagerEmpty
import os, logging, time, datetime, math, json, random
import sys
from ..helpers import getLogger
from .mytime import MyTime
from .utils import Utils

# Gets the instance of the logger.
logSys = getLogger(__name__)


class _QEvent(list):
	"""A ticket-bound observer event.

	The object is at the same time the event tuple (method name + arguments),
	the coalescing state holder while it is pending, and the synchronization
	primitive producers may wait on. A single instance per ticket is kept in
	the queue, so retries and ban/unban coalescing never produce duplicates.
	"""
	__slots__ = ('key', 'kind', 'op', 'attempts', 'prepared', 'prepared_for',
		'applied', 'cancelled', 'done', 'last_error')

	def __init__(self, key, kind, op, args):
		super(_QEvent, self).__init__(args)
		## coalescing key, e. g. ('B', jail, ip):
		self.key = key
		## event class: 'B' (ban/unban write), 'F' (failure found), 'flush' (jail flush):
		self.kind = kind
		## desired final state of the ticket: 'add', 'remove', 'flush' or 'failure':
		self.op = op
		## number of already failed database write attempts:
		self.attempts = 0
		## ban-time increase calculation (and prolong timer) done once per payload:
		self.prepared = False
		self.prepared_for = None
		## last state already written to database (None if nothing written yet):
		self.applied = None
		## tombstone marker - event is coalesced away and must be skipped:
		self.cancelled = False
		## last database write error (retry backoff):
		self.last_error = None
		## gets set as soon as the event is settled (written/cancelled/given up):
		self.done = threading.Event()

	def wait_done(self, timeout=None):
		"""Wait until the event is persisted or finally discarded."""
		return self.done.wait(timeout)

	@property
	def ident(self):
		"""Ticket identifier used in log messages."""
		try:
			if self.kind == 'B':
				if self.op == 'add':
					return 'ban:%s:%s' % (self[2].name, self[1].getID())
				return 'unban:%s:%s' % (self[1].name, self[2])
			if self.kind == 'F':
				return 'failure:%s:%s' % (self[1].name, self[2].getID())
			return 'flush:%s' % (self[1].name,)
		except Exception: # pragma: no cover
			return repr(self.key)


class ObserverThread(JailThread):
	"""Handles observing a database, managing bad ips and ban increment.

	Parameters
	----------

	Attributes
	----------
	daemon
	ident
	name
	status
	active : bool
		Control the state of the thread.
	idle : bool
		Control the idle state of the thread.
	sleeptime : int
		The time the thread sleeps for in the loop.
	"""

	# observer is event driven and it sleep organized incremental, so sleep intervals can be shortly:
	DEFAULT_SLEEP_INTERVAL = Utils.DEFAULT_SLEEP_INTERVAL / 10

	## Maximal number of ticket events waiting (or currently retrying) for
	## persistence. Further events get coalesced by ticket or, if impossible,
	## rejected (and counted). Control events (timers, barriers, ...) bypass.
	QUEUE_LIMIT = 1000
	## Bounded exponential backoff for failed database writes:
	DB_RETRY_INTERVAL = 0.1
	DB_RETRY_MAX_INTERVAL = 2.0
	DB_RETRY_MAX_ATTEMPTS = 6
	## Maximal time a producer waits for its own event to be persisted
	## (e. g. explicit unban) - ban main loop never waits anyway:
	PRODUCER_WAIT_TIME = 5

	# ticket-bound events, coalesced per ticket and subject to queue limit:
	_TICKET_EVENTS = {
		'banFound':     ('B', 'add'),
		'banRemoved':   ('B', 'remove'),
		'failureFound': ('F', 'failure'),
		'jailFlushed':  ('flush', 'flush'),
	}

	def __init__(self):
    # init thread
		super(ObserverThread, self).__init__(name='f2b/observer')
		# before started - idle:
		self.idle = True
		## Event queue (FIFO of control tuples and _QEvent ticket entries):
		self._queue_lock = threading.RLock()
		self._queue = deque()
		## Pending ticket entries by coalescing key (one entry per ticket):
		self._tickets = OrderedDict()
		## Monotonic serial for events that must stay distinct below capacity:
		self._serial = 0
		## Ticket entry currently processed (popped from queue but not settled):
		self._inflight = None
		## Event, be notified if anything added to event queue
		self._notify = threading.Event()
		## Wake-up for write retry backoff (merges, shutdown):
		self._retry_wake = threading.Event()
		## Entrance is closed (shutdown in progress) - producers get rejected:
		self._closing = False
		self._stop_deadline = 0
		## Queue capacity and write backoff bounds (overridable per instance):
		self._queue_limit = self.QUEUE_LIMIT
		self._retry_interval = self.DB_RETRY_INTERVAL
		self._retry_max_interval = self.DB_RETRY_MAX_INTERVAL
		self._retry_max_attempts = self.DB_RETRY_MAX_ATTEMPTS
		## Counters (in-memory only, reset on restart):
		self._merged = 0
		self._dropped = 0
		self._dropped_reasons = {}
		self._last_drop_log = 0
		## Sleep for max 60 seconds, it possible to specify infinite to always sleep up to notifying via event, 
		## but so we can later do some service "events" occurred infrequently directly in main loop of observer (not using queue)
		self.sleeptime = 60
		#
		self._timers = {}
		self._paused = False
		self.__db = None
		self.__db_purge_interval = 60*60
		# observer is a not main thread:
		self.daemon = True

	def __getitem__(self, i):
		try:
			return self._queue[i]
		except KeyError:
			raise KeyError("Invalid event index : %s" % i)

	def __delitem__(self, i):
		try:
			del self._queue[i]
		except KeyError:
			raise KeyError("Invalid event index: %s" % i)

	def __iter__(self):
		return iter(self._queue)

	def __len__(self):
		return self._qsize()

	def __eq__(self, other): # Required for Threading
		return False

	def __hash__(self): # Required for Threading
		return id(self)

	def add_named_timer(self, name, starttime, *event):
		"""Add a named timer event to queue will start (and wake) in 'starttime' seconds
		
		Previous timer event with same name will be canceled and trigger self into 
		queue after new 'starttime' value
		"""
		t = self._timers.get(name, None)
		if t is not None:
			t.cancel()
		t = threading.Timer(starttime, self.add, event)
		self._timers[name] = t
		t.start()

	def add_timer(self, starttime, *event):
		"""Add a timer event to queue will start (and wake) in 'starttime' seconds
		"""
		# in testing we should wait (looping) for the possible time drifts:
		if MyTime.myTime is not None and starttime:
			# test time after short sleep:
			t = threading.Timer(Utils.DEFAULT_SLEEP_INTERVAL, self._delayedEvent,
				(MyTime.time() + starttime, time.time() + starttime, event)
			)
			t.start()
			return
		# add timer event:
		t = threading.Timer(starttime, self.add, event)
		t.start()

	def _delayedEvent(self, endMyTime, endTime, event):
		if MyTime.time() >= endMyTime or time.time() >= endTime:
			self.add_timer(0, *event)
			return
		# repeat after short sleep:
		t = threading.Timer(Utils.DEFAULT_SLEEP_INTERVAL, self._delayedEvent,
			(endMyTime, endTime, event)
		)
		t.start()

	def pulse_notify(self):
		"""Notify wakeup (sets /and resets/ notify event)
		"""
		if not self._paused:
			n = self._notify
			if n:
				n.set()
				#n.clear()

	def add(self, *event):
		"""Add an event to queue and notify thread to wake up.

		Returns the :class:`_QEvent` (which can be awaited) for ticket-bound
		events, `True` for control events, or `None` if a ticket event was
		rejected because the entrance is closed or the queue is full.
		Producers never block here.
		"""
		name = event[0] if event and isinstance(event[0], str) else None
		spec = self._TICKET_EVENTS.get(name)
		if spec is None:
			## lock and add new control event to queue:
			with self._queue_lock:
				self._queue.append(event)
			self.pulse_notify()
			return True
		return self._add_ticket_event(spec, event)

	def add_wn(self, *event):
		"""Add a event to queue without notifying thread to wake up.
		"""
		## lock and add new event to queue:
		with self._queue_lock:
			self._queue.append(event)

	def call_lambda(self, l, *args):
		l(*args)

	## -----------------------------------------
	## Bounded coalescing event queue ...
	## -----------------------------------------

	def _count_merge(self):
		self._merged += 1

	def _count_drop(self, reason, warn=True):
		# call with self._queue_lock held:
		self._dropped += 1
		self._dropped_reasons[reason] = self._dropped_reasons.get(reason, 0) + 1
		if warn:
			now = time.time()
			if now - self._last_drop_log >= 1:
				self._last_drop_log = now
				logSys.warning(
					"Observer event discarded (%s): queue=%s/%s merged=%s dropped=%s",
					reason, len(self._tickets), self._queue_limit,
					self._merged, self._dropped)

	def _add_ticket_event(self, spec, event):
		name = event[0]
		kind, op = spec
		result = None
		notify = False
		with self._queue_lock:
			## entrance closed (shutdown/drain) - reject immediately (R7):
			if self._closing:
				self._count_drop('closed')
				return None
			if kind == 'B':
				if op == 'add':
					ticket, jail = event[1], event[2]
					key = ('B', jail.name, str(ticket.getID()))
				else:
					jail, ip = event[1], event[2]
					key = ('B', jail.name, str(ip))
				ev = self._tickets.get(key)
				if ev is not None:
					result = self._merge_ban(ev, op, event, key)
					notify = True
			elif kind == 'F':
				jail, ticket = event[1], event[2]
				ip = str(ticket.getID())
				# Below capacity every failure event stays distinct (their
				# accumulation changes the retry count); only once the queue
				# is full do we coalesce same-ticket failures that are still
				# queued, or reject if there is nothing to merge with:
				if len(self._tickets) >= self._queue_limit:
					for sk, e in self._tickets.items():
						if sk[0] == 'F' and sk[1] == jail.name and sk[2] == ip:
							# only latest state of that pending failure matters:
							e[2] = ticket
							self._count_merge()
							result = e
							notify = True
							break
					if result is None:
						self._count_drop('full')
						return None
				if result is None:
					self._serial += 1
					key = ('F', jail.name, ip, self._serial)
					ev = _QEvent(key, kind, op, list(event))
					self._tickets[key] = ev
					self._queue.append(ev)
					result = ev
					notify = True
			else: # flush
				jail = event[1]
				# flush is the last state for the whole jail - all pending
				# ban/unban events before it collapse into it:
				for k, e in list(self._tickets.items()):
					if k[0] != 'B' or k[1] != jail.name:
						continue
					self._count_merge()
					if e is self._inflight:
						# can't remove an in-flight entry - turn it into the
						# desired removal (the flush event behind it does the rest):
						if e.op == 'add':
							ip = k[2]
							e[:] = ['banRemoved', jail, ip]
							e.op = 'remove'
					else:
						e.cancelled = True
						e.done.set()
						del self._tickets[k]
				key = ('flush', jail.name, '')
				ev = self._tickets.get(key)
				if ev is not None:
					ev[1] = jail
					self._count_merge()
					result = ev
					notify = True
			## capacity bound - no same ticket to coalesce with.
			## a whole-jail flush bypasses the bound: it is the final state
			## itself and frees the slots it collapses:
			if result is None and kind != 'flush' \
				and len(self._tickets) >= self._queue_limit:
				self._count_drop('full')
				return None
			if result is None:
				ev = _QEvent(key, kind, op, list(event))
				self._tickets[key] = ev
				self._queue.append(ev)
				result = ev
				notify = True
		if notify:
			self.pulse_notify()
			self._retry_wake.set()
		return result

	def _merge_ban(self, ev, op, event, key):
		"""Coalesce a new ban/unban event into the pending one (call with lock).

		Last state of the same ticket wins. If a ban has never been written
		yet, ban followed by unban collapses to no operation at all, so no
		intermediate state ever reaches the database.
		"""
		if op == 'add':
			ticket, jail = event[1], event[2]
			ev[:] = ['banFound', ticket, jail, event[3]]
			ev.op = 'add'
			# add over a removal not yet written is a new desired state:
			if ev.applied != 'add':
				ev.prepared = False
				ev.prepared_for = None
		else:
			jail, ip = event[1], event[2]
			if ev.op == 'add' and ev.applied is None and ev is not self._inflight:
				# ban still pending and never written - unban cancels it:
				ev.cancelled = True
				ev[:] = ['banRemoved', jail, ip]
				ev.op = 'remove'
				ev.done.set()
				del self._tickets[key]
				self._count_merge()
				return ev
			ev[:] = ['banRemoved', jail, ip]
			ev.op = 'remove'
		self._count_merge()
		return ev

	def _qsize(self):
		with self._queue_lock:
			return len(self._queue) + (1 if self._inflight is not None else 0)

	def _pop_next(self):
		"""Pop next dispatchable event, marking ticket entry as in-flight."""
		with self._queue_lock:
			if self._inflight is not None:
				return None
			while self._queue:
				ev = self._queue.popleft()
				if isinstance(ev, _QEvent):
					if ev.cancelled:
						# tombstone - drop, do not touch index (key may be reused):
						continue
					if ev.kind == 'F':
						# failures stay distinct and are not a merge target
						# while being processed:
						self._tickets.pop(ev.key, None)
					self._inflight = ev
				return ev
		return None

	def _finish(self, ev, dropreason=None):
		"""Settle an in-flight ticket entry (written, skipped or given up)."""
		with self._queue_lock:
			self._inflight = None
			if self._tickets.get(ev.key) is ev:
				del self._tickets[ev.key]
			if dropreason is not None:
				self._count_drop(dropreason)
		ev.done.set()
		self.pulse_notify()
		self._retry_wake.set()

	def run(self):
		"""Main loop for Threading.

		This function is the main loop of the thread.

		Returns
		-------
		bool
			True when the thread exits nicely.
		"""
		logSys.info("Observer start...")
		## first time create named timer to purge database each hour (clean old entries) ...
		self.add_named_timer('DB_PURGE', self.__db_purge_interval, 'db_purge')
		## Mapping of all possible event types of observer:
		__meth = {
			# universal lambda:
			'call': self.call_lambda,
			# system and service events:
			'db_set': self.db_set,
			'db_purge': self.db_purge,
			# service events of observer self:
			'is_alive' : self.isAlive,
			'is_active': self.isActive,
			'start': self.start,
			'stop': self.stop,
			'nop': lambda:(),
			'shutdown': lambda:()
		}
		try:
			## check it self with sending is_alive event
			self.add('is_alive')
			## if we should stop - break a main loop
			while self.active:
				self.idle = False
				## check events available and execute all events from queue
				while not self._paused:
					ev = self._inflight or self._pop_next()
					if ev is None:
						break
					try:
						if isinstance(ev, _QEvent):
							## ticket event (bounded, coalesced, retried write):
							self._process_ticket(ev)
						else:
							## retrieve method by name
							meth = ev[0]
							if not callable(ev[0]): meth = __meth.get(meth) or getattr(self, meth)
							## execute it with rest of event as variable arguments
							meth(*ev[1:])
					except Exception as e:
						#logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
						logSys.error('%s', e, exc_info=True)
				## going sleep, wait for events (in queue)
				n = self._notify
				if n:
					self.idle = True
					n.wait(self.sleeptime)
					## wake up - reset signal now (we don't need it so long as we reed from queue)
					n.clear()
					if self._paused:
						continue
				else:
					## notify event deleted (shutdown) - just sleep a little bit (waiting for shutdown events, prevent high cpu usage)
					time.sleep(ObserverThread.DEFAULT_SLEEP_INTERVAL)
					## stop by shutdown and empty queue :
					if not self.is_full:
						break
				## end of main loop - exit
			logSys.info("Observer stopped, %s events remaining.", self._qsize())
			self._notify = None
			#print("Observer stopped, %s events remaining." % len(self._queue))
		except Exception as e:
			logSys.error('Observer stopped after error: %s', e, exc_info=True)
			#print("Observer stopped with error: %s" % str(e))
		# account ticket events never persisted (normally already done in stop):
		self._discard_remaining('thread-end')
		# clear all events - exit, for possible calls of wait_empty:
		with self._queue_lock:
			self._queue.clear()
			self._tickets.clear()
			self._inflight = None
		self.idle = True
		return True

	def isAlive(self):
		#logSys.debug("Observer alive...")
		return True

	def isActive(self, fromStr=None):
		# logSys.info("Observer alive, %s%s", 
		# 	'active' if self.active else 'inactive', 
		# 	'' if fromStr is None else (", called from '%s'" % fromStr))
		return self.active

	def start(self):
		with self._queue_lock:
			if not self.active:
				super(ObserverThread, self).start()

	def stop(self, wtime=5, forceQuit=True):
		# already stopped (or not started):
		if not (self.active and self._notify):
			return True
		logSys.info("Observer stop ... try to end queue %s seconds", wtime)
		with self._queue_lock:
			# 1) close entrance first - producers get rejected immediately:
			self._closing = True
			# the drain deadline is set once and never extended: the final
			# force phase must not grant extra retry time after the first
			# drain phase already exceeded the waiting cap (an expired
			# deadline stays expired):
			if not self._stop_deadline:
				self._stop_deadline = MyTime.time() + wtime
			# just add shutdown job to make possible wait later until full (events remaining)
			self.add_wn('shutdown')
			#don't pulse - just set, because we will delete it hereafter (sometimes not wakeup)
			n = self._notify
			self._notify.set()
			#self.pulse_notify()
			self._notify = None
		self._retry_wake.set()
		# 2) wait max wtime seconds until queue is drained (events persisted):
		drained = self.wait_empty(wtime)
		if drained or forceQuit:
			n.clear()
			self.active = False; # leave outer (active) loop
			self._paused = True; # leave inner (queue) loop
			self._retry_wake.set()
			# let an in-flight write notice the deactivation:
			self.wait_idle(min(wtime, 0.5))
			# 3) anything still not persisted must be logged and counted -
			# never discard pending ticket events silently:
			self._discard_remaining('shutdown')
			self.__db = None
			return self.wait_idle(min(wtime, 0.5)) and not self.is_full
		else:
			self._notify = n
			return self.wait_idle(min(wtime, 0.5)) and not self.is_full

	@property
	def is_full(self):
		return self._qsize() != 0

	def wait_empty(self, sleeptime=None):
		"""Wait observer is running and returns if observer has no more events (queue is empty)
		"""
		time.sleep(ObserverThread.DEFAULT_SLEEP_INTERVAL)
		if sleeptime is not None:
			e = MyTime.time() + sleeptime
		# block queue with not operation to be sure all really jobs are executed if nop goes from queue :
		if self._notify is not None:
			self.add_wn('nop')
			if self.is_full and self.idle:
				self.pulse_notify()
		while self.is_full:
			if sleeptime is not None and MyTime.time() > e:
				break
			time.sleep(ObserverThread.DEFAULT_SLEEP_INTERVAL)
		# wait idle to be sure the last queue element is processed (because pop event before processing it) :
		self.wait_idle(0.001)
		return not self.is_full


	def wait_idle(self, sleeptime=None):
		"""Wait observer is running and returns if observer idle (observer sleeps)
		"""
		time.sleep(ObserverThread.DEFAULT_SLEEP_INTERVAL)
		if self.idle:
			return True
		if sleeptime is not None:
			e = MyTime.time() + sleeptime
		while not self.idle:
			if sleeptime is not None and MyTime.time() > e:
				break
			time.sleep(ObserverThread.DEFAULT_SLEEP_INTERVAL)
		return self.idle

	@property
	def paused(self):
		return self._paused;

	@paused.setter
	def paused(self, pause):
		if self._paused == pause:
			return
		self._paused = pause
		# wake after pause ended
		self.pulse_notify()


	@property
	def status(self):
		"""Status of the persistence queue: size, capacity, coalesced and
		discarded event counts and current write retry attempt.

		Counters are in-memory only and reset on restart.
		"""
		with self._queue_lock:
			retrying = self._inflight.attempts if self._inflight is not None else 0
			return ("Persistence", [
				"queue=%d" % len(self._tickets),
				"capacity=%d" % self._queue_limit,
				"merged=%d" % self._merged,
				"dropped=%d" % self._dropped,
				"retrying=%d" % retrying,
			])

	def _discard_remaining(self, where):
		"""Log/count all still pending ticket events and clear the queue.

		Already committed database records are not touched (no rollback), the
		database file stays readable.
		"""
		with self._queue_lock:
			items = list(self._tickets.values())
			if self._inflight is not None and self._inflight not in items:
				items.append(self._inflight)
			self._tickets.clear()
			self._inflight = None
			self._queue.clear()
		if not items:
			return
		ids = []
		for ev in items:
			ids.append(ev.ident)
			self._dropped += 1
			self._dropped_reasons[where] = self._dropped_reasons.get(where, 0) + 1
			ev.done.set()
		shown = ids[:100]
		logSys.error(
			"Observer %s: %s ticket event(s) not persisted and discarded "
			"(merged=%s, dropped=%s), ticket ids: %s%s",
			where, len(ids), self._merged, self._dropped,
			", ".join(shown), "" if len(ids) <= 100 else ", ...")

	## -----------------------------------------
	## [Async] database write with retry/backoff ...
	## -----------------------------------------

	def _retry_delay(self, attempts):
		"""Exponential backoff delay (bounded) for the given attempt."""
		delay = self._retry_interval * (2 ** (attempts - 1))
		return min(self._retry_max_interval, delay)

	def _wait_retry(self, ev):
		"""Wait the backoff delay; returns False if deactivated/shutdown deadline."""
		delay = self._retry_delay(ev.attempts)
		end = MyTime.time() + delay
		if self._stop_deadline:
			# don't sleep past the shutdown drain deadline:
			end = min(end, self._stop_deadline)
		while self.active and not self._paused:
			now = MyTime.time()
			if self._closing and self._stop_deadline and now >= self._stop_deadline:
				return False
			if now >= end:
				return True
			self._retry_wake.wait(max(0.001, min(0.5, end - now)))
			self._retry_wake.clear()
		return False

	def _process_ticket(self, ev):
		"""Process one ticket entry, with bounded backoff retry of writes.

		The entry is kept (and re-tried) until the final desired state is
		written or retries are exhausted. Events of other tickets stay
		queued, so the original event order is never changed.
		"""
		while self.active and not self._paused:
			# if shutdown drain deadline elapsed, don't start further attempts
			# (stop() will account the still pending entry):
			if ev.attempts and self._closing and self._stop_deadline \
				and MyTime.time() >= self._stop_deadline:
				return
			try:
				outcome = self._ticket_step(ev)
			except Exception as e:
				# not a database write error - retry wouldn't help, log and
				# discard the event as before:
				logSys.error('Observer: processing %s failed: %s', ev.ident, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				self._finish(ev, 'failed')
				return
			if outcome == 'settled':
				self._finish(ev)
				return
			if outcome == 'again':
				# desired state flipped while writing (ban/unban) - apply it:
				continue
			## write failed - retain the ticket and retry with backoff:
			ev.attempts += 1
			if ev.attempts > self._retry_max_attempts:
				logSys.error(
					"Observer: give up persisting %s after %d failed write attempt(s): %s",
					ev.ident, ev.attempts - 1, getattr(ev, 'last_error', ''))
				self._finish(ev, 'writefailed')
				return
			delay = self._retry_delay(ev.attempts)
			logSys.warning(
				"Observer: database write for %s failed (%s), retry %d/%d in %.2fs",
				ev.ident, ev.last_error, ev.attempts,
				self._retry_max_attempts, delay)
			if not self._wait_retry(ev):
				# shutdown/deactivated while backing off; entry stays pending,
				# stop() logs and counts it:
				return

	def _ticket_step(self, ev):
		"""Execute one attempt; returns 'settled', 'again' or 'retry'."""
		kind = ev.kind
		if kind == 'F':
			# read-only check (may trigger a new ban) - no write to retry:
			self.failureFound(ev[1], ev[2])
			return 'settled'
		if kind == 'flush':
			jail = ev[1]
			try:
				if jail.database is not None:
					jail.database.delBan(jail)
			except Exception as e:
				ev.last_error = e
				return 'retry'
			ev.applied = 'flush'
			return 'settled'
		# kind == 'B':
		if ev.op == 'add':
			# note: goes through self.banFound so it stays the single
			# interception point (monkeypatched in tests, too):
			outcome = self.banFound(ev[1], ev[2], ev[3], ev)
			# None (e. g. an interception wrapper) means the write is done:
			return outcome if outcome in ('retry', 'again') else 'settled'
		# remove
		jail, ip = ev[1], ev[2]
		try:
			if jail.database is not None:
				jail.database.delBan(jail, ip)
		except Exception as e:
			ev.last_error = e
			return 'retry'
		ev.applied = 'remove'
		# state flipped while writing (e. g. re-ban merged during the delete):
		return 'settled' if ev.applied == ev.op else 'again'

	## -----------------------------------------
	## [Async] database service functionality ...
	## -----------------------------------------

	def db_set(self, db):
		self.__db = db

	def db_purge(self):
		logSys.debug("Purge database event occurred")
		if self.__db is not None:
			self.__db.purge()
		# trigger timer again ...
		self.add_named_timer('DB_PURGE', self.__db_purge_interval, 'db_purge')

	## -----------------------------------------
	## [Async] ban time increment functionality ...
	## -----------------------------------------

	def failureFound(self, jail, ticket):
		""" Notify observer a failure for ip was found

		Observer will check ip was known (bad) and possibly increase an retry count
		"""
		# check jail active :
		if not jail.isAlive() or not jail.getBanTimeExtra("increment"):
			return
		ip = ticket.getID()
		unixTime = ticket.getTime()
		logSys.debug("[%s] Observer: failure found %s", jail.name, ip)
		# increase retry count for known (bad) ip, corresponding banCount of it (one try will count than 2, 3, 5, 9 ...)  :
		banCount = 0
		retryCount = 1
		timeOfBan = None
		try:
			maxRetry = jail.filter.failManager.getMaxRetry()
			db = jail.database
			if db is not None:
				for banCount, timeOfBan, lastBanTime in db.getBan(ip, jail):
					banCount = max(banCount, ticket.getBanCount())
					retryCount = ((1 << (banCount if banCount < 20 else 20))/2 + 1)
					# if lastBanTime == -1 or timeOfBan + lastBanTime * 2 > MyTime.time():
					# 	retryCount = maxRetry
					break
				retryCount = min(retryCount, maxRetry)
				# check this ticket already known (line was already processed and in the database and will be restored from there):
				if timeOfBan is not None and unixTime <= timeOfBan:
					logSys.debug("[%s] Ignore failure %s before last ban %s < %s, restored",
								jail.name, ip, unixTime, timeOfBan)
					return
			# for not increased failures observer should not add it to fail manager, because was already added by filter self
			if retryCount <= 1:
				return
			# retry counter was increased - add it again:
			logSys.info("[%s] Found %s, bad - %s, %s # -> %s%s", jail.name, ip, 
				MyTime.time2str(unixTime), banCount, retryCount,
				(', Ban' if retryCount >= maxRetry else ''))
			# retryCount-1, because a ticket was already once incremented by filter self
			retryCount = jail.filter.failManager.addFailure(ticket, retryCount - 1, True)
			ticket.setBanCount(banCount)
			# after observe we have increased attempt count, compare it >= maxretry ...
			if retryCount >= maxRetry:
				# perform the banning of the ip now (again)
				jail.filter.performBan(ip)

		except Exception as e:
			logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)


	class BanTimeIncr:
		def __init__(self, banTime, banCount):
			self.Time = banTime
			self.Count = banCount

	def calcBanTime(self, jail, banTime, banCount):
		be = jail.getBanTimeExtra()
		return be['evformula'](self.BanTimeIncr(banTime, banCount))

	def incrBanTime(self, jail, banTime, ticket):
		"""Check for IP address to increment ban time (if was already banned).

		Returns
		-------
		float
			new ban time.
		"""
		# check jail active :
		if not jail.isAlive() or not jail.database:
			return banTime
		be = jail.getBanTimeExtra()
		ip = ticket.getID()
		orgBanTime = banTime
		# check ip was already banned (increment time of ban):
		try:
			if banTime > 0 and be.get('increment', False):
				# search IP in database and increase time if found:
				for banCount, timeOfBan, lastBanTime in \
					jail.database.getBan(ip, jail, overalljails=be.get('overalljails', False)) \
				:
					# increment count in ticket (if still not increased from banmanager, test-cases?):
					if banCount >= ticket.getBanCount():
						ticket.setBanCount(banCount+1)
					logSys.debug('IP %s was already banned: %s #, %s', ip, banCount, timeOfBan);
					# calculate new ban time
					if banCount > 0:
						banTime = be['evformula'](self.BanTimeIncr(banTime, banCount))
					ticket.setBanTime(banTime)
					# check current ticket time to prevent increasing for twice read tickets (restored from log file besides database after restart)
					if ticket.getTime() > timeOfBan:
						logSys.info('[%s] IP %s is bad: %s # last %s - incr %s to %s' % (jail.name, ip, banCount, 
							MyTime.time2str(timeOfBan), 
							MyTime.seconds2str(orgBanTime), MyTime.seconds2str(banTime)))
					else:
						ticket.restored = True
					break
		except Exception as e:
			logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		return banTime

	def _prepareBanFound(self, ticket, jail, btime):
		"""Ban-time increase / prolong / old-ban handling for a new ban.

		Returns False if the ban is too old and must not be written to the
		database, True otherwise. Mutates the ticket ban time as needed.
		"""
		if ticket.restored: # pragma: no cover (normally not resored tickets only)
			return False
		oldbtime = btime
		ip = ticket.getID()
		logSys.debug("[%s] Observer: ban found %s, %s", jail.name, ip, btime)
		# if not permanent and ban time was not set - check time should be increased:
		if btime != -1 and ticket.getBanTime() is None:
			btime = self.incrBanTime(jail, btime, ticket)
			# if we should prolong ban time:
			if btime == -1 or btime > oldbtime:
				ticket.setBanTime(btime)
		# if not permanent
		if btime != -1:
			bendtime = ticket.getTime() + btime
			# check ban is not too old :
			if bendtime < MyTime.time():
				logSys.debug('Ignore old bantime %s', bendtime)
				return False
		# if ban time was prolonged - log again with new ban time:
		if btime != oldbtime:
			logSys.notice("[%s] Increase Ban %s (%d # %s -> %s)", jail.name, 
				ip, ticket.getBanCount(),
				MyTime.seconds2str(btime), MyTime.time2str(ticket.getTime() + btime))
			# delayed prolonging ticket via actions that expected this (not later than 10 sec):
			logSys.log(5, "[%s] Observer: prolong %s in %s", jail.name, ip, (btime, oldbtime))
			self.add_timer(min(10, max(0, btime - oldbtime - 5)), self.prolongBan, ticket, jail)
		return True

	def banFound(self, ticket, jail, btime, _ev=None):
		"""Notify observer a ban occurred for ip.

		Two call modes share this single entry point:

		* queued ticket events call it with their `_ev` state entry; the
		  ban-time increase is prepared once per ticket payload and the write
		  is retried (idempotently) by the queue worker, returning
		  ``'settled'``, ``'again'`` or ``'retry'``;
		* direct invocations (legacy/API, `_ev` is None) keep the former
		  one-shot behavior: prepare and write immediately, never raise.
		"""
		if _ev is None:
			if ticket.restored: # pragma: no cover (normally not resored tickets only)
				return
			try:
				if self._prepareBanFound(ticket, jail, btime) is False:
					return False
				if jail.database is not None and not ticket.restored:
					jail.database.addBan(jail, ticket)
			except Exception as e:
				logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			return
		ev = _ev
		# ban-time increase/prolong calculated once per ticket payload:
		if not ev.prepared or ev.prepared_for is not ticket:
			if self._prepareBanFound(ticket, jail, btime) is False:
				ev.applied = 'skip'
				return 'settled' # too old ban - nothing to write
			ev.prepared = True
			ev.prepared_for = ticket
		try:
			if jail.database is not None and not ticket.restored:
				# retries of an uncertain previous attempt are idempotent:
				jail.database.addBan(jail, ticket, ev.attempts > 0)
		except Exception as e:
			ev.last_error = e
			return 'retry'
		ev.applied = 'add'
		# state flipped while writing (e. g. unban merged during the write):
		return 'settled' if ev.applied == ev.op else 'again'

	def prolongBan(self, ticket, jail):
		""" Notify observer a ban occurred for ip

		Observer will check ip was known (bad) and possibly increase/prolong a ban time
		Secondary we will actualize the bans and bips (bad ip) in database
		"""
		try:
			btime = ticket.getBanTime()
			ip = ticket.getID()
			logSys.debug("[%s] Observer: prolong %s, %s", jail.name, ip, btime)
			# prolong ticket via actions that expected this:
			jail.actions._prolongBan(ticket)
		except Exception as e:
			logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

# Global observer initial created in server (could be later rewritten via singleton)
class _Observers:
	def __init__(self):
		self.Main = None

Observers = _Observers()
