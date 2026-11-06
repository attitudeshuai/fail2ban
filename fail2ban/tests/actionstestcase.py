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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Author: Daniel Black
# 

__author__ = "Daniel Black"
__copyright__ = "Copyright (c) 2013 Daniel Black"
__license__ = "GPL"

import time
import os
import subprocess
import tempfile
import threading

from ..server.ticket import FailTicket
from ..server.utils import Utils, CommandCancelHandle
from ..server.action import ActionCommandCancelled
from .dummyjail import DummyJail
from .utils import LogCaptureTestCase, with_alt_time, with_tmpdir, MyTime

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


class ExecuteActions(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(ExecuteActions, self).setUp()
		self.__jail = DummyJail()
		self.__actions = self.__jail.actions

	def tearDown(self):
		super(ExecuteActions, self).tearDown()

	def defaultAction(self, o={}):
		self.__actions.add('ip')
		act = self.__actions['ip']
		act.actionstart = 'echo ip start'+o.get('start', '')
		act.actionban = 'echo ip ban <ip>'+o.get('ban', '')
		act.actionunban = 'echo ip unban <ip>'+o.get('unban', '')
		act.actioncheck = 'echo ip check'+o.get('check', '')
		act.actionflush = 'echo ip flush'+o.get('flush', '')
		act.actionstop = 'echo ip stop'+o.get('stop', '')
		return act

	def testActionsAddDuplicateName(self):
		self.__actions.add('test')
		self.assertRaises(ValueError, self.__actions.add, 'test')

	def testActionsManipulation(self):
		self.__actions.add('test')
		self.assertTrue(self.__actions['test'])
		self.assertIn('test', self.__actions)
		self.assertNotIn('nonexistent action', self.__actions)
		self.__actions.add('test1')
		del self.__actions['test']
		del self.__actions['test1']
		self.assertNotIn('test', self.__actions)
		self.assertEqual(len(self.__actions), 0)

		self.__actions.setBanTime(127)
		self.assertEqual(self.__actions.getBanTime(),127)
		self.assertRaises(ValueError, self.__actions.removeBannedIP, '127.0.0.1')

	def testAddBannedIP(self):
		self.assertEqual(self.__actions.addBannedIP('192.0.2.1'), 1)
		self.assertLogged('Ban 192.0.2.1')
		self.pruneLog()
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '192.0.2.2', '192.0.2.3']), 2)
		self.assertLogged('192.0.2.1 already banned')
		self.assertNotLogged('Ban 192.0.2.1')
		self.assertLogged('Ban 192.0.2.2')
		self.assertLogged('Ban 192.0.2.3')

	def testActionsOutput(self):
		self.defaultAction()
		self.__actions.start()
		self.assertLogged("stdout: %r" % 'ip start', wait=True)
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged("stdout: %r" % 'ip flush', "stdout: %r" % 'ip stop')
		self.assertEqual(self.__actions.status(),[("Currently banned", 0 ),
               ("Total banned", 0 ), ("Banned IP list", [] )])
		self.assertEqual(self.__actions.status('short'),[("Currently banned", 0 ),
               ("Total banned", 0 )])

	def testAddActionPython(self):
		self.__actions.add(
			"Action", os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value'})

		self.assertLogged("TestAction initialised")

		self.__actions.start()
		self.assertTrue( Utils.wait_for(lambda: self._is_logged("TestAction action start"), 3) )

		self.__actions.stop()
		self.__actions.join()
		self.assertLogged("TestAction action stop")

		self.assertRaises(IOError,
			self.__actions.add, "Action3", "/does/not/exist.py", {})

		# With optional argument
		self.__actions.add(
			"Action4", os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value', 'opt2': 'value2'})
		# With too many arguments
		self.assertRaises(
			TypeError, self.__actions.add, "Action5",
			os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value', 'opt2': 'value2', 'opt3': 'value3'})
		# Missing required argument
		self.assertRaises(
			TypeError, self.__actions.add, "Action5",
			os.path.join(TEST_FILES_DIR, "action.d/action.py"), {})

	def testAddPythonActionNOK(self):
		self.assertRaises(RuntimeError, self.__actions.add,
			"Action", os.path.join(TEST_FILES_DIR,
				"action.d/action_noAction.py"),
			{})
		self.assertRaises(RuntimeError, self.__actions.add,
			"Action", os.path.join(TEST_FILES_DIR,
				"action.d/action_nomethod.py"),
			{})
		self.__actions.add(
			"Action", os.path.join(TEST_FILES_DIR,
				"action.d/action_errors.py"),
			{})
		self.__actions.start()
		self.assertTrue( Utils.wait_for(lambda: self._is_logged("Failed to start"), 3) )
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged("Failed to stop")

	def testBanActionsAInfo(self):
		# Action which deletes IP address from aInfo
		self.__actions.add(
			"action1",
			os.path.join(TEST_FILES_DIR, "action.d/action_modifyainfo.py"),
			{})
		self.__actions.add(
			"action2",
			os.path.join(TEST_FILES_DIR, "action.d/action_modifyainfo.py"),
			{})
		self.__jail.putFailTicket(FailTicket("1.2.3.4"))
		self.__actions._Actions__checkBan()
		# Will fail if modification of aInfo from first action propagates
		# to second action, as both delete same key
		self.assertNotLogged("Failed to execute ban")
		self.assertLogged("action1 ban deleted aInfo IP")
		self.assertLogged("action2 ban deleted aInfo IP")

		self.__actions._Actions__flushBan()
		# Will fail if modification of aInfo from first action propagates
		# to second action, as both delete same key
		self.assertNotLogged("Failed to execute unban")
		self.assertLogged("action1 unban deleted aInfo IP")
		self.assertLogged("action2 unban deleted aInfo IP")

	@with_alt_time
	def testUnbanOnBusyBanBombing(self):
		# check unban happens in-between of "ban bombing" despite lower precedence,
		# if it is not work, we'll not see "Unbanned 30" (rather "Unbanned 50")
		# because then all the unbans occur earliest at flushing (after stop)

		# each 3rd ban we should see an unban check (and up to 5 tickets gets unbanned):
		self.__actions.banPrecedence = 3
		self.__actions.unbanMaxCount = 5
		self.__actions.setBanTime(100)

		self.__actions.start()

		MyTime.setTime(0); # avoid "expired bantime" (in 0.11)
		i = 0
		while i < 20:
			ip = "192.0.2.%d" % i
			self.__jail.putFailTicket(FailTicket(ip, 0))
			i += 1

		# wait for last ban (all 20 tickets gets banned):
		self.assertLogged(' / 20,', wait=True)

		MyTime.setTime(200); # unban time for 20 tickets reached

		while i < 50:
			ip = "192.0.2.%d" % i
			self.__jail.putFailTicket(FailTicket(ip, 200))
			i += 1

		# wait for last ban (all 50 tickets gets banned):
		self.assertLogged(' / 50,', wait=True)
		self.__actions.stop()
		self.__actions.join()

		self.assertLogged('Unbanned 30, 0 ticket(s)')
		self.assertNotLogged('Unbanned 50, 0 ticket(s)')

	def testActionsConsistencyCheck(self):
		act = self.defaultAction({'check':' <family>', 'flush':' <family>'})
		# flush for inet6 is intentionally "broken" here - test no unhandled except and invariant check:
		act['actionflush?family=inet6'] = act.actionflush + '; exit 1'
		act.actionstart_on_demand = True
		# force errors via check in ban/unban:
		act.actionban = "<actioncheck> ; " + act.actionban
		act.actionunban = "<actioncheck> ; " + act.actionunban
		self.__actions.start()
		self.assertNotLogged("stdout: %r" % 'ip start')

		self.assertEqual(self.__actions.addBannedIP('192.0.2.1'), 1)
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 192.0.2.1', 'Ban 2001:db8::1',
			"stdout: %r" % 'ip start',
			"stdout: %r" % 'ip ban 192.0.2.1',
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)

		# check should fail (so cause stop/start):
		self.pruneLog('[test-phase 1a] simulate inconsistent irreparable env by unban')
		act['actioncheck?family=inet6'] = act.actioncheck + '; exit 1'
		self.__actions.removeBannedIP('2001:db8::1')
		self.assertLogged('Invariant check failed. Unban is impossible.',
			wait=True)
		self.pruneLog('[test-phase 1b] simulate inconsistent irreparable env by flush')
		self.__actions._Actions__flushBan()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip flush inet6',
			'Failed to flush bans',
			'No flush occurred, do consistency check',
			'Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop',  # same for both families
			'Failed to flush bans',
			all=True, wait=True)

		# check succeeds:
		self.pruneLog('[test-phase 2] consistent env')
		act['actioncheck?family=inet6'] = act.actioncheck
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 2001:db8::1',
			"stdout: %r" % 'ip start',   # same for both families
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)
		self.assertNotLogged("stdout: %r" % 'ip check inet4',
			all=True)

		self.pruneLog('[test-phase 3] failed flush in consistent env')
		self.__actions._Actions__flushBan()
		self.assertLogged('Failed to flush bans',
			'No flush occurred, do consistency check',
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip check inet6',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip stop',
			"stdout: %r" % 'ip start',
			'Unable to restore environment',
			all=True)

		# stop, flush succeeds:
		self.pruneLog('[test-phase end] flush successful')
		act['actionflush?family=inet6'] = act.actionflush
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip stop',    # same for both families
			'action ip terminated',
			all=True, wait=True)
		# no flush for inet4 (already successfully flushed):
		self.assertNotLogged("ERROR",
			"stdout: %r" % 'ip flush inet4',
			'Unban tickets each individually',
			all=True)

	def testActionsConsistencyCheckDiffFam(self):
		# same as testActionsConsistencyCheck, but different start/stop commands for both families and repair on unban
		act = self.defaultAction({'start':' <family>', 'check':' <family>', 'flush':' <family>', 'stop':' <family>'})
		# flush for inet6 is intentionally "broken" here - test no unhandled except and invariant check:
		act['actionflush?family=inet6'] = act.actionflush + '; exit 1'
		act.actionstart_on_demand = True
		act.actionrepair_on_unban = True
		# force errors via check in ban/unban:
		act.actionban = "<actioncheck> ; " + act.actionban
		act.actionunban = "<actioncheck> ; " + act.actionunban
		self.__actions.start()
		self.assertNotLogged("stdout: %r" % 'ip start')

		self.assertEqual(self.__actions.addBannedIP('192.0.2.1'), 1)
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 192.0.2.1', 'Ban 2001:db8::1',
			"stdout: %r" % 'ip start inet4',
			"stdout: %r" % 'ip ban 192.0.2.1',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)

		# check should fail (so cause stop/start):
		act['actioncheck?family=inet6'] = act.actioncheck + '; exit 1'
		self.pruneLog('[test-phase 1a] simulate inconsistent irreparable env by unban')
		self.__actions.removeBannedIP('2001:db8::1')
		self.assertLogged('Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop inet6',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip start inet6', # start on demand (not on repair)
			"stdout: %r" % 'ip stop inet4',  # family inet4 is not affected
			"stdout: %r" % 'ip start inet4',
			all=True)

		self.pruneLog('[test-phase 1b] simulate inconsistent irreparable env by ban')
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop inet6',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip check inet6',
			'Unable to restore environment',
			'Failed to execute ban',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip stop inet4',  # family inet4 is not affected
			"stdout: %r" % 'ip start inet4',
			all=True)

		act['actioncheck?family=inet6'] = act.actioncheck
		self.assertEqual(self.__actions.addBannedIP('2001:db8::2'), 1)
		act['actioncheck?family=inet6'] = act.actioncheck + '; exit 1'
		self.pruneLog('[test-phase 1c] simulate inconsistent irreparable env by flush')
		self.__actions._Actions__flushBan()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip flush inet6',
			'Failed to flush bans',
			'No flush occurred, do consistency check',
			'Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop inet6',
			'Failed to flush bans in jail',
			all=True, wait=True)
		# start/stop should be called for inet6 only:
		self.assertNotLogged(
			"stdout: %r" % 'ip stop inet4',
			all=True)

		# check succeeds:
		self.pruneLog('[test-phase 2] consistent env')
		act['actioncheck?family=inet6'] = act.actioncheck
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 2001:db8::1',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip check inet4',
			"stdout: %r" % 'ip start inet4',
			all=True)

		self.pruneLog('[test-phase 3] failed flush in consistent env')
		act['actioncheck?family=inet6'] = act.actioncheck
		self.__actions._Actions__flushBan()
		self.assertLogged('Failed to flush bans',
			'No flush occurred, do consistency check',
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip check inet6',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip stop inet4',
			"stdout: %r" % 'ip start inet4',
			"stdout: %r" % 'ip stop inet6',
			"stdout: %r" % 'ip start inet6',
			all=True)

		# stop, flush succeeds:
		self.pruneLog('[test-phase end] flush successful')
		act['actionflush?family=inet6'] = act.actionflush
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip stop inet4',
			"stdout: %r" % 'ip stop inet6',
			'action ip terminated',
			all=True, wait=True)
		# no flush for inet4 (already successfully flushed):
		self.assertNotLogged("ERROR",
			"stdout: %r" % 'ip flush inet4',
			'Unban tickets each individually',
			all=True)

	@with_alt_time
	@with_tmpdir
	def testActionsRebanBrokenAfterRepair(self, tmp):
		act = self.defaultAction({
			'start':' <family>; touch "<FN>"',
			'check':' <family>; test -f "<FN>"',
			'flush':' <family>; echo -n "" > "<FN>"',
			'stop': ' <family>; rm -f "<FN>"',
			'ban':  ' <family>; echo "<ip> <family>" >> "<FN>"',
		})
		act['FN'] = tmp+'/<family>'
		act.actionstart_on_demand = True
		act.actionrepair = 'echo ip repair <family>; touch "<FN>"'
		act.actionreban = 'echo ip reban <ip> <family>; echo "<ip> <family> -- rebanned" >> "<FN>"'
		self.pruneLog('[test-phase 0] initial ban')
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '2001:db8::1']), 2)
		self.assertLogged('Ban 192.0.2.1', 'Ban 2001:db8::1',
			"stdout: %r" % 'ip start inet4',
			"stdout: %r" % 'ip ban 192.0.2.1 inet4',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip ban 2001:db8::1 inet6',
			all=True)

		self.pruneLog('[test-phase 1] check ban')
		self.dumpFile(tmp+'/inet4')
		self.assertLogged('192.0.2.1 inet4')
		self.assertNotLogged('2001:db8::1 inet6')
		self.pruneLog()
		self.dumpFile(tmp+'/inet6')
		self.assertLogged('2001:db8::1 inet6')
		self.assertNotLogged('192.0.2.1 inet4')

		# simulate 3 seconds past:
		MyTime.setTime(MyTime.time() + 4)
		# already banned produces events:
		self.pruneLog('[test-phase 2] check already banned')
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '2001:db8::1', '2001:db8::2']), 1)
		self.assertLogged(
			'192.0.2.1 already banned', '2001:db8::1 already banned', 'Ban 2001:db8::2',
			"stdout: %r" % 'ip check inet4', # both checks occurred
			"stdout: %r" % 'ip check inet6',
			all=True)
		self.dumpFile(tmp+'/inet4')
		self.dumpFile(tmp+'/inet6')
		# no reban should occur:
		self.assertNotLogged('Reban 192.0.2.1', 'Reban 2001:db8::1',
			"stdout: %r" % 'ip ban 192.0.2.1 inet4',
			"stdout: %r" % 'ip reban 192.0.2.1 inet4',
			"stdout: %r" % 'ip ban 2001:db8::1 inet6',
			"stdout: %r" % 'ip reban 2001:db8::1 inet6',
			'192.0.2.1 inet4 -- repaired',
			'2001:db8::1 inet6 -- repaired',
			all=True)

		# simulate 3 seconds past:
		MyTime.setTime(MyTime.time() + 4)
		# break env (remove both files, so check would fail):
		os.remove(tmp+'/inet4')
		os.remove(tmp+'/inet6')
		# test again already banned (it shall cause reban now):
		self.pruneLog('[test-phase 3a] check reban after sane env repaired')
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '2001:db8::1']), 2)
		self.assertLogged(
			"Invariant check failed. Trying to restore a sane environment",
			"stdout: %r" % 'ip repair inet4', # both repairs occurred
			"stdout: %r" % 'ip repair inet6',
			"Reban 192.0.2.1, action 'ip'", "Reban 2001:db8::1, action 'ip'", # both rebans also
			"stdout: %r" % 'ip reban 192.0.2.1 inet4',
			"stdout: %r" % 'ip reban 2001:db8::1 inet6',
			all=True)

		# now last IP (2001:db8::2) - no repair, but still old epoch of ticket, so it gets rebanned:
		self.pruneLog('[test-phase 3a] check reban by epoch mismatch (without repair)')
		self.assertEqual(self.__actions.addBannedIP('2001:db8::2'), 1)
		self.assertLogged(
			"Reban 2001:db8::2, action 'ip'",
			"stdout: %r" % 'ip reban 2001:db8::2 inet6',
			all=True)
		self.assertNotLogged(
			"Invariant check failed. Trying to restore a sane environment",
			"stdout: %r" % 'ip repair inet4', # both repairs occurred
			"stdout: %r" % 'ip repair inet6',
			"Reban 192.0.2.1, action 'ip'", "Reban 2001:db8::1, action 'ip'", # both rebans also
			"stdout: %r" % 'ip reban 192.0.2.1 inet4',
			"stdout: %r" % 'ip reban 2001:db8::1 inet6',
			all=True)

		# and bans present in files:
		self.pruneLog('[test-phase 4] check reban')
		self.dumpFile(tmp+'/inet4')
		self.assertLogged('192.0.2.1 inet4 -- rebanned')
		self.assertNotLogged('2001:db8::1 inet6 -- rebanned')
		self.pruneLog()
		self.dumpFile(tmp+'/inet6')
		self.assertLogged(
			'2001:db8::1 inet6 -- rebanned', 
			'2001:db8::2 inet6 -- rebanned', all=True)
		self.assertNotLogged('192.0.2.1 inet4 -- rebanned')

		# coverage - intended error in reban (no unhandled exception, message logged):
		act.actionreban = ''
		act.actionban = 'exit 1'
		self.assertEqual(self.__actions._Actions__reBan(FailTicket("192.0.2.1", 0)), 0)
		self.assertLogged(
			'Failed to execute reban',
			'Error banning 192.0.2.1', all=True)


class ActionCancellationTest(LogCaptureTestCase):
	"""Tests for cancellation of in-progress action commands on stop/reload.
	"""

	def setUp(self):
		super(ActionCancellationTest, self).setUp()
		self.__jails = []
		self.__tmpfiles = []

	def tearDown(self):
		for jail in self.__jails:
			try:
				actions = jail.actions
				if actions.is_alive():
					actions.stop()
					actions.join()
			except Exception:
				pass
		for fn in self.__tmpfiles:
			try:
				os.unlink(fn)
			except OSError:
				pass
		super(ActionCancellationTest, self).tearDown()

	def _newJail(self, name, actionban, timeout=30, db=None):
		jail = DummyJail(name)
		if db is not None:
			jail._Jail__db = db
		actions = jail.actions
		actions.add('a')
		action = actions['a']
		action.timeout = timeout
		action.actionstart = ''
		action.actionban = actionban
		action.actionunban = ''
		action.actionflush = ''
		action.actionstop = ''
		action.actionreload = ''
		actions.sleeptime = 1
		self.__jails.append(jail)
		return jail, actions, action

	def _treeScript(self, marker, duration=30, trap_term=False):
		"""A shell script which records its pid and its sleep child pid
		and then waits for the child, so the whole tree is observable.
		"""
		fn = tempfile.mktemp('.sh', 'f2b_cancel_')
		with open(fn, 'w') as f:
			f.write('#!/bin/sh\n')
			if trap_term:
				# ignore the gentle SIGTERM - forces the SIGKILL escalation:
				f.write("trap '' TERM\n")
			f.write('echo $$ > "%s"\n' % marker)
			f.write('sleep %d & c=$!\n' % duration)
			f.write('echo $c >> "%s"\n' % marker)
			f.write('wait $c\n')
		self.__tmpfiles.append(fn)
		return fn

	@staticmethod
	def _procState(pid):
		try:
			out = subprocess.run(
				['ps', '-o', 'state=', '-p', str(pid)],
				stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			return out.stdout.decode().strip()
		except Exception:
			return None

	def _assertTreeDead(self, pids):
		# every pid must be gone (no running children and no zombies,
		# the direct child is explicitly reaped by executeCmd):
		dead = Utils.wait_for(
			lambda: all(self._procState(p) == '' for p in pids), 3)
		self.assertTrue(dead,
			"residual process tree: %r" %
			[(p, self._procState(p)) for p in pids])

	def _waitActive(self, actions, timeout=5):
		self.assertTrue(Utils.wait_for(
			lambda: bool(actions.activeCommands()), timeout),
			"no command became active")

	def _readPids(self, marker):
		def _pids():
			try:
				with open(marker) as f:
					pids = [int(l) for l in f.read().split()]
				if len(pids) == 2:
					return pids
			except (IOError, ValueError):
				pass
			return None
		pids = Utils.wait_for(_pids, 5)
		self.assertTrue(pids, "pid marker %r not written" % marker)
		return pids

	# Scenario 1: stop ends a long command early and leaves no residual tree
	def testStopCancelsLongCommandAndProcessTree(self):
		marker = tempfile.mktemp('.pid', 'f2b_cancel_')
		self.__tmpfiles.append(marker)
		script = self._treeScript(marker)
		jail, actions, action = self._newJail('stop', 'sh "%s"' % script)
		actions.start()
		jail.putFailTicket(FailTicket('192.0.2.1'))
		self._waitActive(actions)
		pids = self._readPids(marker)
		stime = time.time()
		actions.stop()
		actions.join()
		elapsed = time.time() - stime
		# stopped promptly (not the 30s timeout) but with room for the
		# two-level termination budget:
		self.assertLess(elapsed, 5, "stop took %.2fs" % elapsed)
		self._assertTreeDead(pids)
		# ticket is back to unfinished, not shown banned, not counted:
		self.assertEqual(actions.status()[0], ("Currently banned", 0))
		self.assertEqual(actions.status()[1], ("Total banned", 0))
		canceled, failed = actions.getCancelStats()
		self.assertEqual(canceled, 1)
		self.assertEqual(failed, 0)
		self.assertLogged('canceled', 'ticket back to unfinished', all=True)
		self.assertNotLogged('timed out')

	# Two-level termination: a SIGTERM-ignoring tree gets SIGKILL
	def testCancellationEscalatesToSigKill(self):
		marker = tempfile.mktemp('.pid', 'f2b_cancel_')
		self.__tmpfiles.append(marker)
		script = self._treeScript(marker, trap_term=True)
		jail, actions, action = self._newJail('kill', 'sh "%s"' % script)
		actions.start()
		jail.putFailTicket(FailTicket('192.0.2.2'))
		self._waitActive(actions)
		pids = self._readPids(marker)
		stime = time.time()
		actions.stop()
		actions.join()
		elapsed = time.time() - stime
		# the gentle termination budget was awaited, then force applied:
		self.assertGreater(elapsed, 0.15)
		self.assertLess(elapsed, 5)
		self._assertTreeDead(pids)
		self.assertLogged('killed with SIGKILL')
		self.assertEqual(actions.getCancelStats(), (1, 0))

	# Cancelled ban leaves no persistent record
	def testCancelledBanNotPersisted(self):
		from ..server.database import Fail2BanDb
		dbf = tempfile.mktemp('.db', 'f2b_cancel_')
		self.__tmpfiles.append(dbf)
		db = Fail2BanDb(dbf)
		try:
			marker = tempfile.mktemp('.pid', 'f2b_cancel_')
			self.__tmpfiles.append(marker)
			script = self._treeScript(marker)
			jail, actions, action = self._newJail('persist',
				'sh "%s"' % script, db=db)
			db.addJail(jail)
			actions.start()
			jail.putFailTicket(FailTicket('192.0.2.3'))
			self._waitActive(actions)
			ticket = list(iter(actions.banManager))[0]
			# simulate the observer having persisted the ban already:
			db.addBan(jail, ticket)
			actions.stop()
			actions.join()
			self.assertEqual(
				list(db.getCurrentBans(jail)), [],
				"canceled ban must not remain persisted")
		finally:
			db.close()

	# Repeated cancellation is idempotent
	def testCancelIsIdempotent(self):
		marker = tempfile.mktemp('.pid', 'f2b_cancel_')
		self.__tmpfiles.append(marker)
		script = self._treeScript(marker)
		jail, actions, action = self._newJail('idem', 'sh "%s"' % script)
		actions.start()
		jail.putFailTicket(FailTicket('192.0.2.4'))
		self._waitActive(actions)
		pids = self._readPids(marker)
		# cancel repeatedly from multiple threads, including after stop:
		def spam():
			for i in range(5):
				action.cancel()
				time.sleep(0.005)
		threads = [threading.Thread(target=spam) for i in range(3)]
		for t in threads: t.start()
		stime = time.time()
		actions.stop()
		for t in threads: t.join()
		actions.join()
		self.assertLess(time.time() - stime, 5)
		self._assertTreeDead(pids)
		# one cancellation accounted, no failures:
		self.assertEqual(actions.getCancelStats(), (1, 0))
		self.assertNotLogged('cancellation failed', 'Failed to cancel')
		# stopping twice must not raise:
		actions.stop()

	# Scenario 2: reload cancels only the affected action
	def testReloadCancelsOnlyAffectedAction(self):
		# reloaded jail - long command gets cancelled:
		rmarker = tempfile.mktemp('.pid', 'f2b_cancel_r_')
		self.__tmpfiles.append(rmarker)
		rscript = self._treeScript(rmarker)
		rjail, ractions, raction = self._newJail(
			'reloaded', 'sh "%s"' % rscript)
		# untouched jail - short command runs to normal completion:
		kjail, kactions, kaction = self._newJail('kept', 'sleep 0.5')
		ractions.start()
		kactions.start()
		rjail.putFailTicket(FailTicket('192.0.2.10'))
		kjail.putFailTicket(FailTicket('192.0.2.11'))
		# the reloaded jail must actually run its command (hold the command
		# lock) before it is cancelled - wait for its process tree to exist:
		rpids = self._readPids(rmarker)
		# reload only the 'reloaded' jail:
		ractions.idle = True
		ractions.reload(begin=True)
		ractions.add('a', reload=True)
		ractions._waitActionsSettle([('a', raction)])
		raction.actionban = 'echo NEW <ip>'
		ractions.reload(begin=False)
		rjail.queue = []
		ractions.idle = False
		self._assertTreeDead(rpids)
		# the untouched action completed normally without being cancelled:
		self.assertTrue(Utils.wait_for(
			lambda: '192.0.2.11' in kactions.getBanList(), 5))
		self.assertEqual(kactions.getCancelStats(), (0, 0))
		self.assertEqual(kaction._cancelCount, 0)
		# reloaded jail: ticket rolled back, old command cancelled:
		self.assertEqual(ractions.getBanList(), [])
		self.assertEqual(ractions.getCancelStats(), (1, 0))

	# Scenario 2b: on reload, unprocessed tickets of the interrupted batch
	# are requeued and all settled again with the new parameters
	def testReloadRequeuesRemainingBatchTickets(self):
		marker = tempfile.mktemp('.pid', 'f2b_cancel_b_')
		self.__tmpfiles.append(marker)
		script = self._treeScript(marker)
		jail, actions, action = self._newJail('batch', 'sh "%s"' % script)
		ips = ['192.0.2.%d' % i for i in (91, 92, 93)]
		actions.start()
		for ip in ips:
			jail.putFailTicket(FailTicket(ip))
		# the first ticket of the batch is in the long command:
		pids = self._readPids(marker)
		actions.idle = True
		actions.reload(begin=True)
		actions.add('a', reload=True)
		actions._waitActionsSettle([('a', action)])
		action.actionban = 'echo BATCH-NEW <ip>'
		actions.reload(begin=False)
		actions.idle = False
		self._assertTreeDead(pids)
		# all three tickets settled once with the new command:
		for ip in ips:
			self.assertLogged('BATCH-NEW %s' % ip, wait=True)
		self.assertEqual(sorted(actions.getBanList()), sorted(ips))
		self.assertEqual(actions.getCancelStats(), (1, 0))
		actions.stop()
		actions.join()

	# Scenario 3: cancel and completion simultaneously
	def testCancelWithSuccessfulCompletionSettlesOnce(self):
		# a command succeeding before the cancel is observed is success,
		# never terminated:
		handle = CommandCancelHandle()
		def late_cancel():
			time.sleep(0.02)
			handle.cancel()
		threading.Thread(target=late_cancel).start()
		self.assertTrue(Utils.executeCmd('true', 5, cancel_event=handle))
		self.assertFalse(handle.engaged)

		# repeated race - each command executes exactly once, outcomes are
		# either one success or one cancellation, never a double execution:
		jail, actions, action = self._newJail('race', None)
		marker = tempfile.mktemp('.cnt', 'f2b_cancel_')
		self.__tmpfiles.append(marker)
		n = 12
		success = cancelled = 0
		for i in range(n):
			action.actionban = 'echo m%d >> "%s"; sleep 0.03' % (i, marker)
			timer = threading.Timer(
				0.01 + (i % 5) * 0.012, action.cancel)
			timer.start()
			try:
				self.assertTrue(
					action._processCmd('<actionban>', {'ip': '192.0.2.20'}))
				success += 1
			except ActionCommandCancelled:
				cancelled += 1
			finally:
				timer.join()
		self.assertEqual(success + cancelled, n)
		# every spawned command ran at most once (no retry/duplication);
		# a cancel arriving before spawn simply never executes the command,
		# which is also a single settlement:
		with open(marker) as f:
			lines = [l for l in f.read().splitlines() if l.strip()]
		self.assertEqual(len(lines), len(set(lines)))
		self.assertTrue(set(lines) <= {'m%d' % i for i in range(n)})
		self.assertLessEqual(len(lines), n)
		self.assertEqual(actions.getCancelStats()[0], cancelled)
		self.assertEqual(actions.getCancelStats()[1], 0)

	# Timeout is handled separately from cancellation
	def testTimeoutNotCountedAsCancellation(self):
		jail, actions, action = self._newJail('tout', None)
		action.timeout = 0.2
		stime = time.time()
		self.assertFalse(action._execCmd('sleep 5'))
		self.assertLess(time.time() - stime, 3)
		canceled, failed = actions.getCancelStats()
		self.assertEqual((canceled, failed), (0, 0))
		self.assertLogged('timed out after 0.2')
		self.assertNotLogged('canceled')

	# Scenario 4: many commands cancelled concurrently
	def testConcurrentCancellationMultipleCommands(self):
		threads = []
		handles = []
		results = []
		allpids = []
		lock = threading.Lock()
		n = 5
		scripts = []
		for i in range(n):
			marker = tempfile.mktemp('.pid', 'f2b_cancel_m%d_' % i)
			self.__tmpfiles.append(marker)
			scripts.append((self._treeScript(marker), marker))
		def worker(i):
			script, marker = scripts[i]
			handle = CommandCancelHandle()
			with lock:
				handles.append(handle)
			r = Utils.executeCmd('sh "%s"' % script, 30,
				cancel_event=handle)
			with lock:
				results.append(r)
		for i in range(n):
			t = threading.Thread(target=worker, args=(i,))
			threads.append(t)
			t.start()
		# wait for every command tree to be fully spawned:
		for i, (script, marker) in enumerate(scripts):
			pids = self._readPids(marker)
			allpids.extend(pids)
		self.assertTrue(Utils.wait_for(
			lambda: len(handles) == n and
				all(h.pid is not None for h in handles), 5))
		stime = time.time()
		# cancel all at once - none must block or fail the others:
		for h in handles:
			h.cancel()
		for t in threads:
			t.join(5)
		elapsed = time.time() - stime
		self.assertLess(elapsed, 5)
		self.assertEqual(len(results), n)
		self.assertFalse(any(results))
		self.assertTrue(all(h.engaged and h.retcode is not None for h in handles))
		self._assertTreeDead(allpids)

	# one action failing to cancel does not block the others
	def testCancelActionFailureDoesNotBlockOthers(self):
		jail, actions, action = self._newJail('cf', 'sleep 30')

		class BadAction(object):
			def cancel(self):
				raise RuntimeError("boom at cancel")

		actions._actions['bad'] = BadAction()
		try:
			# must not raise and must continue with the other action:
			self.assertEqual(actions.cancelActions(actions._actions), 0)
			canceled, failed = actions.getCancelStats()
			# a failed cancellation is still accounted as a cancellation:
			self.assertEqual(canceled, 1)
			self.assertEqual(failed, 1)
			self.assertLogged("Failed to cancel jail 'cf' action 'bad'",
				"'signal'")
		finally:
			del actions._actions['bad']

	# cancellation status flavor
	def testCancellationsStatus(self):
		marker = tempfile.mktemp('.pid', 'f2b_cancel_')
		self.__tmpfiles.append(marker)
		script = self._treeScript(marker)
		jail, actions, action = self._newJail('st', 'sh "%s"' % script)
		self.assertEqual(actions.status('cancellations'),
			[("Currently executing", []),
			 ("Total cancelled", 0),
			 ("Total cancel failures", 0)])
		actions.start()
		jail.putFailTicket(FailTicket('192.0.2.30'))
		self._waitActive(actions)
		running = actions.status('cancellations')[0][1]
		self.assertEqual(len(running), 1)
		self.assertIn('a: sh "%s"' % script, running)
		actions.stop()
		actions.join()
		self.assertEqual(actions.status('cancellations')[1],
			("Total cancelled", 1))
