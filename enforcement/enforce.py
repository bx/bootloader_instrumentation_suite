# MIT License

# Copyright (c) 2017 Rebecca ".bx" Shapiro

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import gdb
import time
import argparse
import sys
import os
import signal
path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(path, ".."))
sys.path.append(path)
version = os.path.join(path, ".python-version")
if os.path.exists(version):
    with open(version, 'r') as pv:
        penv = pv.read().strip()
        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
import intervaltree
from config import Main
import gdb_tools
import substage
import pytable_utils
import db_info


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr
do_halt = False
allowed_writes = {}
check_inline = False


class CloseSubstageDB():
    def __init__(self, db):
        self.db

    def __call__(self):
        self.db.close_dbs()


class CheckWrite():
    def __init__(self, stage, name, substagenum, pc,
                 relocated, startdest, enddest):
        self.name = name
        self.stage = stage
        self.pc = pc
        self.num = substagenum
        self.start = startdest
        self.end = enddest
        self.relocated = relocated
        global do_halt
        global check_inline
        if check_inline or do_halt:
            self.do()

    def do(self):
        global allowed_writes
        a = allowed_writes[self.stage.stagename][self.num]
        i = intervaltree.Interval(self.start, self.end)
        if not a.search(i):
            gdb.write("#CAUGHT INVALID WRITE pc %x (%x-%x) substage %s (%s)\n" % (self.pc,
                                                                                  self.start,
                                                                                  self.end,
                                                                                  self.name,
                                                                                  self.num),
                      gdb.STDOUT)
            global do_halt
            if do_halt:
                pid = gdb.selected_inferior().pid
                os.kill(pid, signal.SIGINT)

    def __call__(self):
        global check_inline
        global do_halt
        if not (check_inline or do_halt):
            self.do()


class Enforce(gdb_tools.GDBBootController):

    def __init__(self):
        bp_hooks = {'WriteBreak': self.write_stophook,
                    'LongWriteBreak': self.longwrite_stophook,
                    'SubstageEntryBreak': self.substage_stophook}

        gdb_tools.GDBBootController.__init__(self, "enforce",
                                             f_hook=self.finalize_hook,
                                             bp_hooks=bp_hooks,
                                             stage_hook=self.setup_stage)
        self._setup_parsers()
        self.writesearch = None
        self.calculate_write_dst = True
        self.current_substage = 0
        self._setup_parsers()

    def _setup_parsers(self):
        self.add_subcommand_parser("do_halt")
        self.add_subcommand_parser("check_inline")

    def check_inline(self, args):
        global check_inline
        check_inline = True

    def do_halt(self, args):
        global do_halt
        do_halt = True

    def finalize_hook(self, args):
        substages = False
        for s in self._stages.itervalues():
            if s.substages:
                substages = True
                break
        if not substages:
            self.gdb_print('No substages to set, do not know what to enforce')
            return
        global allowed_writes
        for s in [_s for _s in self._stages.itervalues() if _s.stage in self.stage_order]:
            name = s.stage.stagename
            st = self._stages[name]
            policy = Main.get_config("policy_file", s)
            ss = substage.substages_entrypoints(policy)
            i = db_info.policydb(st)
            allowed_writes[name] = {}

            for n in range(0, len(ss)):
                allowed_writes[name][n] = i.allowed_writes(n)

    def write_stophook(self, bp, ret):
        return self.longwrite_stophook(bp, ret)

    def open_substage_policy(self, bp):
        return False

    def substage_stophook(self, bp, ret):

        bp.msg("started substage %s (%s)\n" % (bp.substagenum,
                                               bp.fnname))
        if not bp.controller.current_substage >= (bp.substagenum - 1):
            bp.msg("Uh oh! Entrypoint for substage number "
                   "%s (%s) triggered at wrong time\n" % (bp.substagenum,
                                                          bp.fnname))
            return True
        return False

    def longwrite_stophook(self, bp, ret):
        substagenum = bp.controller.current_substage
        gdb.post_event(CheckWrite(bp.stage,
                                  bp.controller.current_substage_name,
                                  substagenum,
                                  bp.writeinfo['pc'],
                                  bp.relocated,
                                  bp.writeinfo['start'],
                                  bp.writeinfo['end']))
        return ret

    def setup_stage(self, stage):
        pass


e = Enforce()
