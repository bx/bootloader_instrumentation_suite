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
import sys
import os
import signal
import intervaltree
import gdb_tools
import substage
import db_info


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr
do_halt = False
allowed_writes = {}
now = True
check_inline = now


class CloseSubstageDB():
    def __init__(self, db):
        self.db
        global now
        if now:
            self.do()

    def do(self):
        self.db.close_dbs()

    def __call__(self):
        global now
        if not now:
            self.do()


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
        if not len(a.search(self.start, self.end)) == 1:
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


class Enforce(gdb_tools.GDBPlugin):

    def __init__(self):
        bp_hooks = {'WriteBreak': self.write_stophook,
                    'LongWriteBreak': self.longwrite_stophook,
                    'SubstageEntryBreak': self.substage_stophook}
        parser_options = [
            gdb_tools.GDBPluginParser("do_halt"),
            gdb_tools.GDBPluginParser("check_inline")]

        gdb_tools.GDBPlugin.__init__(self, "enforce",
                                     f_hook=self.finalize_hook,
                                     bp_hooks=bp_hooks,
                                     calculate_write_dst=True,
                                     parser_args=parser_options)

    def check_inline(self, args):
        global check_inline
        check_inline = True

    def do_halt(self, args):
        global do_halt
        do_halt = True

    def finalize_hook(self, args):
        substages = False
        for s in self.controller._stages.itervalues():
            if s.substages:
                substages = True
                break
        if not substages:
            self.controller.gdb_print('No substages to set, do not know what to enforce',
                                      self.name)
            return
        global allowed_writes
        for s in [_s for _s in self.controller._stages.itervalues()
                  if _s.stage in self.controller.stage_order]:
            name = s.stage.stagename
            # policy = self.controller.policy_file
            ss = self.controller._stages[name].substages_entrypoints
            i = db_info.get(s.stage)
            allowed_writes[name] = {}

            for n in range(0, len(ss)):
                allowed_writes[name][n] = i.allowed_substage_writes(n)

    def write_stophook(self, bp, ret):
        return self.longwrite_stophook(bp, ret)

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


plugin_config = Enforce()
