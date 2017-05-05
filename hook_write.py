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

import os
import sys
path = gdb.os.getcwd()
sys.path.append(path)
# sys.path.append(os.path.join(path, ".."))
version = os.path.join(path, ".python-version")
if os.path.exists(version):
    with open(version, 'r') as pv:
        penv = pv.read().strip()
        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
from config import Main
import staticanalysis
import database
import pure_utils
import gdb_tools
import intervaltree
from gdb_tools import *
import db_info

stepnum = 0


class WriteLog():
    def __init__(self, msg):
        self.message = msg

    def __call__(self):
        gdb.write(self.message, gdb.STDLOG)


db_written = False
now = True

start = time.time()


class FlushDatabase():
    def __init__(self, stage, for_now=False):
        self.stage = stage
        global now
        if now or for_now:
            self.do()

    def do(self):
        global db_written
        if db_written:
            return
        db_info.get(self.stage).flush_tracedb()

        # print "consolidating write intervals\n"
        # start = time.time()
        global start
        # db_info.get(self.stage).consoladate_trace_write_table()
        db_info.get(self.stage).flush_tracedb()
        stop = time.time()
        print ".. finished in %f minutes\n" % ((stop-start)/60)
        db_written = True

    def __call__(self):
        global now
        if not now:
            self.do()


class WriteDatabase():
    def __init__(self, time, pid, size, dest, pc, lr, cpsr, step, origpc, stage, substage):
        self.time = time
        self.pid = pid
        self.size = size
        self.dest = dest
        self.pc = pc
        self.lr = lr
        self.cpsr = cpsr
        self.step = step
        self.origpc = origpc
        self.num = substage
        self.stage = stage
        global now
        if now:
            self.do()

    def do(self):
        db_info.get(self.stage).add_trace_write_entry(self.time, self.pid,
                                                      self.size, self.dest,
                                                      self.pc, self.lr,
                                                      self.cpsr, self.step)
        db_info.get(self.stage).update_trace_writes('', self.pc, self.dest, self.dest + self.size,
                                                    self.stage,
                                                    self.origpc, self.num)

    def __call__(self):
        global now
        if not now:
            self.do()


class HookWrite(gdb_tools.GDBBootController):
    def __init__(self):
        bp_hooks = {'WriteBreak': self.write_stophook,
                    'LongwriteBreak': self.longwrite_stophook,
                    'StageEndBreak': self.endstop_hook}
        gdb_tools.GDBBootController.__init__(self, "hookwrite", bp_hooks,
                                             stage_hook=self._go_stage,
                                             f_hook=self.f_hook,
                                             create_trace=True, open_dbs_ro=False,
                                             exit_hook=self._exit_hook)
        self.ranges = intervaltree.IntervalTree()
        self.isbaremetal = False
        self.create_trace_table = True
        self.calculate_write_dst = True
        self.open_dbs_ro = False
        self._setup_parsers()

    def f_hook(self, args):
        for s in self.stage_order:
            db_info.create(s, "tracedb")

    def write_stophook(self, bp, ret):
        global stepnum
        stepnum = stepnum + 1
        bp.controller.process_write(bp.writeinfo,
                                    bp.relocated,
                                    bp.stage,
                                    bp.controller.current_substage)
        return False

    def longwrite_stophook(self, bp, ret):
        global stepnum
        # calculate first and last write addresses
        start = bp.writeinfo['start']
        end = bp.writeinfo['end']
        writepc = bp.writeinfo['pc']
        controller = bp.controller
        num = controller.current_substage

        lr = bp.controller.get_reg_value('lr')
        cpsr = bp.controller.get_reg_value('cpsr')
        pid = 2
        if bp.relocated > 0:
            pid = 3
        for i in range(start, end, bp.writesize):
            waddr = i
            if bp.inplace:
                waddr = start
            bp.controller.writeinfo(waddr, bp.writesize, writepc,
                                    lr, cpsr, pid, writepc - bp.relocated,
                                    bp.stage, num)
        return False

    def stage_finish(self, now=False):
        #print "posting stage finish event %s" % self.current_stage
        fd = FlushDatabase(self.current_stage)
        gdb.flush()
        if now:
            fd()
        else:
            gdb.post_event(fd)

    def _exit_hook(self, event):
        self.stage_finish(True)

    def endstop_hook(self, bp, ret):
        controller = bp.controller
        controller.stage_finish()
        # controller.tracedb.close()
        # controller.analysisdb.close()
        # disable bp in case it is hit agan
        # otherwise we will have problems
        # with tables since the are now closed
        return True

    def _setup_parsers(self):
        self.add_subcommand_parser("flushall")
        self.add_subcommand_parser("baremetal")
        sp = self.add_subcommand_parser("stage")
        sp.add_argument("stagename")

    def _go_stage(self, stage):
        #print "go stage"
        pass

    def baremetal(self, args):
        self.isbaremetal = True

    def flushall(self, args):
        gdb.post_event(FlushDatabase(self.current_stage, now=True))

    def process_write(self, writeinfo, relocated, stage, substage):
        pc = writeinfo['pc']
        inspc = pc - relocated
        cpsr = writeinfo["cpsr"]
        lr = self.get_reg_value('lr')
        thumb = writeinfo['thumb']
        i = writeinfo['i']
        ins = writeinfo['ins']
        size = writeinfo['end'] - writeinfo['start']
        dst = writeinfo['start']
        pid = 0
        if relocated > 0:
            pid = 1
        self.writeinfo(dst, size, pc, lr, cpsr, pid, pc - relocated, stage, substage)

    def writeinfo(self, writedst, size, pc, lr, cpsr, pid, origpc, stage, substage):
        global stepnum
        stepnum += 1
        #self.gdb_print("%s, " % substage)
        gdb.post_event(WriteDatabase(time.time(),
                                     pid, size, writedst, pc, lr,
                                     cpsr, stepnum, origpc, stage, substage))

    # def stop (self):
    #     self.hw.process_write(self.relocated)
    #     return False


hookwrite = HookWrite()
# gdb.events.cont.connect(hookwrite.handle_continue)
# gdb.events.stop.connect(hookwrite.handle_stop)
# signal.signal(signal.SIGINT, hookwrite.handle_stop)
