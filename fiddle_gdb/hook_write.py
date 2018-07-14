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
import gdb_tools
from gdb_tools import *
import db_info

stepnum = 0
now = False
db_written = False
start = time.time()

class WriteLog():
    def __init__(self, msg):
        self.message = msg
        global now
        if now:
            self.do()

    def do(self):
        gdb.write(self.message, gdb.STDLOG)

    def __call__(self):
        global now
        if not now:
            self.do()


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
        global start
        gdb.flush()
        db_info.get(self.stage).flush_tracedb()
        stop = time.time()
        gdb.write(".. finished in %f minutes\n" % ((stop-start)/60), gdb.STDOUT)
        db_written = True

    def __call__(self):
        global now
        if not now:
            self.do()


class WriteDatabase():
    def __init__(self, time, pid, size, dest, pc, lr, cpsr, step,
                 origpc, stage, substage, substage_name,doit=False):
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
        self.substage_name = substage_name
        self.stage = stage
        global now
        if now or doit:
            self.do()

    def do(self):
        db_info.get(self.stage).add_trace_write_entry(self.time, self.pid,
                                                      self.size, self.dest,
                                                      self.pc, self.lr,
                                                      self.cpsr, self.step,
                                                      self.num)
        if self.size < 0:
            end = self.dest
            start = self.dest + self.size
        else:
            start = self.dest
            end = self.dest + self.size
        db_info.get(self.stage).update_trace_writes('', self.pc, start, end,
                                                    self.stage,
                                                    self.origpc, self.num)

    def __call__(self):
        global now
        if not now:
            self.do()


class HookWrite(gdb_tools.GDBPlugin):
    def __init__(self):
        bp_hooks = {'WriteBreak': self.write_stophook,
                    'LongwriteBreak': self.longwrite_stophook,
                    'StageEndBreak': self.endstop_hook}
        parser_options = [
            gdb_tools.GDBPluginParser("flushall"),
            gdb_tools.GDBPluginParser("stage", ["stagename"])
        ]
        gdb_tools.GDBPlugin.__init__(self, "hookwrite", bp_hooks,
                                     f_hook=self.f_hook,
                                     calculate_write_dst=True,
                                     exit_hook=self._exit_hook,
                                     parser_args=parser_options)

    def f_hook(self, args):
        for s in self.controller.stage_order:
            db_info.create(s, "tracedb")

    def write_stophook(self, bp, ret):
        global stepnum
        stepnum = stepnum + 1
        self.process_write(bp.writeinfo,
                           bp.relocated,
                           bp.stage,
                           bp.controller.current_substage,
                           bp.controller.current_substage_name)
        return False

    def longwrite_stophook(self, bp, ret):
        # plugin = bp.controller.get_plugin(self.name)
        global stepnum
        # calculate first and last write addresses
        start = bp.writeinfo['start']
        end = bp.writeinfo['end']
        writepc = bp.writeinfo['pc']
        controller = bp.controller
        num = controller.current_substage
        name = controller.current_substage_name
        lr = bp.controller.get_reg_value('lr')
        cpsr = bp.controller.get_reg_value('cpsr')
        pid = 2
        # gdb.post_event(WriteLog("\n<%x longwrite..." % writepc))
        if bp.relocated > 0:
            pid = 3
        for i in range(start, end, bp.writesize):
            waddr = i
            if bp.inplace:
                waddr = start

            self.dowriteinfo(waddr, bp.writesize, writepc,
                             lr, cpsr, pid, writepc - bp.relocated,
                             bp.stage, num, name)
        # gdb.post_event(WriteLog(">\n"))
        return False

    def stage_finish(self, now=False):
        fd = FlushDatabase(self.controller.current_stage)
        gdb.flush()
        if now:
            fd()
        else:
            gdb.post_event(fd)

    def _exit_hook(self, event):
        self.stage_finish(True)

    def endstop_hook(self, bp, ret):
        self.stage_finish()
        return True

    def flushall(self, args):
        gdb.post_event(FlushDatabase(self.controller.current_stage, now=True))

    def process_write(self, writeinfo, relocated, stage, substage, name):
        pc = writeinfo['pc']
        cpsr = writeinfo["cpsr"]
        lr = self.controller.get_reg_value('lr')
        size = writeinfo['end'] - writeinfo['start']
        dst = writeinfo['start']
        pid = 0
        if relocated > 0:
            pid = 1
        self.dowriteinfo(dst, size, pc, lr, cpsr, pid, pc - relocated,
                         stage, substage, name)

    def dowriteinfo(self, writedst, size, pc, lr, cpsr, pid, origpc, stage, substage, name):
        global stepnum
        stepnum += 1
        gdb.post_event(WriteDatabase(time.time(),
                                     pid, size, writedst, pc, lr,
                                     cpsr, stepnum, origpc, stage, substage,
                                     name))


plugin_config = HookWrite()
