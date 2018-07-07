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

now = True
start = time.time()


class Flush():
    def __init__(self):
        global now
        if now:
            self.do()

    def do(self):
        gdb.flush()
        global start
        stop = time.time()
        gdb.write("watchpoint trace finished in %f minutes\n" % ((stop-start)/60), gdb.STDOUT)

    def __call__(self):
        global now
        if not now:
            self.do()


class Watchpoints(gdb_tools.GDBPlugin):
    def __init__(self):
        bp_hooks = {'StageEndBreak': self.endstop_hook}
        parser_options = [
            gdb_tools.GDBPluginParser("stage", ["stagename"])
        ]
        disabled = ["LongwriteBreak", "WriteBreak"]
        gdb_tools.GDBPlugin.__init__(self, "watchpoints", bp_hooks,
                                     f_hook=self.f_hook,
                                     calculate_write_dst=False,
                                     exit_hook=self._exit_hook,
                                     disabled_breakpoints=disabled,
                                     parser_args=parser_options)

    def f_hook(self, args):
        pass

    def endstop_hook(self, bp, ret):
        return True

    def stage_finish(self, now=False):
        flush = Flush()
        if now:
            flush()
        else:
            gdb.post_event(flush)

    def _exit_hook(self, event):
        self.stage_finish(True)


plugin_config = Watchpoints()
