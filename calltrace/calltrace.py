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
import os
import re
path = gdb.os.getcwd()
sys.path.append(path)
version = os.path.join(path, ".python-version")
if os.path.exists(version):
    with open(version, 'r') as pv:
        penv = pv.read().strip()
        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
from config import Main
import testsuite_utils as utils
import config
import gdb_tools

open_log = None

class CloseLog():
    def __init__(self):
        pass

    def __call__(self):
        global open_log
        if open_log is not None:
            open_log.close()
            open_log = None


class WriteResults():
    def __init__(self, depth, name, kind, pc, line, minimal=False):
        self.line = line
        self.depth = depth
        self.name = name
        self.kind = kind
        self.pc = pc
        self.entry = True if kind == "entry" else False
        self.minimal = minimal
        #self.do()

    def do(self):
        global open_log
        if self.entry:
            c = " > "
        else:
            c = " < "
        outstr = ("*" * (self.depth + 1)) + c + self.name
        if (not self.entry) and (not self.minimal):
            outstr += "@0x%x" % self.pc
        if self.line:
            outstr += " [[%s]]" % self.line
        outstr += "\n"
        if open_log:
            open_log.write(outstr)
        else:
            gdb.write(outstr, gdb.STDOUT)

    def __call__(self):
        self.do()


class CallExitBreak(gdb_tools.BootFinishBreakpoint):
    def __init__(self, name, controller, stage, entry):
        self.name = name
        self.entry = entry
        gdb_tools.BootFinishBreakpoint.__init__(self, controller, True, stage)

    def out_of_scope(self):
        if self.entry.no_rec:
            self.entry.breakpoint.enabled = True
        print "exit breakpoint for %s out of scope" % self.name

    def _stop(self):
        c = self.controller
        c.depth -= 1
        gdb.post_event(WriteResults(c.depth,
                                    self.name, "exit", c.pc(),
                                    "",
                                    c._minimal))

        if self.entry.no_rec:
            self.entry.breakpoint.enabled = True
        return False


class CallEntryBreak(gdb_tools.BootBreak):
    def __init__(self, name, controller, stage, no_rec):
        self.name = name
        self.no_rec = no_rec
        try:
            i = gdb.execute("x/x %s" % self.name, to_string=True).split()[0]
        except gdb.error as e:
            print e
            return
        i = re.sub(':', '', i)
        self.fnloc = int(i, 0)
        spec = "*(0x%x)" % self.fnloc
        self.line = re.sub(":",
                           "::",
                           utils.addr2line(self.fnloc,
                                           stage)) if controller._sourceinfo else ""
        gdb_tools.BootBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, ret):
        c = self.controller
        gdb.post_event(WriteResults(c.depth,
                                    self.name, "entry", self.fnloc,
                                    self.line,
                                    c._minimal))
        c.depth += 1
        CallExitBreak(self.name, c, self.stage, self)
        if self.no_rec:
            self.breakpoint.enabled = False
        return False


class CallTrace(gdb_tools.GDBBootController):
    def __init__(self):
        self.depth = 0
        self.quiet = False
        self._minimal = True
        self._sourceinfo = False
        self.results_written = False
        self.blacklisted = {}
        self.no_rec_funs = []
        bp_hooks = {'StageEndBreak': self.stop_end}
        gdb_tools.GDBBootController.__init__(self, "calltrace",
                                             bp_hooks=bp_hooks,
                                             stage_hook=self.setup_breakpoints,
                                             exit_hook=self._gdb_exit,
                                             disabled_breakpoints=[gdb_tools.WriteBreak,
                                                                   gdb_tools.LongwriteBreak,
                                                                   gdb_tools.EndLongwriteBreak,
                                                                   gdb_tools.SubstageEntryBreak])
        p = self.add_subcommand_parser("stage_log")
        p.add_argument('stage')
        p.add_argument('log')
        p = self.add_subcommand_parser("blacklist")
        p.add_argument('stage')
        p.add_argument('fns', nargs='*')
        p = self.add_subcommand_parser("no_recursion")
        p.add_argument('recfns', nargs='*', default=[])
        p = self.add_subcommand_parser("sourceinfo")
        p.add_argument("enabled", nargs='?', default=True)
        self.stage_logs = {}
        p = self.add_subcommand_parser("minimal")
        p.add_argument("disabled", nargs='?', default=False)

    def no_recursion(self, args):
        self.no_rec_funs.extend(args.recfns)

    def minimal(self, args):
        if args.disabled is False:
            self._minimal = False
        else:
            self._minimal = True

    def sourceinfo(self, args):
        if args.enabled is True:
            self._sourceinfo = True
        else:
            self._sourceinfo = False

    def stage_log(self, args):
        self.stage_logs[args.stage] = args.log

    def blacklist(self, args):
        self.blacklisted[args.stage] = args.fns

    def pc(self):
        return int(gdb.selected_frame().pc())

    def setup_breakpoints(self, stage):
        if not gdb.current_progspace().filename:
            gdb.execute("file %s" % stage.elf)
        sname = stage.stagename
        if (sname in self.stage_logs.iterkeys()) and self.stage_logs[sname]:
            global open_log
            open_log = open(self.stage_logs[sname], 'w')

        self.results_written = False
        functions = utils.get_c_function_names(stage)
        sname = stage.stagename
        hasblacklist = sname in self.blacklisted.iterkeys()
        for (name, addr) in functions:
            if (not hasblacklist) or (hasblacklist and
                                      (name not in self.blacklisted[stage.stagename])):
                norec = name in self.no_rec_funs
                c = CallEntryBreak(name, self, stage, norec)

    def stop_end(self, bp, ret):
        if bp is None:
            print "quitting"
        if bp is not None:
            stage = self.current_stage
            controller = bp.controller
        else:
            controller = self
            stage = controller.current_stage
        if controller.results_written:
            return ret
        global open_log
        if open_log:
            sname = controller.current_stage.stagename
            print "results written to %s" % open_log
            controller.results_written = True
            # use event to make sure log is closed after all write events
            gdb.post_event(CloseLog())
        return ret

    def _gdb_exit(self, event):
        self.stop_end(None, True)


ct = CallTrace()
