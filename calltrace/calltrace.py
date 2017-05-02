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
import sys
sys.path.append(path)
version = os.path.join(path, ".python-version")
if os.path.exists(version):
    with open(version, 'r') as pv:
        penv = pv.read().strip()
        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
import testsuite_utils as utils
import gdb_tools


open_log = None
now = True


class CloseLog():
    def __init__(self):
        global now
        if now:
            self.do()
        pass

    def do(self):
        global open_log
        if open_log is not None:
            open_log.close()
            open_log = None

    def __call__(self):
        global now
        if not now:
            self.do()


class WriteResults():
    def __init__(self, depth, name, kind, pc, line, minimal=False):
        self.line = line
        self.depth = depth
        self.name = name
        self.kind = kind
        self.pc = pc
        self.entry = True if kind == "entry" else False
        self.minimal = minimal
        global now
        if now:
            self.do()

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
        global now
        if not now:
            self.do()


class CallExitBreak(gdb_tools.BootFinishBreakpoint):
    plugin_name = "calltrace"

    def __init__(self, name, controller, stage, entry):
        self.name = name
        self.entry = entry
        self.plugin = controller.get_plugin(self.plugin_name)
        self.controller = controller
        try:
            gdb_tools.BootFinishBreakpoint.__init__(self, controller, True, stage)
        except ValueError:
            pass

    def out_of_scope(self):
        if self.entry.no_rec:
            self.controller.disable_breakpoint(self.entry, disable=False)
        self.controller.gdb_print("exit breakpoint for %s out of scope\n" % self.name,
                                  self.plugin.name)

    def _stop(self, bp, ret):
        c = self.plugin
        c.depth -= 1
        gdb.post_event(WriteResults(c.depth,
                                    self.name, "exit", c.pc(),
                                    "",
                                    c._minimal))

        if self.entry.no_rec:
            self.controller.disable_breakpoint(self.entry, disable=False)
        return False


class CallEntryBreak(gdb_tools.BootBreak):
    plugin_name = "calltrace"

    def __init__(self, name, controller, stage, no_rec):
        self.name = name
        self.no_rec = no_rec
        self.stage = stage
        self.plugin = controller.subcommand_parsers[self.plugin_name].plugin
        try:
            i = gdb.execute("x/x %s" % self.name, to_string=True).split()[0]
        except gdb.error as e:
            self.gdb_print("%s\n" % e,
                           self.plugin.name)
            return
        i = re.sub(':', '', i)
        self.fnloc = int(i, 0)
        spec = "*(0x%x)" % self.fnloc
        self.line = re.sub(":",
                           "::",
                           utils.addr2line(self.fnloc,
                                           stage)) if self.plugin._sourceinfo else ""
        gdb_tools.BootBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, bp, ret):
        c = self.plugin
        gdb.post_event(WriteResults(c.depth,
                                    self.name, "entry", self.fnloc,
                                    self.line,
                                    c._minimal))
        c.depth += 1
        CallExitBreak(self.name, self.controller, self.stage, self)
        if self.no_rec and self.breakpoint:
            self.controller.disable_breakpoint(self, delete=False)
        return False


class CallTrace(gdb_tools.GDBPlugin):
    def __init__(self):
        self.depth = 0
        self._minimal = True
        self._sourceinfo = False
        self.results_written = False
        self.blacklisted = {}
        self.no_rec_funs = []
        self.stage_logs = {}
        bp_hooks = {'StageEndBreak': self.stop_end}

        parser_options = [
            gdb_tools.GDBPluginParser("stage_log", ["stage", "log"]),
            gdb_tools.GDBPluginParser("blacklist",
                                      ["stage",
                                       gdb_tools.GDBPluginPargerArg("fns", nargs="*")]),
            gdb_tools.GDBPluginParser("no_recursion",
                                      [gdb_tools.GDBPluginPargerArg("recfns",
                                                                    nargs="*", default=[])]),
            gdb_tools.GDBPluginParser("sourceinfo",
                                      [gdb_tools.GDBPluginPargerArg("enabled",
                                                                    nargs="?", default=True)]),
            gdb_tools.GDBPluginParser("minimal",
                                      [gdb_tools.GDBPluginPargerArg("disabled", nargs="?",
                                                                    default=False)]),

            ]
        gdb_tools.GDBPlugin.__init__(self, "calltrace",
                                     bp_hooks=bp_hooks,
                                     stage_hook=self.setup_breakpoints,
                                     exit_hook=self._gdb_exit,
                                     disabled_breakpoints=[gdb_tools.WriteBreak,
                                                           gdb_tools.LongwriteBreak,
                                                           gdb_tools.EndLongwriteBreak,
                                                           gdb_tools.SubstageEntryBreak],
                                     parser_args=parser_options)

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
        return self.controller.get_reg_value('pc')

    def setup_breakpoints(self, startbreak, stage):
        c = self.controller
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
                CallEntryBreak(name, c, stage, norec)

    def stop_end(self, bp, ret, c=None):
        if bp is None and c is None:
            c.gdb_print("quitting\n",
                        self.name)
        if c is None:
            c = bp.controller

        if self.results_written:
            return ret
        global open_log
        if open_log:
            c.gdb_print("results written to %s\n" % open_log.name, self.name)
            self.results_written = True
            # use event to make sure log is closed after all write events
            gdb.post_event(CloseLog())
        return ret

    def _gdb_exit(self, event):
        self.stop_end(None, True, self.controller)


plugin_config = CallTrace()
