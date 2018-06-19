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
import sys
# sys.path.append(os.path.join(sys.prefix, "lib/python2.7/site-packages"))
import testsuite_utils as utils
import gdb_tools

open_log = None
now = False


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


class CallExitBreak(gdb_tools.TargetFinishBreakpoint):
    plugin_name = "calltrace"

    def __init__(self, name, controller, stage, entry, depth):
        self.name = name
        self.entry = entry
        self.plugin = controller.get_plugin(self.plugin_name)
        self.controller = controller
        self.valid = True
        self.depth = depth
        try:
            gdb_tools.TargetFinishBreakpoint.__init__(self, controller, True, stage)
        except ValueError:
            self.valid = False

    def out_of_scope(self):
        if self.entry.no_rec:
            self.controller.disable_breakpoint(self.entry, disable=False)
        self.controller.gdb_print("exit breakpoint for %s out of scope\n" % self.name,
                                  self.plugin.name)

    def _stop(self, bp, ret):
        c = self.plugin
        c.depth = self.depth
        #if not self.depth == c.depth:
        #    return
        gdb.post_event(WriteResults(self.depth,
                                    self.name, "exit", c.pc(),
                                    "",
                                    c._minimal))

        if self.entry.no_rec:
            self.controller.disable_breakpoint(self.entry, disable=False)
        return False


class CallEntryBreak(gdb_tools.TargetBreak):
    plugin_name = "calltrace"

    @classmethod
    def settable(cls, name, c):
        try:
            i = gdb.execute("x/x %s" % name, to_string=True).split()[0]
        except gdb.error as e:
            #c.gdb_print("%s cannot set breakpoint for %s\n" % (e,
             #                                                           name), "calltrace")
            return False
        return True            
    
    def __init__(self, name, controller, stage, no_rec):
        self.name = name
        self.no_rec = no_rec
        self.stage = stage
        self.plugin = controller.subcommand_parsers[self.plugin_name].plugin
        try:
            i = gdb.execute("x/x %s" % self.name, to_string=True).split()[0]
        except gdb.error as e:
            controller.gdb_print("%s cannot set breakpoint for %s\n" % (e,
                                                                        self.name),
                                 self.plugin.name)
            return
        i = re.sub(':', '', i)
        self.fnloc = int(i, 0)
        spec = "*(0x%x)" % self.fnloc
        self.line = re.sub(":",
                           "::",
                           utils.addr2line(self.fnloc,
                                           stage)) if self.plugin._sourceinfo else ""
        gdb_tools.TargetBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, bp, ret):
        c = self.plugin
        gdb.post_event(WriteResults(c.depth,
                                    self.name, "entry", self.fnloc,
                                    self.line,
                                    c._minimal))

        e = CallExitBreak(self.name, self.controller, self.stage, self, c.depth)
        c.depth += 1
        if not e.valid:
            c.depth -= 1
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
            gdb_tools.GDBPluginParser("stage_log",
                                      [gdb_tools.GDBPluginParserArg("log_args",
                                                                    nargs="*", default=[])]),
                                       
            gdb_tools.GDBPluginParser("blacklist",
                                      [gdb_tools.GDBPluginParserArg("stage_args",
                                                                    nargs="*", default=[])]),
            gdb_tools.GDBPluginParser("no_recursion",
                                      [gdb_tools.GDBPluginParserArg("recfns",
                                                                    nargs="*", default=[])]),
            gdb_tools.GDBPluginParser("sourceinfo",
                                      [gdb_tools.GDBPluginParserArg("enabled",
                                                                    nargs="?", default=True)]),
            gdb_tools.GDBPluginParser("minimal",
                                      [gdb_tools.GDBPluginParserArg("disabled", nargs="?",
                                                                    default=False)]),

            ]
        gdb_tools.GDBPlugin.__init__(self, "calltrace",
                                     bp_hooks=bp_hooks,
                                     stage_hook=self.setup_breakpoints,
                                     exit_hook=self._gdb_exit,
                                      disabled_breakpoints=[
                                          #"WriteBreak",
                                          "LongwriteBreak",
                                     #                       "EndLongwriteBreak",
                                     #                       "SubstageEntryBreak"],
                                          ],
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
        current = None
        nextstage = True
        for l in args.log_args:
            if nextstage:
                current = l
                nextstage = False
            elif l == "--":
                nextstage = True
            else:
                self.stage_logs[current] = l


    def blacklist(self, args):
        current = None
        nextstage = True
        for l in args.stage_args:
            if nextstage:
                current = l
                nextstage = False
                self.blacklisted[current] = []
            elif l == "--":
                nextstage = True
            else:
                self.blacklisted[current].append(l)

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
                if CallEntryBreak.settable(name, c):
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
