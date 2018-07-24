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
import sys
import os
import argparse
import signal
import re
import importlib

#import capstone
#from capstone.arm import *


breakpoint_classes = {}
now = False
gdb.execute('set pagination off')
gdb.execute('set height unlimited')
gdb.execute('set confirm off')


class BreakpointRegistrar(type):
    def __new__(cls, clsname, bases, attrs):
        newcls = type.__new__(cls, clsname, bases, attrs)
        newcls.name = clsname
        global breakpoint_classes
        if clsname not in breakpoint_classes.keys():
            breakpoint_classes[clsname] = newcls
        return newcls


class TargetStageData(gdb.Command):
    def __init__(self, stage, stop_hooks):
        self.stage = stage
        self.stop_hooks = stop_hooks
        self._custom_start = False
        self._custom_stop = False
        self._substages = None
        self._exitpoint = None
        self._entrypoint = None
        self._startpoint = None
        self.stoppoint = None
        self.endbreaks = []
        self.substages = []
        self.policy_file = None
        self.regions_files = None
        self.substages_entrypoints = []
        self.entry_break = None

    def init_with_test_instance(self, enable_policy):
        # update stage start/end info now that it has been calculated
        self.stage = Main.stage_from_name(self.stage.stagename)
        if not self.stage.post_build_setup_done:
            self.stage.post_build_setup(Main.raw.instance_image_cache)

        if enable_policy and hasattr(Main.raw, "policies") and hasattr(Main.raw.policies, "substages_file") and hasattr(Main.raw.policies.substages_file, self.stage.stagename):
            self.policy_file = getattr(Main.raw.policies.substages_file, self.stage.stagename)
            self.regions_file = getattr(Main.raw.policies.regions_file, self.stage.stagename)
            self.substages_entrypoints = substage.SubstagesInfo.substage_names_from_file(self.policy_file)
        else:
            enable_policy = False
            self.policy_file = None
            self.regions_file = None
            self.substages_entrypoints = []
        self._entrypoint = self.stage.entrypoint
        self._exitpoint = self.stage.exitpc
        if self._startpoint is None:
            self._startpoint = self._entrypoint

    @property
    def startpoint(self):
        return self._startpoint

    @startpoint.setter
    def startpoint(self, val):
        if isinstance(val, str):
            try:
                val = int(val, 0)
            except:
                pass
        self._startpoint = val


class StartNextStage(object):
    def __init__(self, controller, stage):
        self.controller = controller
        self.stage = stage
        global now
        if now:
            self.do()

    def do(self):
        cont = self.controller
        stage_index = cont.stage_order.index(self.stage)
        next_stage = cont.stage_order[stage_index + 1]
        cont.delete_stage_breakpoints(self.stage)
        self.controller.gdb_print("starting next stage deleting breakpoing for %s\n" %
                                  self.stage.stagename)
        cont.prepare_stage(next_stage, True)

    def __call__(self):
        global now
        if not now:
            self.do()


class GDBTargetCommandHandler(gdb.Command):
    def __init__(self, name, controller, root=False):
        self.name = name
        self.root = root
        self.controller = controller
        gdb.Command.__init__(self, name, gdb.COMMAND_DATA)

    def invoke(self, args, from_tty):
        cmd = "%s %s" % (self.name,  args)
        self.controller.invoke(cmd, from_tty)


class GDBTargetController(object):
    def __init__(self):
        self.breakpoints = []
        self.gone = False
        self.stages_with_policies = []
        self.disabled_breakpoints = set()
        self.test_instance_name = None
        self.test_trace_name = None
        gdb.execute('set python print-stack full')

        self.name = "gdb_tools"
        self.command_handlers = [GDBTargetCommandHandler(self.name, self, True)]

        self.parser = argparse.ArgumentParser(prog=self.name)
        self.subparser = self.parser.add_subparsers(title=self.name)
        # self.subparser_parsers = self.subparser.add_parser(self.name)
        # self.tool_subparsers = self.subparser_parsers.add_subparsers(title=self.name)
        self.cmds = []
        self.subcommand_parsers = {}
        self.core_state = None
        self.current_substage = 0
        self.current_substage_name = ""
        self.current_stage = None
        self._setup = False
        self.calculate_write_dst = False
        self.isbaremetal = False
        self.run_standalone = False
        self._kill = False
        self.bp_hooks = {}
        self.f_hooks = []
        self.stage_hooks = []
        self.exit_hooks = []
        global breakpoint_classes
        self._import_done = False
        for k in breakpoint_classes.iterkeys():
            self.bp_hooks[k] = []
        p = self.add_subcommand_parser('log')
        p.add_argument('logfile', default='', nargs='?')
        self.add_subcommand_parser('flushlog')
        p = self.add_subcommand_parser('go')
        p.add_argument('-p', "--prepare_only", action='store_true', default=False)
        p.add_argument('-r', "--run_not_cont", action='store_true', default=False)
        p = self.add_subcommand_parser("startat")
        p.add_argument('-s', "--stage", action='store', default='')
        p.add_argument("pc", nargs='?')
        p = self.add_subcommand_parser('until')
        p.add_argument('-s', "--stage", action='store', default='')
        p.add_argument("pc", nargs='?')
        p = self.add_subcommand_parser('test_trace')
        p.add_argument('name')
        p = self.add_subcommand_parser('test_instance')
        p.add_argument('name')
        p = self.add_subcommand_parser('stages')
        p.add_argument('stage_name', nargs='*')
        p = self.add_subcommand_parser('enable_policy')
        p.add_argument('stage_name')
        p = self.add_subcommand_parser('dir')
        p.add_argument('paths', nargs='*')
        self.add_subcommand_parser('update_path')
        p = self.add_subcommand_parser('kill')
        p.add_argument('do_kill', nargs='?', default=False)
        p = self.add_subcommand_parser("setup_target")
        p.add_argument('do_setup', nargs='?', default=True)
        p = self.add_subcommand_parser('plugin')
        p.add_argument('module', nargs='*')
        p = self.add_subcommand_parser("is_bare_metal")
        p.add_argument('baremetal', nargs='?', default=False)
        p = self.add_subcommand_parser("standalone")
        p.add_argument('run_standalone', nargs='?', default=True)

        self.hw = None

    def gdb_exit(self, event):
        gdb.flush()
        for e in self.exit_hooks:
            e(event)

    @staticmethod
    def _clsname(b):
        if isinstance(b, type):
            name = b.__name__
        else:
            name = b.__class__.__name__
        if '.' in name:
            name = name.split('.')[-1]

        return name

    def lookup_bp_hooks(self, bp):
        name = self._clsname(bp)
        if name in self.bp_hooks.iterkeys():
            return self.bp_hooks[name]
        else:
            return []

    def get_plugin(self, name):
        return self.subcommand_parsers[name].plugin

    def test_instance(self, args):
        self.test_instance_name = args.name

    def test_trace(self, args):
        self.test_trace_name = args.name

    def plugin(self, args):
        for m in args.module:
            self.install_plugin(m)

    def is_bare_metal(self, args):
        if args.baremetal is not True:
            self.isbaremetal = False
        else:
            self.isbaremetal = True

    def standalone(self, args):
        if args.run_standalone is not True:
            self.run_standalone = False
            print "NO STANDALONE"
        else:
            print "RUN STANDALONE"
            self.run_standalone = True

    def setup_target(self, args):
        self._do_import()

        if args.do_setup is not True:
            self._setup = False
        else:
            self._setup = True

    def kill(self, args):
        if args.do_kill is not True:
            self._kill = True
        else:
            self._kill = False

    def set_mode(self):
        if self.run_standalone:
            return
        if self.isbaremetal:
            addr = self.get_reg_value('pc')
            (ts, arms, ds) = getattr(Main.raw.runtime.thumb_ranges, self.current_stage.stagename)()
            # hack
            if utils.addr2functionname(addr, self.current_stage) == "clear_bss":
                typ = "thumb"
            elif arms.search(addr):
                typ = "arm"
            else:
                typ = "thumb"
            if not typ == self.core_state:
                self.core_state = typ
                gdb.execute("mon arm core_state %s" % typ, to_string=True)

    def get_instr_value(self, addr, thumb):
        size = 'w'
        if self.isbaremetal:
            gdb.execute("mon gdb_sync")
        val = (gdb.execute("x/1%sx 0x%x" % (size, addr), to_string=True).split(':'))[-1].strip()
        # strip off leading '0x'
        val = val[2:]
        val = val.decode('hex')
        # reverse bytes
        val = val[::-1]
        return val

    def get_reg_value(self, reg, force=False):
        if self.isbaremetal:
            gdb.execute("mon gdb_sync")
            if force:
                out = gdb.execute("mon reg %s force" % reg, to_string=True)
                try:
                    return int(out.split(":")[1].strip(), 16)
                except Exception as e:
                    pass
        return long(gdb.execute("print/x $%s" % reg, to_string=True).split()[2], 16)

    def get_breaks(self, cls):
        if not isinstance(cls, list):
            cls = [cls]
        return [b.companion for b in self.breakpoints
                if any(map(lambda c: isinstance(b, c), cls))]

    def insert_breakpoints(self, stage):
        self.insert_write_breakpoints(stage)
        self.insert_reloc_breakpoints(stage)
        self.insert_longwrites_breakpoints(stage)
        self.insert_substagestart_breakpoints(stage)
        self.insert_stageend_breakpoints(stage)

    def insert_stageend_breakpoints(self, stage):
        if self.run_standalone:
            return
        s_info = self._stages[stage.stagename]
        end = s_info.stoppoint
        if end:
            s_info.endbreaks.append(StageEndBreak(end, self, stage, True))
        for (addr, line, success) in db_info.get(stage).stage_exits():
            s_info.endbreaks.append(StageEndBreak(addr, self, stage, success))

    def insert_substagestart_breakpoints(self, stage):
        if self.run_standalone:
            return
        if any(map(lambda x: "SubstageEntryBreak" == x, self.disabled_breakpoints)):
            return
        sname = stage.stagename
        s_info = self._stages[sname]
        substages = s_info.substages_entrypoints
        self.current_substage_name = substages[0] if substages else ""
        self.current_substage = 0
        for i in range(0, len(substages)):
            self.gdb_print("Inserting beakpoint for substage '%s' (%s)\n" % (substages[i], i))
            SubstageEntryBreak(substages[i], i, self, stage)

    def insert_longwrites_breakpoints(self, stage):
        if self.run_standalone:
            return
        if any(map(lambda x: x == "LongwriteBreak", self.disabled_breakpoints)):
            return

        for r in db_info.get(stage).longwrites_info():
            LongwriteBreak(self, r, stage)

    def insert_reloc_breakpoints(self, stage):
        if self.run_standalone:
            return
        if any(map(lambda x: x == "RelocBreak", self.disabled_breakpoints)):
            return
        for r in db_info.get(stage).reloc_info():
            RelocBreak(self, stage, r)

    def enable_write_breaks(self, stage, enable=True):
        if self.run_standalone:
            return
        for bp in self.breakpoints:
            b = bp.companion
            if isinstance(b, WriteBreak) or isinstance(b, LongwriteBreak):
                self.disable_breakpoint(b, disable=not enable, delete=False)

    def insert_write_breakpoints(self, stage):
        if self.run_standalone:
            return
        if any(map(lambda x: x == "WriteBreak", list(self.disabled_breakpoints))):
            return
        i = 0
        n = db_info.get(stage).num_writes()
        self.gdb_print("%d write breakpoints\n" % n)
        for (pc, halt) in db_info.get(stage).write_info():
            if halt is True:
                if self.isbaremetal:
                    # check to see this address isn't in a skip range
                    if db_info.get(stage).skip_pc(pc):
                        # don't insert WriteBreak
                        continue

                # halt should be false for write entries that match a longwrite writepc,
                # but check just in case
            if db_info.get(stage).is_pc_longwrite(pc):
                self.gdb_print("write pc 0x%x is part of a longwrite, not adding breakpoint.\n"
                               % pc)
                continue
            i = i + 1
            WriteBreak(pc, self, stage)
        self.gdb_print("actually inserted %s of %s write breakpoints\n" % (i, n))

    def until(self, args):
        stagename = args.stage
        if not stagename:  # default is first stage
            if len(self.stage_order) < 1:
                self.gdb_print("no default stage to choose from, "
                               "first add a stage ordering with 'stages' command\n")
                return
            else:
                stagename = self.stage_order[0].stagename
        if args.pc:
            pc = args.pc
        else:
            pc = self._stages[stagename]._exitpoint
        self._stages[stagename].stoppoint = pc

    def gdb_print(self, msg, fm="gdb_tools"):
        gdb.write("[%s] %s" % (fm, msg), gdb.STDOUT)

    def enable_policy(self, args):
        self.stages_with_policies.append(args.stage_name)

    def add_subcommand_parser(self, name, cmd=None):
        if cmd is None:
            self.cmds.append(name)
            s = self.subparser.add_parser(name)
        else:
            sub = self.subcommand_parsers.get(cmd.name,
                                              GDBSubcommandParser(cmd,
                                                                  self))
            sub.cmds.append(name)
            s = sub.subparser.add_parser(name)
            self.subcommand_parsers[cmd.name] = sub
        s.add_argument(name, action='store_true')
        return s

    def dir(self, args):
        sys.path.extend(args.paths)

    def log(self, args):
        gdb.flush()
        if args.logfile:
            gdb.execute("set logging on")
            gdb.execute("set logging file %s" % args.logfile)
        else:
            gdb.execute("set logging off")

    def flushlog(self, args):
        gdb.flush()

    def stages(self, args):
        if self.run_standalone:
            self.stage_order = []
        else:
            self.stage_order = [Main.stage_from_name(s) for s in args.stage_name]

    def startat(self, args):
        stagename = args.stage
        if not stagename:  # default is first substage
            if len(self.stage_order) < 1:
                self.gdb_print("no default stage to choose from, "
                               "first add a stage ordering with 'stages' command\n")
                return
            else:
                stagename = self.stage_order[0].stagename
        if args.pc:
            pc = args.pc
        else:
            pc = ''
        self._stages[stagename].startpoint = pc

    def invoke(self, arg, from_tty):
        def parse_global(a):
            pargs = self.parser.parse_args(a)
            for c in self.cmds:
                if hasattr(pargs, c) and (getattr(pargs, c) is True):
                    getattr(self, c)(pargs)
                    return True
            return False
        argv = gdb.string_to_argv(arg)
        parser_name = argv[0]
        argv = argv[1:]
        if parser_name == self.name:
            if parse_global(argv):
                return
        else:
            if parser_name in self.subcommand_parsers.iterkeys():
                sub = self.subcommand_parsers[parser_name]
                if argv[0] in sub.cmds:
                    pargs = sub.parser.parse_args(argv)
                    for subc in sub.cmds:
                        if hasattr(pargs, subc) and (getattr(pargs, subc) is True):
                            getattr(sub.plugin, subc)(pargs)
                            return
            if parse_global(argv):
                return
        self.gdb_print("unknown command %s\n" % arg)

    def enable_current_stage_write_breaks(self, enable=True):
        self.enable_write_breaks(self.current_stage, enable)

    def enable_current_stage_end_break(self, enable=True):
        for e in self._stages[self.current_stage.stagename].endbreaks:
            self.disable_breakpoint(e, disable=not enable, delete=False)

    def prepare_stage(self, stage, cont=False):
        self.current_stage = stage
        s = StageStartBreak(self, stage)
        if cont and s.cont:
            self.disable_breakpoint(s, delete=False)
            s.continue_stage()
        return s

    def finalize(self, args):
        if self.run_standalone:
            self.stage_order == []
            self._stages = {}
        else:
            if len(self.stage_order) == 0:
                self.stage_order = [Main.stage_from_name(s) for s in self._stages.keys()]
            stages = [s.stagename for s in self.stage_order]
            doit_manager.TaskManager(doit_manager.cmds.hook,
                                     self.test_instance_name,
                                     self.test_trace_name,
                                     None, [], [], {}, [])

            tmpdir = Main.raw.runtime.temp_target_src_dir
            gdb.execute("dir %s" % tmpdir)
            gdb.execute("set substitute-path %s %s" % (Main.target_software.root, tmpdir))
            self.hw = Main.raw.runtime.trace.hw
            for stage in self.stage_order:
                s = self._stages[stage.stagename]
                s.init_with_test_instance(True if s.stage.stagename in self.stages_with_policies else False)
        for f in self.f_hooks:
            f(args)

    def delete_stage_breakpoints(self, stage):
        global breakpoint_classes
        for b in self.get_breaks(list(breakpoint_classes.itervalues())):
            if b.stage == stage:
                self.disable_breakpoint(b, delete=b.name == "StageEndBreak")

    def spec_to_addr(self, spec):
        addr = -1
        if not isinstance(spec, str):
            addr = spec
        else:
            if spec.startswith("*") or spec.startswith("0x"):
                i = re.sub("[()*]+", "", spec)
            else:
                if self.isbaremetal:
                    gdb.execute("mon gdb_sync")
                i = gdb.execute("x/x %s" % spec, to_string=True).split(":")[0]
                i = i.split()[0]
            addr = long(i, 0)
        if addr == -1:
            self.gdb_print("failed to get addr for spec %s\n" % spec)
        return addr

    def disable_breakpoint(self, b, disable=True, delete=True):
        bp = b.breakpoint
        addr = self.spec_to_addr(bp.location)
        bp.enabled = not disable
        if disable and delete:
            if b in self.breakpoints:
                self.breakpoints.remove(b)
            gdb.post_event(lambda: self._delete_bp(bp, addr))

    def _delete_bp(self, bp, addr):
        if not self.isbaremetal:
            bp.delete()

    def install_plugin(self, p):
        sys.path = [os.path.dirname(p)] + sys.path
        name = re.sub(".py", "", os.path.basename(p))
        mod = importlib.import_module(name)
        conf = getattr(mod, "plugin_config")
        self.command_handlers.append(GDBTargetCommandHandler(conf.name, self))
        if conf.calculate_write_dst:
            self.calculate_write_dst = True
        for subparser in conf.parser_args:
            p = self.add_subcommand_parser(subparser.name, conf)
            for parg in subparser.args:
                keys = parg.optional_keys
                kwargs = {
                    k: getattr(parg, k) for k in keys if hasattr(parg, k)
                }
                p.add_argument(parg.name, **kwargs)
                pass
        if conf.f_hook:
            self.f_hooks.append(conf.f_hook)
        for (k, v) in conf.bp_hooks.iteritems():
            if v:
                l = self.bp_hooks.get(k, [])
                l.append(v)
                self.bp_hooks[k] = l
        if conf.exit_hook:
            self.exit_hooks.append(conf.exit_hook)

        if self.disabled_breakpoints:
            self.disabled_breakpoints = self.disabled_breakpoints & set(conf.disabled_breakpoints)
        else:
            self.disabled_breakpoints = set(conf.disabled_breakpoints)

        if conf.stage_hook:
            self.stage_hooks.append(conf.stage_hook)
        conf.controller = self
        sys.path = sys.path[1:]

    def _do_import(self):
        if not self._import_done:
            self._import_done = True
            global Main
            if not self.run_standalone:
                from config import Main
            global substage
            global doit_manager
            global substage
            global staticanalysis
            global ia
            global pure_utils
            global db_info
            global utils
            global unicorn_utils
            global unicorn
            global uniarm
            global capstone
            global caparm
            global r2
            import unicorn
            import unicorn.arm_const as uniarm
            import capstone
            import capstone.arm as caparm
            import r2_keeper as r2
            import ia
            if not self.run_standalone:
                import substage, staticanalysis, pure_utils, doit_manager, db_info
                import testsuite_utils as utils
            import unicorn_utils
            if not self.run_standalone:
                self.cc = Main.cc
                self.stage_order = [Main.stages[0]]  # default is first stage only
                self._stages = {s.stagename: TargetStageData(s, self.bp_hooks)
                                for s in Main.stages}
            else:
                self.cc = "gcc"
                self.stages = {}
                self.stage_order = ["local"]
            self.ia = ia.InstructionAnalyzer()

    def update_path(self, args):
        self._do_import()

    def go(self, args):
        if self.gone:
            return
        self.gone = True
        gdb.events.exited.connect(self.gdb_exit)
        self.finalize(args)
        if not self.run_standalone:
            stage = self.stage_order[0]
        else:
            class LocalStage():
                def __init__(self, elf):
                    self.elf = elf
                    self.entrypoint = pure_utils.get_entrypoint(elf)
                    self.exitpc = -1
                    self.stagename = "local"
            stage = LocalStage(gdb.current_progspace().filename)
        s = self.prepare_stage(stage, False)
        self.set_mode()
        stage_entered = False
        try:
            if self.get_reg_value('pc', True) == s.breakpoint.companion.addr:
                self.gdb_print("First stage already entered\n")
                stage_entered = True
        except gdb.error:
            pass
        if stage_entered and not self.run_standalone:
            print "Calling breakpoint hook"
            s.stop()
            s.continue_stage()

        self.gdb_print("ready to go\n")
        if not args.prepare_only:
            if args.run_not_cont:
                gdb.execute("r")
            else:
                gdb.execute("c")


class CompanionBreakpoint(gdb.Breakpoint):
    def __init__(self, spec, twin, typ=None):
        self._stop = twin.stop
        self.companion = twin
        gdb.Breakpoint.__init__(self, spec, internal=True)

    def stop(self):
        self.companion.controller.set_mode()
        ret = self._stop()
        return ret


class TargetBreak(object):
    __metaclass__ = BreakpointRegistrar

    def __init__(self, spec, controller, needs_relocation, stage, **kwargs):
        #if controller.run_standalone:
        #else:
        self.stage = stage
        self.relocated = 0
        self.needs_relocation = needs_relocation
        if 'r' in kwargs.iterkeys():
            for f in kwargs['r'].iterkeys():
                setattr(self, f, kwargs['r'][f])
        self.controller = controller
        self.stophooks = self.controller.lookup_bp_hooks(self)
        self.final_events = []
        for (k, v) in kwargs.iteritems():
            setattr(self, k, v)
        if not isinstance(spec, str):
            spec = "*(0x%x)" % spec
        else:
            if (spec.startswith("*") or spec.startswith("0x")) \
               and not spec.startswith("*"):
                spec = "*(%s)" % spec
        self.addr = controller.spec_to_addr(spec)
        self.breakpoint = CompanionBreakpoint(spec, self)
        if any(map(lambda x: self.name == x, controller.disabled_breakpoints)):
            controller.disable_breakpoint(self, delete=False)
        controller.breakpoints.append(self)

    def move(self, offset, mod, delorig=False):
        if self.needs_relocation:
            if not self.breakpoint.is_valid():
                self.controller.breakpoints.remove(self)
                return
            if self.breakpoint.location.startswith("*"):
                l = re.sub("[()*]+", "", self.breakpoint.location)
                lpc = long(l, 0)
                self.addr = (lpc + offset) % mod
            else:
                self.addr = (self.addr + offset) % mod
            spec = "*(0x%x)" % self.addr
            # self.controller.gdb_print("relocating %s to %s\n" % (self, spec))
            self.relocated = offset
            if delorig:
                self.controller.disable_breakpoint(self)
            self.breakpoint = CompanionBreakpoint(spec, self)
            if hasattr(self, '_move'):
                self._move(offset, mod, delorig)

    def msg(self, m):
        self.controller.gdb_print(m)

    def _stop(self, bp, ret):
        return True

    def stop(self):
        ret = False
        self.controller.set_mode()
        if hasattr(self, '_stop'):
            ret = self._stop(self, ret)
        for s in self.stophooks:
            r = s(self, ret)
            ret = ret and r
        for f in self.final_events:
            f()
        self.final_events = []
        self.controller.set_mode()
        return ret


class TargetFinishBreakpoint(gdb.FinishBreakpoint, TargetBreak):
    def __init__(self,  controller, needs_relocation, stage, **kwargs):
        self.stage = stage
        self.needs_relocation = needs_relocation
        self.controller = controller
        self.stophooks = self.controller.lookup_bp_hooks(self)
        self.final_events = []
        for (k, v) in kwargs.iteritems():
            setattr(self, k, v)
        if controller.isbaremetal and not controller.run_standalone:
            pc = controller.get_reg_value("lr")
            (ts, arms, ds) = getattr(Main.raw.runtime.thumbranges, stage.stagename)()
            if not (ts.search(pc) or arms.search(pc)):
                self.breakpoint = None
                return
        self.breakpoint = gdb.FinishBreakpoint.__init__(self, internal=True)

    def stop(self):
        self.controller.set_mode()
        ret = False
        if hasattr(self, '_stop'):
            ret = self._stop(self, ret)
        if self.breakpoint:
            self.controller.disable_breakpoint(self)
        self.controller.set_mode()
        return ret


class ReturnBreak(TargetBreak):
    def __init__(self, spec, controller, stage):
        if not isinstance(spec, str):
            spec = "*(0x%x)" % spec
        TargetBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, bp, ret):
        gdb.execute("return")
        return False


class WriteBreak(TargetBreak):
    def __init__(self, spec, controller, stage):
        if not isinstance(spec, str):
            spec = "*(0x%x)" % spec
        self.emptywrite = {'start': None,
                           'end': None,
                           'cpsr': None,
                           'thumb': None,
                           'i': None,
                           'ins': None,
                           'pc': None}
        self.writeinfo = self.emptywrite
        TargetBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, bp, ret):
        cont = self.controller
        if cont.calculate_write_dst:
            self.writeinfo = self.emptywrite
            pc = cont.get_reg_value('pc', True)
            inspc = pc - self.relocated
            cpsr = cont.get_reg_value("cpsr", True)
            thumb = cont.ia.is_thumb(cpsr)
            i = cont.get_instr_value(pc, thumb)
            ins = cont.ia.disasm(i, thumb, inspc, True)
            row = db_info.get(self.stage).pc_writes_info(inspc)
            size = row['writesize']
            needed_regs = [row['reg0'], row['reg1'], row['reg2'], row['reg3']]
            regs = []
            for r in filter(lambda x: len(x) > 0, needed_regs):
                regs.append(cont.get_reg_value(r, True))
            dst = cont.ia.calculate_store_offset(ins, regs)
            if size < 0:  # (ie. push instruction)
                end = dst
                start = dst + size
            else:
                start = dst
                end = dst + size
            self.writeinfo = {
                'pc': pc,
                'start': start,
                'end': end,
                'cpsr': cpsr,
                'thumb': thumb,
                'i': i,
                'ins': ins,
            }
        return False


class SubstageEntryBreak(TargetBreak):
    def __init__(self, fnname, substagenum, controller, stage):
        self.fnname = fnname
        self.substagenum = substagenum
        self.controller = controller
        self.fnloc = utils.get_symbol_location(fnname, stage)
        if self.fnloc < 0:
            raise Exception("not such function named %s, cannot be a substage entrypoint" % fnname)
        if self.fnloc:
            spec = "*(0x%x)" % self.fnloc
        else:
            spec = fnname
        TargetBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, bp, ret):
        self.controller.current_substage = self.substagenum
        self.controller.current_substage_name = self.fnname
        return False


class StageStartBreak(TargetBreak):

    @classmethod
    def get_addr(cls, controller, stage):
        realstart = controller._stages[stage.stagename]._startpoint
        return realstart

    def __init__(self, controller, stage):
        if controller.run_standalone:
            realstart = stage.entrypoint
        else:
            realstart = self.get_addr(controller, stage)
        if not isinstance(realstart, str):
            spec = "*(0x%x)" % realstart
        else:
            spec = realstart
        TargetBreak.__init__(self, spec, controller, True, stage)
        self.cont = True

    def continue_stage(self):
        cont = self.controller
        cont.disable_breakpoint(self)

        if not gdb.current_progspace().filename:
            elf = self.stage.elf
            gdb.execute("file %s" % elf)
            cont.gdb_print('loaded file %s\n' % elf)
        cont.gdb_print("Inserting breakpoints for %s %s ...\n" % (self.controller.name,
                                                                  self.stage.stagename))
        cont.current_substage = 0
        cont.insert_breakpoints(self.stage)
        cont.gdb_print("Done setting breakpoints\n")

        for s in self.controller.stage_hooks:
            s(self, self.stage)

    def _stop(self, bp, ret):
        self.continue_stage()
        return False


class StageEndBreak(TargetBreak):
    def __init__(self, spec, controller, stage, success):
        self.addr = spec
        self.stage = stage
        self.starttime = time.time()
        if not isinstance(spec, str):
            spec = "*(0x%x)" % spec
        #controller.gdb_print("stage ends at %s\n" % spec)
        TargetBreak.__init__(self, spec, controller, True, stage, success=success)

    def _stop(self, bp, ret):
        cont = self.controller
        self.msg("HIT END BREAKPOINT AT 0x%x\n" %
                 cont.get_reg_value("pc"))
        now = time.time()
        self.msg("This took %f minutes to run\n" % ((now-self.starttime)/60))
        stage_index = cont.stage_order.index(self.stage)
        if stage_index >= len(cont.stage_order) - 1:
            ret = True
        else:
            ret = False
            self.final_events = [StartNextStage(cont, self.stage)]
        return ret


class EndLongwriteBreak(TargetBreak):
    def __init__(self, lwbreak, stage):
        self.stage = stage
        controller = lwbreak.controller
        self.addr = lwbreak.contaddr
        spec = "*(0x%x)" % self.addr if not isinstance(self.addr, str) else self.addr
        TargetBreak.__init__(self, spec, controller, False, stage, lwbreak=lwbreak)
        controller.disable_breakpoint(lwbreak, delete=False)

    def _stop(self, bp, ret):
        self.controller.disable_breakpoint(self.lwbreak, disable=False)
        self.controller.disable_breakpoint(self, delete=False)
        return False


class LongwriteBreak(TargetBreak):
    def __init__(self, controller, r, stage):
        # print "creating longwrite break"
        self.emptywrite = {'start': None,
                           'end': None,
                           'pc': None}
        self.writeinfo = self.emptywrite
        self.breakaddr = r['breakaddr']
        self.contaddr = r['contaddr']
        self.writeaddr = r['writeaddr']
        self.thumb = r['thumb']
        r2.gets(stage.elf, "s 0x%x" % self.writeaddr)
        if self.thumb:
            self.emu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_THUMB)
            r2.gets(stage.elf, "ahb 16")
            r2.gets(stage.elf, "e asm.bits=16")
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        else:
            self.emu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
            r2.gets(stage.elf, "ahb 32")
            r2.gets(stage.elf, "e asm.bits=32")
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        r2.get(stage.elf, "pdj 1")

        self.cs.detail = True
        self.info = staticanalysis.LongWriteInfo(stage.elf, r['start'],
                                                 r['end'], self.thumb)
        self.inss = []
        self.regs = set()
        self.bytes = b""
        self.dst_addrs = []
        self.write_size = r['writesize']
        for i in self.info.bbs:
            self.inss.append(i)
            bs = i["bytes"].decode("hex")
            self.bytes += b"%s" % bs
            ci = next(self.cs.disasm(bs, i["offset"], 1))
            if i["offset"] == self.writeaddr:
                self.write_ins = ci
            (read, write) = ci.regs_access()
            for rs in (read, write):
                self.regs.update([ci.reg_name(rn).encode('ascii') for rn in rs])
        self.emu.mem_map(0, 0xFFFFFFFF + 1, unicorn.UC_PROT_ALL)
        self.emu.mem_write(self.inss[0]["offset"], self.bytes)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.write_hook)
        self.spec = "*(0x%x)" % r['breakaddr']
        TargetBreak.__init__(self, self.spec, controller, True, stage, r=r)

    def write_hook(self, emu, access, addr, size, value, data):
        self.dst_addrs.append(long(addr))
        return True

    def _stop(self, bp, ret):
        if self.controller.calculate_write_dst:
            self.writeinfo = self.emptywrite
            if self.controller.isbaremetal:
                gdb.execute("mon gdb_sync")
            for r in self.regs:
                v = self.controller.get_reg_value(r, True)
                reg_num = unicorn_utils.reg_val(r)
                self.emu.reg_write(reg_num, v)
            start = self.breakaddr
            self.dst_addrs = []
            if self.thumb:
                start = start | 1
            self.emu.emu_start(start, self.contaddr)
            self.writeinfo['start'] = self.dst_addrs[0]
            self.writeinfo['end'] = self.dst_addrs[0] + len(self.dst_addrs) * self.write_size
            self.writeinfo['pc'] = self.writeaddr
            # reset dest addrs
            EndLongwriteBreak(self, self.stage)
        return False

    def _move(self, offset, mod, d):
        self.breakaddr = (self.breakaddr + offset) % mod
        self.writeaddr = (self.writeaddr + offset) % mod
        self.contaddr = (self.contaddr + offset) % mod


class RelocBreak(TargetBreak):
    def __init__(self, controller, stage, r):
        self.relocpc = r['relocpc']
        spec = "*(0x%x)" % (self.relocpc)
        self.reldelorig = r['reldelorig']
        controller.gdb_print("relocation bp starts at %s, moves %x-%x by %x, ready by %x\n"
                             % (spec, r['startaddr'], r['startaddr']+r['size'],
                                r['reloffset'], r['relocpc']))
        TargetBreak.__init__(self, spec, controller, False, stage, r=r)

    def addr_in_reloc_range(self, breakaddr):
        return (self.startaddr <= breakaddr) and (breakaddr < (self.startaddr + self.size))

    def _stop(self, bp, ret):
        self.controller.gdb_print("relocating breakpoints\n")
        controller = self.controller
        for bp in self.controller.breakpoints:
            if bp.needs_relocation:
                if self.addr_in_reloc_range(bp.addr):
                    bp.move(self.reloffset, self.relmod, True)
            else:
                continue
        # make sure final breakpoint is still enabled
        controller.enable_current_stage_end_break()
        controller.gdb_print("continuing execution\n")
        controller.disable_breakpoint(self, delete=False)
        return False


class GDBPlugin():
    default_stage_hook = None
    default_finalize_hook = None
    default_bp_hooks = {}

    def __init__(self, name, bp_hooks=default_bp_hooks, stage_hook=None, f_hook=None,
                 exit_hook=None, disabled_breakpoints=[], calculate_write_dst=False,
                 parser_args=[]):
        self.name = name
        self.calculate_write_dst = calculate_write_dst
        self.controller = None
        self.parser_args = parser_args
        self.stage_hook = stage_hook
        self.f_hook = f_hook
        self.disabled_breakpoints = disabled_breakpoints
        self.exit_hook = exit_hook
        self.bp_hooks = {}
        global breakpoint_classes
        for k in breakpoint_classes.iterkeys():
            if k in bp_hooks.iterkeys():
                self.bp_hooks[k] = bp_hooks[k]
            else:
                self.bp_hooks[k] = None


class GDBPluginParserArg():
    optional_keys = ["nargs", "default"]

    def __init__(self, name, **kwargs):
        self.name = name
        for o in self.optional_keys:
            if o in kwargs:
                setattr(self, o, kwargs[o])

    def __repr__(self):
        keys = ["%s=%s" % (o, getattr(self, o)) for o in self.optional_keys if hasattr(self, o)]
        if keys:
            keys = "(%s)" % ",".join(keys)
        else:
            keys = ""
        return "%s%s" % (self.name, keys)


class GDBPluginParser():
    def __init__(self, name, args=[]):
        self.name = name
        self.args = []
        for a in args:
            if isinstance(a, GDBPluginParserArg):
                self.args.append(a)
            else:
                self.args.append(GDBPluginParserArg(a))


class GDBSubcommandParser():
    def __init__(self, plugin, controller):
        self.plugin = plugin
        self.cmds = []
        self.parser = argparse.ArgumentParser(prog=plugin.name)
        self.subparser = self.parser.add_subparsers(title=plugin.name)


if __name__ == "__main__":
    c = GDBTargetController()
