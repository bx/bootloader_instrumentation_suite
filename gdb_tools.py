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
path = gdb.os.getcwd()
sys.path.append(path)
version = os.path.join(path, ".python-version")
if os.path.exists(version):
    with open(version, 'r') as pv:
        penv = pv.read().strip()
        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
from config import Main
import substage
import staticanalysis
import pure_utils
import config
import doit_manager
import db_info

breakpoint_classes = {}

gdb.execute('set pagination off')
gdb.execute('set height unlimited')
gdb.execute('set confirm off')

class BreakpointRegistrar(type):
    def __new__(cls, clsname, bases, attrs):
        newcls = type.__new__(cls, clsname, bases, attrs)
        global breakpoint_classes
        if clsname not in breakpoint_classes.keys():
            breakpoint_classes[clsname] = newcls
        # newcls.name = newcls
        return newcls


class BootStageData(gdb.Command):
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
        self.substages = None
        self.policy_file = None
        self.regions_files = None
        self.substages_entrypoints = None

    def init_with_test_instance(self):
        # update stage start/end info now that it has been calculated
        self.stage = Main.stage_from_name(self.stage.stagename)
        if self.substages:
            self.policy_file = Main.get_config("policy_file", self.stage)
            self.regions_file = Main.get_config("regions_file", self.stage)
            self.substages_entrypoints = substage.SubstagesInfo.substages_entrypoints(self.policy_file)
        self._entrypoint = self.stage.entrypoint
        self._exitpoint = self.stage.exitpc
        # if self._stoppoint is None:
        #    self._stoppoint = self._exitpoint
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


class StartNextStage():
    def __init__(self, controller, stage):
        self.controller = controller
        self.stage = stage

    def __call__(self):
        cont = self.controller
        stage_index = cont.stage_order.index(self.stage)
        next_stage = cont.stage_order[stage_index + 1]
        cont.delete_stage_breakpoints(self.stage)
        print "starting next stage deleting breakpoing for %s" % self.stage.stagename
        cont.prepare_stage(next_stage, True)


class GDBBootController(gdb.Command):
    default_stage_hook = None
    default_finalize_hook = None
    default_bp_hooks = {}

    def __init__(self, name, bp_hooks=default_bp_hooks,
                 stage_hook=None,
                 f_hook=None,
                 exit_hook=None,
                 create_trace=False, open_dbs_ro=True,
                 disabled_breakpoints=[]):

        self.create_new_tracedb = create_trace
        self.open_dbs_ro = open_dbs_ro
        self.bp_hooks = {}
        self.disabled_breakpoints = disabled_breakpoints
        self.test_instance_name = None
        self.test_trace_name = None
        global breakpoint_classes
        for k in breakpoint_classes.iterkeys():
            if k in bp_hooks.iterkeys():
                self.bp_hooks[k] = bp_hooks[k]
            else:
                self.bp_hooks[k] = None
        self.name = name
        self.stage_hook = stage_hook
        self.f_hook = f_hook
        gdb.execute('set python print-stack full')
        self.cc = Main.cc
        gdb.execute("dir %s" % Main.get_bootloader_root())
        gdb.Command.__init__(self, name, gdb.COMMAND_DATA)
        self.parser = argparse.ArgumentParser(prog=name)
        self.subparser = self.parser.add_subparsers()
        self.cmds = []
        self.current_substage = 0
        self.current_substage_name = ""
        self.current_stage = None
        self._setup = False
        self.calculate_write_dst = False
        self.qemu_pid = None
        self.isbaremetal = False
        self.ia = staticanalysis.InstructionAnalyzer()
        #self.create_trace_table = False
        self._kill = False
        #self.disabledwritebreaks = False
        p = self.add_subcommand_parser('log')
        p.add_argument('logfile', default='', nargs='?')
        self.add_subcommand_parser('flushlog')
        #p.add_argument('pc')
        p = self.add_subcommand_parser('go')
        p.add_argument('-p', "--prepare_only", action='store_true', default=False)
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
        p = self.add_subcommand_parser('substages')
        p.add_argument('stage_name')
        p.add_argument('substages_name')
        p = self.add_subcommand_parser('kill')
        p.add_argument('do_kill', nargs='?', default=False)
        p = self.add_subcommand_parser("setup_target")
        p.add_argument('do_setup', nargs='?', default=True)
        self.stage_order = [Main.stage_from_name('spl')]  # default is spl stage only
        self._stages = {s.stagename: BootStageData(s, self.bp_hooks)
                        for s in Main.get_bootloader_cfg().supported_stages.itervalues()}
        self.exit_hook = exit_hook

    def gdb_exit(self, event):
        gdb.flush()
        if self.exit_hook:
            self.exit_hook(event)

    @staticmethod
    def _clsname(b):
        if isinstance(b, type):
            name = b.__name__
        else:
            name = b.__class__.__name__
        if '.' in name:
            name = name.split('.')[-1]

        return name

    def lookup_bp_hook(self, bp):
        name = self._clsname(bp)
        if name in self.bp_hooks.iterkeys():
            return self.bp_hooks[name]
        else:
            return None

    def test_instance(self, args):
        self.test_instance_name = args.name

    def test_trace(self, args):
        self.test_trace_name = args.name

    def setup_target(self, args):
        if args.do_setup is not True:
            self._setup = False
        else:
            self._setup = True

    def kill(self, args):
        if args.do_kill is not True:
            self._kill = True
        else:
            self._kill = False

    def get_instr_value(self, addr, thumb):
        size = 'w'
        val = (gdb.execute("x/1%sx 0x%x" % (size, addr), to_string=True).split(':'))[-1].strip()
        # strip off leading '0x'
        val = val[2:]
        val = val.decode('hex')
        # reverse bytes
        val = val[::-1]
        return val

    def get_reg_value(self, reg):
        return int(gdb.execute("print/x $%s" % reg, to_string=True).split()[2], 16)

    def get_breaks(self, cls):
        if not isinstance(cls, list):
            cls = [cls]
        return [b.companion for b in gdb.breakpoints()
                if hasattr(b, "companion") and any(map(lambda c: isinstance(b, c), cls))]

    def insert_breakpoints(self, stage):
        self.insert_write_breakpoints(stage)
        self.insert_reloc_breakpoints(stage)
        self.insert_longwrites_breakpoints(stage)
        self.insert_substagestart_breakpoints(stage)
        self.insert_stageend_breakpoints(stage)

    def insert_stageend_breakpoints(self, stage):
        s_info = self._stages[stage.stagename]
        end = s_info.stoppoint
        if end:
            s_info.endbreaks.append(StageEndBreak(end, self, stage, True))
        for (addr, line, success) in db_info.get(stage).stage_exits():
            s_info.endbreaks.append(StageEndBreak(addr, self, stage, success))

    def insert_substagestart_breakpoints(self, stage):
        if any(map(lambda x: issubclass(SubstageEntryBreak, x), self.disabled_breakpoints)):
            return
        sname = stage.stagename
        s_info = self._stages[sname]
        substages = s_info.substages_entrypoints
        self.current_substage_name = substages[0] if substages else ""
        for i in range(0, len(substages)):
            s = SubstageEntryBreak(substages[i], i, self, stage)

    def insert_longwrites_breakpoints(self, stage):
        if any(map(lambda x: issubclass(LongwriteBreak, x), self.disabled_breakpoints)):
            return
        for r in db_info.get(stage).longwrites_info():
            l = LongwriteBreak(self, r, stage)


    def insert_reloc_breakpoints(self, stage):
        if any(map(lambda x: issubclass(RelocBreak, x), self.disabled_breakpoints)):
            return
        for r in db_info.get(stage).reloc_info():
            RelocBreak(self, stage, r)

    def enable_write_breaks(self, stage, enable=True):
        name = stage.stagename
        sinfo = self._stages[name]
        for bp in gdb.breakpoints():
            b = bp.companion
            if isinstance(b, WriteBreak):
                b.breakpoint.enabled = enable
            elif isinstance(b, LongwriteBreak):
                b.breakpoint.enabled = enable

    def insert_write_breakpoints(self, stage):
        if any(map(lambda x: issubclass(WriteBreak, x), self.disabled_breakpoints)):
            return
        i = 0
        n = db_info.get(stage).num_writes()
        self.gdb_print("%d write breakpoints\n" % n)
        for (pc, halt) in db_info.get(stage).write_info():
            if halt is True:
                i = i + 1
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
                w = WriteBreak(pc, self, stage)

    def until(self, args):
        stagename = args.stage
        if not stagename:  # default is first stage
            if len(self.stage_order) < 1:
                self.gdb_print("no default stage to choose from, first add a stage ordering with 'stages' command\n")
                return
            else:
                stagename = self.stage_order[0].stagename
        if args.pc:
            pc = args.pc
        else:
            pc = self._stages[stagename]._exitpoint
        self._stages[stagename].stoppoint = pc

    def gdb_print(self, msg):
        gdb.write(msg, gdb.STDOUT)

    def substages(self, args):
        self._stages[args.stage_name].substages = args.substages_name

    def add_subcommand_parser(self, name):
        self.cmds.append(name)
        s = self.subparser.add_parser(name)
        s.add_argument(name, action='store_true')
        return s

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
        args = self.parser.parse_args(gdb.string_to_argv(arg))
        for c in self.cmds:
            if hasattr(args, c) and (getattr(args, c) is True):
                getattr(self, c)(args)
                return
        self.gdb_print("unknown command %s\n" % arg)

    def enable_current_stage_write_breaks(self, enable=True):
        self.enable_write_breaks(self.current_stage, enable)

    def enable_current_stage_end_break(self, enable=True):
        for e in self._stages[self.current_stage.stagename].endbreaks:
            e.breakpoint.enabled = enable

    def prepare_stage(self, stage, cont=False):
        self.current_stage = stage
        if cont:
            s = StageStartBreak(self, stage)
            s.breakpoint.enabled = False
            s.continue_stage()
        else:
            StageStartBreak(self, stage)

    def finalize(self, args):
        substage_names = {s.stagename: self._stages[s.stagename].substages
                          for s in self.stage_order if self._stages[s.stagename].substages is not None}
        stages = [s.stagename for s in self.stage_order]
        d = doit_manager.TaskManager(False, False, stages,
                                     substage_names, False, False, self.test_trace_name,
                                     False,
                                     [], self.test_instance_name)
        if len(self.stage_order) == 0:
            self.stage_order = [Main.stage_from_name(s) for s in list(self._stages.iterkeys())]
        for stage in self.stage_order:
            s = self._stages[stage.stagename]
            s.init_with_test_instance()
        if self.f_hook:
            self.f_hook(args)

    def delete_stage_breakpoints(self, stage):
        global breakpoint_classes

        for b in self.get_breaks(list(breakpoint_classes.itervalues())):
            if b.stage == stage:
                b.breakpoint.enabled = False
                if not isinstance(b, StageEndBreak):
                    gdb.post_event(b.breakpoint.delete)

    def go(self, args):
        self.finalize(args)
        stage = self.stage_order[0]
        gdb.events.exited.connect(self.gdb_exit)
        self.prepare_stage(stage, False)
        self.gdb_print("%s plugin is ready to go\n" % self.name)
        if not args.prepare_only:
            gdb.execute("c")


class CompanionBreakpoint(gdb.Breakpoint):
    def __init__(self, spec, twin):
        self._stop = twin.stop
        self.companion = twin
        gdb.Breakpoint.__init__(self, spec, internal=True)

    def stop(self):
        return self._stop()


class BootBreak():
    __metaclass__ = BreakpointRegistrar

    def __init__(self, spec, controller, needs_relocation, stage, **kwargs):
        self.stage = stage
        self.addr = -1
        self.relocated = 0
        self.needs_relocation = needs_relocation
        if 'r' in kwargs.iterkeys():
            for f in kwargs['r'].iterkeys():
                setattr(self, f, kwargs['r'][f])
        self.controller = controller
        self.stophook = self.controller.lookup_bp_hook(self)
        self.final_event = None
        for (k, v) in kwargs.iteritems():
                setattr(self, k, v)
        if not isinstance(spec, str):
            self.addr = spec
            spec = "*(0x%x)" % spec
        else:
            i = ""
            if spec.startswith("*"):
                i = re.sub("[()*]+", "", spec)
            else:
                try:
                    i = gdb.execute("x/x %s" % spec, to_string=True).split(":")[0]
                except gdb.error as e:
                    print e
                    return
            self.addr = long(i, 0)
        self.breakpoint = CompanionBreakpoint(spec, self)
        if any(map(lambda x: isinstance(self, x), controller.disabled_breakpoints)):
            self.breakpoint.enabled = False
            gdb.post_event(self.breakpoint.delete)
            #self.breakpoint.delete()

    def move(self, offset, mod, delorig=False):
        if self.needs_relocation:
            if self.breakpoint.location.startswith("*"):
                l = re.sub("[()*]+", "", self.breakpoint.location)
                lpc = long(l, 0)
                self.addr = (lpc + offset) % mod
            else:
                self.addr = (self.addr + offset) % mod
            spec = "*(0x%x)" % self.addr
            self.relocated = offset
            self.breakpoint.enabled = False
            if delorig:
                gdb.post_event(self.breakpoint.delete)
                #self.breakpoint.delete()
                self.breakpoint = None
            self.breakpoint = CompanionBreakpoint(spec, self)
            # if any(map(lambda x: isinstance(self, x), self.controller.disabled_breakpoints)):
            #     if self.breakpoint:
            #         self.breakpoint.enabled = False
            #         self.breakpoint.delete()

            if hasattr(self, '_move'):
                self._move(offset, mod, delorig)

    def msg(self, m):
        self.controller.gdb_print(m)

    def stop(self):
        ret = False
        if hasattr(self, '_stop'):
            ret = self._stop(ret)

        if self.stophook:
            ret = self.stophook(self, ret)
        if self.final_event:
            self.final_event()
            self.final_event = None
        return ret


class BootFinishBreakpoint(gdb.FinishBreakpoint, BootBreak):
    def __init__(self,  controller, needs_relocation, stage, **kwargs):
        self.stage = stage
        self.needs_relocation = needs_relocation
        self.controller = controller
        self.stophook = self.controller.lookup_bp_hook(self)
        self.final_event = None
        for (k, v) in kwargs.iteritems():
            setattr(self, k, v)

        gdb.FinishBreakpoint.__init__(self, internal=True)

    def stop(self):
        if hasattr(self, '_stop'):
            self._stop()
        gdb.post_event(self.delete)


class WriteBreak(BootBreak):
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

        BootBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, ret):
        cont = self.controller
        if cont.calculate_write_dst:
            self.writeinfo = self.emptywrite
            pc = cont.get_reg_value('pc')
            inspc = pc - self.relocated
            cpsr = cont.get_reg_value("cpsr")
            thumb = cont.ia.is_thumb(cpsr)
            i = cont.get_instr_value(pc, thumb)
            ins = cont.ia.disasm(i, thumb, inspc, True)
            row = db_info.get(self.stage).pc_writes_info(inspc)
            size = row['writesize']
            needed_regs = [row['reg0'], row['reg1'], row['reg2'], row['reg3']]
            regs = []
            for r in filter(lambda x: len(x) > 0, needed_regs):
                regs.append(cont.get_reg_value(r))
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
        return ret


class SubstageEntryBreak(BootBreak):
    def __init__(self, fnname, substagenum, controller, stage):
        self.fnname = fnname
        self.substagenum = substagenum
        self.controller = controller
        self.fnloc = int(gdb.execute("x/x %s" % self.fnname, to_string=True).split()[0], 0)
        spec = "*(0x%x)" % self.fnloc
        BootBreak.__init__(self, spec, controller, True, stage)

    def _stop(self, ret):
        self.controller.current_substage = self.substagenum
        self.controller.current_substage_name = self.fnname
        #self.breakpoint.delete()
        #gdb.post_event(self.delete)
        return ret


class StageStartBreak(BootBreak):
    def __init__(self, controller, stage):
        realstart = controller._stages[stage.stagename]._startpoint
        if not isinstance(realstart, str):
            spec = "*(0x%x)" % realstart
        else:
            spec = realstart
        controller.gdb_print("StartStageBreak %s at %s ...\n" % (stage.stagename, spec))
        BootBreak.__init__(self, spec, controller, True, stage)

    def continue_stage(self):
        cont = self.controller
        if not gdb.current_progspace().filename:
            elf = Main.get_config("stage_elf", self.stage)
            gdb.execute("file %s" % elf)
            cont.gdb_print('loaded file %s\n' % elf)
        cont.gdb_print("Inserting breakpoints for %s %s ...\n" % (self.controller.name,
                                                                  self.stage.stagename))
        cont.current_substage = 0
        cont.insert_breakpoints(self.stage)
        cont.gdb_print("Done setting breakpoints\n")
        index = cont.stage_order.index(self.stage)
        if self.controller.stage_hook:
            self.controller.stage_hook(self.stage)
        #self.breakpoint.delete()

    def _stop(self, ret):
        self.continue_stage()
        return False


class StageEndBreak(BootBreak):
    def __init__(self, spec, controller, stage, success):
        self.addr = spec
        self.stage = stage
        self.starttime = time.time()
        if not isinstance(spec, str):
            spec = "*(0x%x)" % spec
        BootBreak.__init__(self, spec, controller, True, stage, success=success)

    def _stop(self, ret):
        cont = self.controller
        self.msg("HIT END BREAKPOINT AT 0x%x\n" %
                 cont.get_reg_value("pc"))
        now = time.time()
        self.msg("This took %f minutes to run\n" % ((now-self.starttime)/60))
        stage_index = cont.stage_order.index(self.stage)

        if stage_index >= len(cont.stage_order) - 1:
            ret = True
            # if cont._kill:
            #     gdb.execute("monitor quit")
        else:
            ret = False
            self.final_event = StartNextStage(cont, self.stage)
        return ret


class EndLongwriteBreak(BootBreak):
    def __init__(self, lwbreak, stage):
        self.stage = stage
        controller = lwbreak.controller
        self.addr = lwbreak.contaddr
        spec = "*(0x%x)" % self.addr if not isinstance(self.addr, str) else self.addr
        lwbreak.breakpoint.enabled = False
        BootBreak.__init__(self, spec, controller, False, stage, lwbreak=lwbreak)

    def _stop(self, ret):
        self.lwbreak.breakpoint.enabled = True
        self.breakpoint.enabled = False
        #self.breakpoint.delete()
        gdb.post_event(self.breakpoint.delete)
        return ret


class LongwriteBreak(BootBreak):
    def __init__(self, controller, r, stage):
        self.regs = {}
        self.sregs = r['sregs']
        self.eeregs = r['eregs']

        self.emptywrite = {'start': None,
                           'end': None,
                           'pc': None}
        self.writeinfo = self.emptywrite

        spec = "*(0x%x)" % r['breakaddr']
        BootBreak.__init__(self, spec, controller, True, stage, r=r)

    def _stop(self, ret):
        if self.controller.calculate_write_dst:
            self.writeinfo = self.emptywrite
            regs = {}
            eregs = []
            for r in self.sregs:
                v = self.controller.get_reg_value(r)
                regs.update({r: v})
            for r in self.eeregs:
                regs.update({r: self.controller.get_reg_value(r)})
                eregs.append(v)
            if not self.destsubtract == "":
                regs.update({self.destsubtract: self.controller.get_reg_value(self.destsubtract)})

            needs_string = db_info.get(self.stage).is_longwrite_string(self.rangetype)
            str2 = None
            if needs_string:
                self.msg("getting string at 0x%x\n" % sum(eregs))
                str2 = gdb.execute("print/s (char *) $%s" % eregs[0], to_string=True)
                str2 = str2.split("\"")[1]
                self.msg("string %s\n" % str2)
            (self.writeinfo['start'],
             self.writeinfo['end']) = db_info.get(self.stage).longwrites_calculate_dest_addrs(
                 self.r,
                 self.rangetype,
                 regs,
                 self.sregs,
                 self.eeregs,
                 str2)
            self.writeinfo['pc'] = self.writeaddr
            EndLongwriteBreak(self, self.stage)
        return ret

    def _move(self, offset, mod, d):
        self.breakaddr = (self.breakaddr + offset) % mod
        self.writeaddr = (self.writeaddr + offset) % mod
        self.contaddr = (self.contaddr + offset) % mod


class RelocBreak(BootBreak):
    def __init__(self, controller, stage, r):
        self.relocpc = r['relocpc']
        spec = "*(0x%x)" % (self.relocpc)
        self.reldelorig = r['reldelorig']
        BootBreak.__init__(self, spec, controller, False, stage, r=r)

    def addr_in_reloc_range(self, breakaddr):
        return (self.startaddr <= breakaddr) and (breakaddr < (self.startaddr + self.size))

    def _stop(self, ret):
        # disable this breakpoint
        #self.breakpoint.enabled = False
        self.msg("relocating breakpoints\n")
        controller = self.controller
        for bp in gdb.breakpoints():
            if isinstance(bp, CompanionBreakpoint):
                b = bp.companion
                if self.addr_in_reloc_range(b.addr):
                    b.move(self.reloffset, self.relmod, True) #self.reldelorig)
            else:
                continue
        # make sure final breakpoint is still enabled
        controller.enable_current_stage_end_break()

        self.msg("continuing execution\n")
        self.breakpoint.enabled = False
        #self.breakpoint.delete()
        #self.breakpoint.delete()
        #gdb.post_event(self.delete)
        return ret
