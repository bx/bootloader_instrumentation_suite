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
import unicorn
from config import Main
import hook_write
import unicorn_utils
import binascii
import testsuite_utils as utils
import r2_keeper as r2
now = True
start = time.time()


class Mapping():
    def __init__(self, start, end, size=None, s=""):
        self.start = start
        self.end = end
        if size is None:
            self.size = self.end - self.start
        else:
            self.size = size
        self.s = s


class Emulator():
    def __init__(self, name, arch, mode, pc_name, bits, initregs):
        self.name = name
        self.arch = arch
        self.mode = mode
        self.pc_name = pc_name
        self.val_info = unicorn_utils.UnicornCPU(self.name)
        self.pc = self.get_reg_id(pc_name)
        self.bits = bits
        self.initregs = initregs
        self.syscall_hook = None
        self.syscall_mnus = ["syscall", "svc", "int"]
        self.stacktop = None
        self.stackbot = None
        self.syscall_regnames = []

    def get_syscall_regnames(self, emu):
        return self.syscall_regnames

    def get_stack_position(self, emu):
        top = emu.reg_read(self.get_reg_id(self.stacktop))
        bottom = emu.reg_read(self.get_reg_id(self.stackbot))
        return (top, bottom)

    def write_memory(self, start, buffer):
        inf = gdb.selected_inferior()
        inf.write_memory(start, b"%s" % buffer)

    def read_memory(self, start, size):
        inf = gdb.selected_inferior()
        try:
            bs = inf.read_memory(start, size)
        except gdb.MemoryError:
            bs = "\0" * size
        return b"%s" % bs

    def get_reg_id(self, name):
        return self.val_info.get_reg_name_val(name)

    def _syscall_wrapper(self, emu, intnum, user=None):
        if self.syscall_hook:
            return self.syscall_hook(emu, user)

    def hook_syscall(self, emu, hook):
        self.syscall_hook = hook
        emu.hook_add(unicorn.UC_HOOK_INTR,
                     self._syscall_wrapper)

    def is_exit_syscall(self, emu):
        return False

    def get_mappings(self):
        mlist = []
        mappings = gdb.execute("info proc mappings", to_string=True)
        mappings = mappings.split("\n")
        if len(mappings) == 1: # then try to get gdb target's mappings
            th = gdb.selected_thread()
            (tpid, pid, id3) = th.ptid
            if pid > 1:
                maps = "/proc/%d/maps" % pid
                mlist = []
                with open(maps, "r") as mmap:
                    for m in mmap:
                        fields = m.split()
                        (lo, hi) = fields[0].split("-")
                        s = fields[-1]
                        mlist.append(Mapping(long(lo, 16), long(hi, 16), s=s))
                return mlist
            else:
                raise Exception("Unicorn does not support this setup")
        else: # get mappings directly from gdb
            for m in mappings:
                m = m.strip()
                if not m.startswith("0x"):
                    continue
                m = m.split()
                start = long(m[0], 0)
                end = long(m[1], 0)
                size = long(m[2], 0)
                mlist.append(Mapping(start, end, size, m[3]))
            return mlist


class X86Emulator(Emulator):
    def __init__(self):
        Emulator.__init__(self, "X86",
                          unicorn.UC_ARCH_X86, unicorn.UC_MODE_32,
                          "eip",
                          32,
                          ["esp", "eip", "gs", "fs", "ds"
                           ])
        # "ss", "cs", "ds", "es",

        self.syscall_regnames = ["edi", "esi", "ecx", "edx",
                                 "ebx", "eax", "ebp", "esp"]
        self.stackbot = "ebp"
        self.stacktop = "esp"

    def _syscall_wrapper(self, emu, hook):
        if self.syscall_hook:
            return self.syscall_hook(emu, hook)

    def hook_syscall(self, emu, hook):
        self.syscall_hook = hook
        emu.hook_add(unicorn.UC_HOOK_INSN,
                     self._syscall_wrapper,
                     arg1=unicorn.x86_const.UC_X86_INS_SYSCALL)

    def is_exit_syscall(self, emu):
        return emu.reg_read(self.get_reg_id("eax")) in [60, 231]


class X86_64Emulator(Emulator):
    def __init__(self):
        Emulator.__init__(self, "X86",
                          unicorn.UC_ARCH_X86,
                          unicorn.UC_MODE_64,
                          "rip",
                          64,
                          ["rsp", "cs", "ss", "rbx", "si", "ip"])
        self.syscall_regnames = ["rdi", "rsi", "rcx", "r8", "rdx",
                                 "r9", "rbx", "rax"]
        self.stackbot = "rbp"
        self.stacktop = "rsp"

    def _syscall_wrapper(self, emu, hook):
        if self.syscall_hook:
            return self.syscall_hook(emu, hook)

    def hook_syscall(self, emu, hook):
        self.syscall_hook = hook
        emu.hook_add(unicorn.UC_HOOK_INSN,
                     self._syscall_wrapper,
                     arg1=unicorn.x86_const.UC_X86_INS_SYSCALL)

    def is_exit_syscall(self, emu):
        return emu.reg_read(self.get_reg_id("rax")) in [60, 231]


class Aarch64Emulator(Emulator):
    def __init__(self):
        Emulator.__init__(self, "ARM64",
                          unicorn.UC_ARCH_ARM64,
                          unicorn.UC_MODE_ARM,
                          "pc",
                          64,
                          ["sp", "cpsr"])
        self.syscall_regnames = map(lambda x: "x%d" % x, range(0, 8)) + ["x8",
                                                                         "pc"]
        self.stackbot = "fp"
        self.stacktop = "sp"
        self.syscall_reg = "x8"

    def _syscall_wrapper(self, emu, callnum, user=None):
        if self.syscall_hook:
            return self.syscall_hook(emu, user)

    def is_exit_syscall(self, emu):
        return emu.reg_read(self.get_reg_id(self.syscall_reg)) in [93, 94]

    def get_reg_id(self, name):
        if name == "cpsr":
            return 3
        else:
            return self.val_info.get_reg_name_val(name)


class ArmEmulator(Aarch64Emulator):
    def __init__(self):
        Emulator.__init__(self, "ARM",
                          unicorn.UC_ARCH_ARM,
                          unicorn.UC_MODE_ARM,
                          "pc",
                          32,
                          ["sp", "cpsr"])
        self.syscall_regnames = map(lambda x: "x%d" % x, range(0, 8)) + ["x7",
                                                                         "pc"]
        self.stackbot = "fp"
        self.stacktop = "sp"
        self.syscall_reg = "x7"


class Unicorn(gdb_tools.GDBPlugin):

    def __init__(self):
        parser_options = [
            gdb_tools.GDBPluginParser("enforce",
                                      [gdb_tools.GDBPluginParserArg("disabled",
                                                                    nargs="?",
                                                                    default=False)]),
            gdb_tools.GDBPluginParser("no_run",
                                      [gdb_tools.GDBPluginParserArg("disabled",
                                                                    nargs="?",
                                                                    default=True)])


        ]
        disabled = ["LongwriteBreak", "WriteBreak", "TargetFinishBreakpoint",
                    "ReturnBreak", "SubstageEntryBreak", "SubstageStartBreak",
                    "StageEndBreak"]

        bp_hooks = {'StageStartBreak': self.stage_start_hook}
        gdb_tools.GDBPlugin.__init__(self, "unicorn", bp_hooks,
                                     f_hook=self.f_init,
                                     disabled_breakpoints=disabled,
                                     parser_args=parser_options)
        self._enforce = False
        self._no_run = False

    def enforce(self, args):
        if args.disabled is False:
            self._enforce = False
        else:
            self._enforce = True

    def no_run(self, args):
        if args.disabled is False:
            self._no_run = False
        else:
            self._no_run = True

    def create_emulator(self):
        o = Main.shell.run_cmd("%sreadelf -h %s| grep Machine" % (Main.cc,
                                                                  self.stage.elf))
        machine = o.split(" ", 2)[-1].strip()
        ms = {
            "ARM": ArmEmulator(),
            "AArch64": Aarch64Emulator(),
            "Advanced Micro Devices X86-64": X86_64Emulator(),
            "Intel 80386": X86Emulator()
        }
        self.machine = ms[machine]
        self.emu = unicorn.Uc(self.machine.arch,
                              self.machine.mode)
        self.stop = False

    def setup_emulator(self):
        # init register values
        for r in self.machine.initregs:
            regval = self.controller.get_reg_value(r, True)
            regnum = self.machine.get_reg_id(r)
            self.emu.reg_write(regnum, regval)

        mappings = self.machine.get_mappings()
        for m in mappings:
            self.emu.mem_map(m.start, m.size, unicorn.UC_PROT_ALL)
            bs = self.machine.read_memory(m.start, m.size)
            self.emu.mem_write(m.start, bs)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,
                          self.write_hook)
        self.emu.hook_add(unicorn.UC_HOOK_CODE,
                          self.i_hook)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED |
                          unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,
                            self.hook_mem_invalid)
        self.machine.hook_syscall(self.emu, self.hook_syscall)

    def hook_syscall(self, emu, user_data):
        if self.machine.is_exit_syscall(emu) or self.stop:
            self.stop = True
            emu.emu_stop()
            return False
        pc = emu.reg_read(self.machine.pc)
        print "syscall @ 0x%x" % pc
        orig_pc = pc
        # make sure PC points to syscall instruction
        r2.gets(self.stage.elf, "s 0x%x" % pc)
        i = r2.get(self.stage.elf, "pdj 1")[0]
        dis = i['disasm'].split()[0].lower()
        if dis not in self.machine.syscall_mnus:
            # try previous
            i2 = r2.get(self.stage.elf, "pdj -1")[0]
            dis = i2['disasm'].split()[0].lower()
            if dis not in self.machine.syscall_mnus:
                print "issue finding system call instruction near or after %x" % pc
                print (map(lambda x: "%s %x" % (x, emu.reg_read(self.machine.get_reg_id(x))),
                           ["ip0", "ip1", "lr"]))
                # emu.reg_write(self.machine.pc, pc)
                # emu.reg_write(self.machine.pc, pc)
                # i3 = r2.get(self.stage.elf, "pdj 2")[1]
                # emu.reg_write(self.machine.pc, orig_pc + i["size"])
                # exit(1)
                # emu.reg_write(self.machine.pc, i3["offset"])

                # there seems to be a bug in unicorn where
                # the pc read at this point doesn't point to the svc instr
                exit(1)
                return False
            else:
                pc = i2["offset"]
        (stack_top, stack_bottom) = self.machine.get_stack_position(emu)

        # if stack_bottom is not properly set, just copy in a page of the stack
        if stack_bottom <= stack_top:
            stack_bottom = stack_top + 1024
        reg_names = self.machine.get_syscall_regnames(emu)

        # update value of gdb's registers from emu's value
        for r in reg_names:
            val = emu.reg_read(self.machine.get_reg_id(r))
            try:
                gdb.execute("set $%s = 0x%x" % (r, val), to_string=True)
            except gdb.error as e:
                print e
                #exit(0)

        # copy stack frame from emu to gdb
        frame = emu.mem_read(long(stack_top), long(stack_bottom - stack_top))
        self.machine.write_memory(stack_top, b"%s" % frame)

        # instruct gdb to exec instruction at pc
        gdb.execute("set $%s = 0x%x" % (self.machine.pc_name, pc), to_string=True)
        gdb.execute("x/2i $pc")
        gdb.execute("si")

        # copy reg values (results) from gdb to emu
        for r in reg_names:
            val = self.controller.get_reg_value(r, True)
            emu.reg_write(self.machine.get_reg_id(r), val)

        # copy stack frame from gdb to emu
        frame = self.machine.read_memory(stack_top, stack_bottom - stack_top)
        emu.mem_write(stack_top, frame)

        return True

    def i_hook(self, emu, addr, size, u):
        if self.stop:
            emu.emu_stop()
            return False

        if self.substage_num < (len(self.substage_entries) - 1):
            if addr == self.substage_entries[self.substage_num+1]:
                self.substage_num += 1
                print "entered stage %s" % self.substage_num
        return True

    def hook_mem_invalid(self, emu, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE_UNMAPPED:
            pc = emu.reg_read(self.machine.pc)
            print(">>> Missing memory is being WRITE at 0x%x, data size = %u, "
                  "data value = 0x%x by %x"
                  % (address, size, value, pc))
            # map a page a memory here
            kb = 4*1024
            emu.mem_map((address/kb)*kb, kb)

            # write it anyway (https://github.com/unicorn-engine/unicorn/blob/fb4dc10fe96067b3338cf362d3a27eb1199e0308/tests/regress/init.py#L43)
            emu.mem_write(address, str(value))
            # return True to indicate we want to continue emulation
            return True
        else:
            print(">>> Missing memory  at 0x%x, data size = %u, data value = 0x%x"
                  % (address, size, value))
            # return False to indicate we want to stop emulation
            return False

    def write_hook(self, emu, access, addr, size, value, data):
        cspr = 0
        lr = 0
        pc = emu.reg_read(self.machine.pc)
        t = time.time()
        if (pc == 0x408125):
            print locals()
            print self.emu.__dict__
            print dir(self.emu)
            raise Exception
        gdb.post_event(hook_write.WriteDatabase(t,
                                                0,
                                                size,
                                                addr,
                                                pc,
                                                lr,
                                                cspr,
                                                pc,
                                                self.stage,
                                                self.substage_num,
                                                "",
                                                True))

    def init(self):
        self.stage = self.controller.stage_order[0]
        self.substage_num = 0
        self.substage_entries = [utils.get_symbol_location(sub, self.stage)
                                 for sub in
                                 self.controller._stages[self.stage.stagename].substages_entrypoints]
        db_info.create(self.stage, "tracedb")
        self.create_emulator()
        self.setup_emulator()
        self.emu.emu_start(long(self.stage.entrypoint, 0),
                           self.stage.exitpc)
        global start
        gdb.flush()
        db_info.get(self.stage).flush_tracedb()
        gdb.post_event(hook_write.FlushDatabase(self.stage, True))
        db_info.get(self.stage).update_static_entries()

    def f_init(self, args):
        if self._no_run:
            stage = self.controller.stage_order[0]
            gdb.execute("break *%s" % stage.entrypoint, to_string=True)
            gdb.execute("r")
            self.init()

    def stage_start_hook(self, bp, ret):
        bp.cont = False
        if not self._no_run:
            self.init()
            print "init"
        return False


plugin_config = Unicorn()
