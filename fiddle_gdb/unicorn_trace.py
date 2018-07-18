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
now = True
stepnum = 0
start = time.time()


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
        self.stacktop = None
        self.stackbot = None
        self.syscall_regnames = []

    def get_syscall_regnames(self, emu):
        return self.syscall_regnames

    def get_stack_position(self, emu):
        top = emu.reg_read(self.get_reg_id(self.stacktop))
        bottom = emu.reg_read(self.get_reg_id(self.stackbot))
        return (top, bottom)

    def get_reg_id(self, name):
        return self.val_info.get_reg_name_val(name)

    def _syscall_wrapper(self, emu, hook):
        if self.syscall_hook:
            return self.syscall_hook()
        return True

    def hook_syscall(self, emu, hook):
        self.syscall_hook = hook
        emu.hook_add(unicorn.UC_HOOK_INTR,
                     self._syscall_wrapper)

    def is_exit_syscall(self, emu):
        return False


class X86Emulator(Emulator):
        def __init__(self):
            Emulator.__init__(self, "X86",
                              unicorn.UC_ARCH_X86, unicorn.UC_MODE_32,
                              "eip",
                              32,
                              ["esp"])


class X86_64Emulator(Emulator):
        def __init__(self):
            Emulator.__init__(self, "X86",
                              unicorn.UC_ARCH_X86,
                              unicorn.UC_MODE_64,
                              "rip",
                              64,
                              ["rsp", "cs", "ss", "bx", "si", "ip"])
            self.syscall_regnames = ["rdi", "rsi", "rcx", "r8", "rdx",
                                     "r9", "rbx", "rax", "rbp", "rsp"]
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
            return emu.reg_read(self.get_reg_id("eax")) in [60, 231]


class Aarch64Emulator(Emulator):
        def __init__(self):
            Emulator.__init__(self, "ARM",
                              unicorn.UC_ARCH_ARM64,
                              unicorn.UC_MODE_ARM,
                              "pc",
                              64,
                              ["sp"])


class ArmEmulator(Emulator):
        def __init__(self):
            Emulator.__init__(self, "ARM",
                              unicorn.UC_ARCH_ARM,
                              unicorn.UC_MODE_ARM,
                              "pc",
                              32,
                              ["sp"])


class Unicorn(gdb_tools.GDBPlugin):

    def __init__(self):
        parser_options = [
            gdb_tools.GDBPluginParser("enforce",
                                      [gdb_tools.GDBPluginParserArg("disabled",
                                                                    nargs="?", default=False)])
        ]
        disabled = ["LongwriteBreak", "WriteBreak", "TargetFinishBreakpoint",
                    "ReturnBreak", "SubstageEntryBreak", "SubstageStartBreak", "StageEndBreak"]

        bp_hooks = {}
        gdb_tools.GDBPlugin.__init__(self, "unicorn", bp_hooks,
                                     f_hook=self.f_hook,
                                     disabled_breakpoints=disabled,
                                     parser_args=parser_options)

    def enforce(self, args):
        if args.disabled is False:
            self._enforce = False
        else:
            self._enforce = True

    def create_emulator(self):
        o = Main.shell.run_cmd("%sreadelf -h %s| grep Machine" % (Main.cc, self.stage.elf))
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

    def setup_emulator(self):
        gdb.execute("break *%s" % self.stage.entrypoint, to_string=True)
        gdb.execute("r")
        mappings = gdb.execute("info proc mappings", to_string=True)
        inf = gdb.selected_inferior()
        for m in mappings.split("\n"):
            m = m.strip()
            if not m.startswith("0x"):
                continue
            m = m.split()
            start = long(m[0], 0)
            end = long(m[1], 0)
            size = long(m[2], 0)
            #print "%x, %x" % (start, start+len(bs))
            self.emu.mem_map(start, size, unicorn.UC_PROT_ALL)
            # copy current values of memory
            try:
                bs = inf.read_memory(start, size)
            except gdb.MemoryError:
                bs = "\0" * size
            self.emu.mem_write(start, b"%s" % bs)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,
                          self.write_hook)
        self.emu.hook_add(unicorn.UC_HOOK_CODE,
                          self.i_hook)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED |
                          unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,
                            self.hook_mem_invalid)
        self.machine.hook_syscall(self.emu, self.hook_syscall)

        # init register values
        for r in self.machine.initregs:
            regval = self.controller.get_reg_value(r, True)
            regnum = self.machine.get_reg_id(r)
            print "setting reg %s to %x" % (r, regval)
            self.emu.reg_write(regnum, regval)

    def hook_syscall(self, emu, user_data):
        self.controller.gdb_print("syscall %d\n" %
                                  emu.reg_read(self.machine.get_reg_id("eax")))
        if self.machine.is_exit_syscall(emu):
            return False

        pc = self.emu.reg_read(self.machine.pc)
        (stack_top, stack_bottom) = self.machine.get_stack_position(emu)
        # if stack_bottom is not properly set, just copy in a page of the stack
        if stack_bottom < stack_top:
            stack_bottom = stack_top + 1024
        reg_names = self.machine.get_syscall_regnames(emu)

        # update value of gdb's registers from emu's value
        for r in reg_names:
            val = emu.reg_read(self.machine.get_reg_id(r))
            gdb.execute("set $%s = 0x%x" % (r, val), to_string=True)

        # copy stack frame from emu to gdb
        frame = self.emu.mem_read(long(stack_top), long(stack_bottom - stack_top))
        inf = gdb.selected_inferior()
        inf.write_memory(stack_top, b"%s" % frame)

        # instruct gdb to exec instruction at pc
        gdb.execute("set $%s = 0x%x" % (self.machine.pc_name, pc), to_string=True)
        gdb.execute("si")

        # copy reg values (results) from gdb to emu
        for r in reg_names:
            val = self.controller.get_reg_value(r, True)
            emu.reg_write(self.machine.get_reg_id(r), val)

        # copy stack frame from gdb to emu
        frame = inf.read_memory(stack_top, stack_bottom - stack_top)
        emu.mem_write(stack_top, b"%s" % frame)

    def i_hook(self, emu, addr, size, u):
        if self.substage_num < (len(self.substage_entries) - 1):
            if addr == self.substage_entries[self.substage_num+1]:
                self.substage_num += 1
                s = emu.mem_read(addr, size)

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
            print(">>> Missing memory  at 0x%x, data size = %u, data value = 0x%x" \
                  %(address, size, value))
            # return False to indicate we want to stop emulation
            return False

    def write_hook(self, emu, access, addr, size, value, data):
        cspr = 0
        lr = 0
        pc = emu.reg_read(self.machine.pc)
        global stepnum
        t = time.time()
        gdb.post_event(hook_write.WriteDatabase(t,
                                                0,
                                                size,
                                                addr,
                                                pc,
                                                lr,
                                                cspr,
                                                stepnum,
                                                pc,
                                                self.stage,
                                                self.substage_num,
                                                "",
                                                True))
        stepnum += 1

    def f_hook(self, args):
        self.stage = self.controller.stage_order[0]
        self.substage_num = 0
        self.substage_entries = [utils.get_symbol_location(sub, self.stage)
                                 for sub in
                                 self.controller._stages[self.stage.stagename].substages_entrypoints]

        # print map(lambda x: "%x" % x, self.substage_entries)
        db_info.create(self.stage, "tracedb")
        self.create_emulator()
        self.setup_emulator()
        print "Starting emulation until %x" % self.stage.exitpc
        self.emu.emu_start(long(self.stage.entrypoint, 0),
                           self.stage.exitpc)
        global start
        gdb.flush()
        db_info.get(self.stage).flush_tracedb()
        gdb.post_event(hook_write.FlushDatabase(self.stage, True))
        db_info.get(self.stage).update_static_entries()



plugin_config = Unicorn()
