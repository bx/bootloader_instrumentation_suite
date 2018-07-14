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
now = True
stepnum = 0
start = time.time()


class Unicorn(gdb_tools.GDBPlugin):

    def __init__(self):
        parser_options = [
        ]
        disabled = ["LongwriteBreak", "WriteBreak", "TargetFinishBreakpoint",
                    "ReturnBreak", "SubstageEntryBreak", "SubstageStartBreak", "StageEndBreak"]

        bp_hooks = {}
        gdb_tools.GDBPlugin.__init__(self, "unicorn", bp_hooks,
                                     f_hook=self.f_hook,
                                     disabled_breakpoints=disabled,
                                     parser_args=parser_options)

    def create_emulator(self):
        o = Main.shell.run_cmd("%sreadelf -h %s| grep Machine" % (Main.cc, self.stage.elf))
        machine = o.split(" ", 2)[-1].strip()
        ms = {
            "ARM": (unicorn.UC_ARCH_ARM,
                    unicorn.UC_MODE_ARM,
                    unicorn.arm_const.UC_ARM_REG_PC,
                    "ARM", ["sp"]),
            "AArch64": (unicorn.UC_ARCH_ARM64,
                        unicorn.UC_MODE_ARM,
                        unicorn.arm64_const.UC_ARM64_REG_PC,
                        "ARM", ["sp"]),
            "Advanced Micro Devices X86-64": (unicorn.UC_ARCH_X86,
                                              unicorn.UC_MODE_64,
                                              unicorn.x86_const.UC_X86_REG_RIP,
                                              "X86", ["rsp", "cs", "ss", "bx", "si", "ip"]),
            "Intel 80386": (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32,
                            unicorn.x86_const.UC_X86_REG_EIP, "X86",
                            ["esp"])
            }
        (ua, um, pc, cpuname, initregs) = ms[machine]
        self.cpuname = cpuname
        self.initregs = initregs
        self.pc_reg = pc
        self.max = max
        self.emu = unicorn.Uc(ua, um)

    def setup_emulator(self):
        gdb.execute("break *%s" % self.stage.entrypoint)
        gdb.execute("r")
        mappings = gdb.execute("info proc mappings", to_string=True)
        inf = gdb.selected_inferior()
        for m in mappings.split("\n"):
            m = m.strip()
            if not m.startswith("0x"):
                continue
            m = m.split()
            start = int(m[0], 0)
            end = int(m[1], 0)
            size = int(m[2], 0)
            self.emu.mem_map(start, size, unicorn.UC_PROT_ALL)
            # copy current values of memory
            try:
                bs = inf.read_memory(start, size)
            except gdb.MemoryError:
                bs = "\0" * size
            #print "%x, %x" % (start, start+len(bs))
            self.emu.mem_write(start, b"%s" % bs)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_WRITE,
                          self.write_hook)
        #self.emu.hook_add(unicorn.UC_HOOK_MEM_READ,
        #                  self.read_hook)
        #self.emu.hook_add(unicorn.UC_HOOK_CODE,
        #              self.i_hook)
        self.emu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED,
                            self.hook_mem_invalid)

        # init register values
        for r in self.initregs:
            regval = self.controller.get_reg_value(r, True)
            regnum = unicorn_utils.reg_val_of(self.cpuname, r)
            #print "setting reg %s to %x" % (r, regval)
            self.emu.reg_write(regnum, regval)

    def i_hook(self, emu, addr, size, u):
        s = emu.mem_read(addr, size)
        print "%x--%s" % (addr, binascii.hexlify(s))

    def read_hook(self, emu, access, addr, size, value, data):
        print "read %x (%s)" % (addr, size)

    def hook_mem_invalid(self, emu, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_WRITE_UNMAPPED:
            pc = emu.reg_read(self.pc_reg)
            #print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x by %x" \
                #%(address, size, value, pc))
            # map a page a memory here
            kb = 4*1024
            emu.mem_map((address/kb)*kb, kb)
            #uemu.mem_map(0xaaaa0000, 2 * 1024*1024)
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
        pc = emu.reg_read(self.pc_reg)
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
                                                0,
                                                "",
                                                True))
        stepnum += 1

    def f_hook(self, args):
        self.stage = self.controller.stage_order[0]
        print Main.raw.runtime.trace.keys()
        db_info.create(self.stage, "tracedb")
        self.create_emulator()
        self.setup_emulator()
        print "Starting emulation until %x" % self.stage.exitpc
        self.emu.emu_start(int(self.stage.entrypoint, 0), self.stage.exitpc)
        global start
        gdb.flush()
        db_info.get(self.stage).flush_tracedb()
        gdb.post_event(hook_write.FlushDatabase(self.stage, True))



plugin_config = Unicorn()
