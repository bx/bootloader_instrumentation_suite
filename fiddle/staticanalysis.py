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

import tables
import atexit
import subprocess
import re
import sys
import os
import intervaltree
from capstone import *
from capstone.arm import *
import testsuite_utils as utils
import labeltool
import pytable_utils
from config import Main
import numpy
import importlib
import db_info
import r2_keeper as r2

def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr


# analyze instruction to figure out what
# registers we need to calculate write destination
# and also calculate destination for us given reg values
class InstructionAnalyzer():
    WORD_SIZE = 4
    writemnere = re.compile("(push)|(stm)|(str)|(stl)|(stc)")

    def __init__(self):
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.thumb.detail = True
        # self.thumb.skipdata = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.arm.detail = True
        # self.arm.skipdata = True
        self.cache = {}

    def disasm(self, value, thumb, pc, cache=False):
        offset = pc
        ins = None
        if cache and pc in self.cache.iterkeys():
            return self.cache[pc]
        if thumb:
            ins = self.thumb.disasm(value, offset, count=1)
        else:
            ins = self.arm.disasm(value, offset, count=1)
        try:
            i = next(ins)
        except StopIteration as i:
            print "-%x %s '%s'-" % (pc, thumb, value.encode('hex'))
            raise i

        if cache:
            self.cache[pc] = i
        return i

    def is_instr_memstore(self, ins):
        return self.is_mne_memstore(ins.mnemonic)

    def get_flag_value(self, flag, cpsr):
        flags = {'n': (1 << 31), 'z': (1 << 30), 'c': (1 << 29), 'v': (1 << 28), 'q': (1 << 27)}
        return True if ((cpsr & flags[flag]) == flags[flag]) else False

    # inclase there is a conditional store check
    def store_will_happen(self, ins, regs):
        if self.has_condition_suffix(ins):
            cc = ins.cc
            cpsr = regs[-1]
            if cc == 0:
                # eq
                return self.get_flag_value('z', cpsr) is True
            elif cc == 1:
                # not equal, ne
                return self.get_flag_value('z', cpsr) is False
            elif cc == 2:
                # carry set, hs
                return self.get_flag_value('c', cpsr) is True
            elif cc == 3:
                # lo, cary clear
                return self.get_flag_value('c', cpsr) is False
            elif cc == 4:
                # mi,
                return self.get_flag_value('n', cpsr) is True
            elif cc == 5:
                # pl
                return self.get_flag_value('n', cpsr) is False
            elif cc == 6:
                # vs
                return self.get_flag_value('v', cpsr) is True
            elif cc == 7:
                return self.get_flag_value('v', cpsr) is False
                # vc
            elif cc == 8:
                # hi
                return (self.get_flag_value('c', cpsr) is True) \
                    and (self.get_flag_value('z', cpsr) is False)
            elif cc == 9:
                # ls
                return (self.get_flag_value('c', cpsr) is False) \
                    or (self.get_flag_value('z', cpsr) is True)
            elif cc == 10:
                # ge
                return (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr))
            elif cc == 11:
                # lt
                return not (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr))
            elif cc == 12:
                # gt
                return (self.get_flag_value('z', cpsr) is False) \
                    and (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr))
            elif cc == 13:
                # le
                return (self.get_flag_value('z', cpsr) is True) \
                    or (not (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr)))
            else:
                return True
        else:
            return True

    def is_thumb(self, cpsr):
        CPSR_THUMB = 0x20
        return True if (cpsr & CPSR_THUMB) == CPSR_THUMB else False  # if cpsr bit 5 is set

    def calculate_store_offset(self, ins, regs):
        if self.has_condition_suffix(ins):
            # strip off cpsr
            regs = regs[:-1]
        operands = ins.operands
        lshift = 0
        disp = 0
        for i in operands:
            if i.type == ARM_OP_MEM:
                lshift = i.mem.lshift
                disp = i.mem.disp
        if lshift > 0:
            regs[1] = (regs[1] << lshift) % (0xFFFFFFFF)

        return (sum(regs) + disp) % (0xFFFFFFFF)

    @classmethod
    def has_condition_suffix(cls, ins):
        # strip off '.w' designator if it is there, it just means
        # its a 32-bit Thumb instruction
        return ins.cc not in [ARM_CC_AL, ARM_CC_INVALID]

    @classmethod
    def calculate_store_size(cls, ins):
        mne = ins.mnemonic.encode("ascii")
        if mne.startswith('push') or mne.startswith('stl'):
            (read, write) = ins.regs_access()
            # cannot push sp value, so if it is in this list don't
            # include it in the count
            if 12 in read:
                read.remove(12)
            return -1*len(read)*InstructionAnalyzer.WORD_SIZE
        elif mne.startswith('stm'):  # stm gets converted to push, but just in case
            (read, write) = ins.regs_access()
            return (len(read) - 1)*InstructionAnalyzer.WORD_SIZE
        elif mne.startswith('str'):
            # strip off '.w' designator if it is there, it just means
            # its a 32-bit Thumb instruction
            if mne[-1] == 'w':
                mne = mne[:-1]
                if mne[-1] == '.':
                    mne = mne[:-1]

            # strip of any condition suffixes
            if cls.has_condition_suffix(ins):
                # remove last 2 chars
                mne = mne[:-2]

            # remove a final t if it is there
            if mne[-1] == 't':
                mne = mne[:-1]
            # now check to see how many bytes the instruction operates on
            if mne == 'str':
                return InstructionAnalyzer.WORD_SIZE
            elif mne[-1] == 'b':
                return 1
            elif mne[-1] == 'h':
                return InstructionAnalyzer.WORD_SIZE/2
            elif mne[-1] == 'd':
                return InstructionAnalyzer.WORD_SIZE*2
            else: # strex
                return InstructionAnalyzer.WORD_SIZE
        elif mne.startswith('stc'):
            if 'L' in mne:
                return InstructionAnalyzer.WORD_SIZE*8
            else:
                return InstructionAnalyzer.WORD_SIZE
        else:
            print "Do not know how to handle instruction mnemonic %s at %x (%x)" \
                % (ins.mnemonic, ins.address, 0)
            return -1
    @classmethod
    def needed_regs(cls, ins):
        regs = []
        if ins.id == 0:
            print "NO DATA!"
            return []
        if ins.mnemonic.startswith("push"):
            regs = ['sp']
        elif ins.mnemonic.startswith("stl") or ins.mnemonic.startswith("stm"):
            # stl is actually treated by capstone as push instruction
            # but we will check just in case
            # similar to push, first operand only
            regs = [ins.reg_name(ins.operands[0].reg).encode('ascii')]
        elif ins.mnemonic.startswith("str") or ins.mnemonic.startswith("stc"):
            readops = []
            for i in ins.operands:
                if i.type == ARM_OP_MEM:
                    if len(readops) > 0:
                        print "multiple mem operators? We can't handle this!"
                        return []
                    if i.mem.base != 0:
                        readops.append(ins.reg_name(i.mem.base).encode('ascii'))
                    if i.mem.index != 0:
                        readops.append(ins.reg_name(i.mem.index).encode('ascii'))
            regs = readops
        if cls.has_condition_suffix(ins):
            regs.append('cpsr')
        return regs

    @classmethod
    def _is_mne_memstore(cls, mne):
        return InstructionAnalyzer.writemnere.match(mne) is not None

    def is_mne_memstore(self, mne):
        return self._is_mne_memstore(mne)


class LongWriteInfo():
    def __init__(self, elf, start, end, thumb):
        self.valid = True
        self.start_ins = None
        self.start_ins_addr = None
        self.write_ins = None
        self.write_ins_addr = None
        self.finish_ins = None
        self.finish_ins_addr = None
        self.start = start
        self.end = end
        self.elf = elf
        self.thumb = thumb
        self.valid = False
        self.branch_ins_addr = None
        self.branch_ins = None
        # grab basic blocks surrounding this region
        r2.gets(elf, "s 0x%x" % self.start)
        if self.thumb:  # force r2 to use the correct instruction size. sigh.
            r2.gets(elf, "ahb 16")
            r2.gets(elf, "e asm.bits=16")
        else:
            r2.gets(elf, "ahb 32")
            r2.gets(elf, "e asm.bits=32")
        self.bbs = r2.get(elf, "pdbj")
        next = self.bbs[-1]["offset"] + self.bbs[-1]["size"]
        while next < end:
            r2.get(elf, "s 0x%x" % next)
            self.bbs.extend(r2.get(elf, "pdbj"))
            next = self.bbs[-1]["offset"] + self.bbs[-1]["size"]
        # grab one more basic block
        r2.get(elf, "s 0x%x" % next)
        self.bbs.extend(r2.get(elf, "pdbj"))

    def calculate_info(self):
        # lookup write instruction
        nwrites = 0
        elf = self.elf
        for i in self.bbs:
            mne = i["opcode"].split()[0]
            if InstructionAnalyzer._is_mne_memstore(mne):
                nwrites += 1
                if (self.start <= i["offset"]) and (i["offset"] <= self.end):
                    if self.write_ins is not None:
                        # if there are two write instruction in basic block, don't know what to do
                        self.valid = False
                        break
                    else:
                        self.write_ins = i
                        self.valid = True
                        self.write_ins_addr = self.write_ins["offset"]
        if nwrites > 1:
            print "Warning: %s write ins in these blocks" % nwrites

        if not self.valid:
            return

        # look for branch after write to find loop
        branch = None
        unconditional = False
        for b in self.bbs:
            if b["offset"] < self.write_ins_addr:
                continue
            if b["type"] == u"cjmp" or b["type"] == u"jmp":
                if b["type"] == "jmp":
                    dst = b["jump"]
                    r2.gets(elf, "s 0x%x" % dst)
                    for next in r2.get(elf, "pdbj"):
                        if next["type"] == u"cjmp" or next["type"] == "jmp":
                            if next["type"] == "cjmp":
                                jump = next["jump"]
                                if jump not in [ii["offset"] for ii in self.bbs]:
                                    self.finish_ins_addr = jump
                                else:
                                    self.finish_ins_addr = next["offset"] + next["size"]
                            else:
                                # don't handle this case yet
                                self.valid = False
                            break
                    break
                    #branch = r2.get(elf, "pdj 1")[0]
                    #self.finish_ins_addr = branch["offset"] + branch["size"]
                else:
                    branch = b
                    jump = branch["jump"]
                    if jump not in [ii["offset"] for ii in self.bbs]:
                        self.finish_ins_addr = jump
                    else:
                        self.finish_ins_addr = branch["offset"] + branch["size"]

        r2.gets(elf, "s 0x%x" % self.finish_ins_addr)
        self.finish_ins = r2.get(elf, "pdj 1")[0]
        self.start_ins_addr = self.write_ins_addr
        self.start_ins = self.write_ins

    def __repr__(self):
        if not self.valid:
            return "<invalid longwrite @ 0x%x>" % self.start_ins_addr
        else:
            return "<longwrite [start=0x%x,write=0x%x,done=0x%x]>" % (self.start_ins_addr, self.write_ins_addr, self.finish_ins_addr)





class WriteEntry(tables.IsDescription):
    pc = tables.UInt32Col()
    thumb = tables.BoolCol()
    reg0 = tables.StringCol(4)
    reg1 = tables.StringCol(4)
    reg2 = tables.StringCol(4)
    reg3 = tables.StringCol(4)
    reg4 = tables.StringCol(4)
    writesize = tables.Int32Col()
    halt = tables.BoolCol()  # whether to insert a breakpoint here


class SrcEntry(tables.IsDescription):
    addr = tables.UInt32Col()
    line = tables.StringCol(512)  # file/lineno
    src = tables.StringCol(512)  # contents of source code at this location
    ivalue = tables.StringCol(12)
    ilength = tables.UInt8Col()
    thumb = tables.BoolCol()
    mne = tables.StringCol(10)
    disasm = tables.StringCol(256)


class RelocInfo(tables.IsDescription):
    startaddr = tables.UInt32Col()  # first address in relocation block
    size = tables.UInt32Col()  # number of relocated bytes
    relocpc = tables.UInt32Col()  # what the pc is once it is relocated
    reldelorig = tables.BoolCol()  # whether to delete the original once relocated
    reloffset = tables.Int64Col()  # (orig addr + offset) % relmod  = new address
    relmod = tables.UInt32Col()
    relbegin = tables.UInt32Col()  # address of where relocation starts happening
    name = tables.StringCol(255)
    symname = tables.StringCol(128)
    cardinal = tables.UInt8Col()


class StageExitInfo(tables.IsDescription):
    addr = tables.UInt32Col()  # non-relocated addr
    success = tables.BoolCol()
    line = tables.StringCol(512)  # file/lineno


class SmcEntry(tables.IsDescription):
    pc = tables.UInt32Col()
    thumb = tables.BoolCol()


class FuncEntry(tables.IsDescription):
    fname = tables.StringCol(40)  # name of function pc is located
    startaddr = tables.UInt32Col()  # first address in relocation block
    endaddr = tables.UInt32Col()  # first address in relocation block


class LongWriteRangeType():
    @staticmethod
    def get_reg_lists(row):
        sregs = []
        eregs = []
        for i in range(0, 5):
            if not row['sreg%d' % i] == "":
                sregs.append(row['sreg%d' % i])
            if not row['ereg%d' % i] == "":
                eregs.append(row['ereg%d' % i])
        return (sregs, eregs)

    @staticmethod
    def parse_reg_values(sregs, eregs, regs):
        return ([regs[name] for name in sregs], [regs[name] for name in eregs])

    @classmethod
    def calculate_dest_count(c, row, regs, sregs=None, eregs=None, s=None):
        if sregs is None or eregs is None:
            (sregs, eregs) = c.get_reg_lists(row)
        (sregvalues, eregvalues) = c.parse_reg_values(sregs, eregs, regs)
        start = sum(sregvalues) + row['startvalue']
        count = (sum(eregvalues) + row['endvalue'])
        sub = row['destsubtract']
        if not sub == "":
            count = count - regs[sub]
        count = count * row['interval']
        return (start, start + count)

    @classmethod
    def calculate_dest_maxaddr(c, row, regs, sregs=None, eregs=None, s=None):
        if sregs is None or eregs is None:
            (sregs, eregs) = c.get_reg_lists(row)
        (sregvalues, eregvalues) = c.parse_reg_values(sregs, eregs, regs)
        start = sum(sregvalues) + row['startvalue']
        end = (sum(eregvalues) + row['endvalue'])
        sub = row['destsubtract']
        if not sub == "":
            end = end - regs[sub]
        return (start, end)

    @classmethod
    def calculate_dest_sourcestr(c, row, regs, sregs=None, eregs=None, s=""):
        if sregs is None or eregs is None:
            (sregs, eregs) = c.get_reg_lists(row)
        (sregvalues, eregvalues) = c.parse_reg_values(sregs, eregs, regs)
        slen = len(s) + 1  # include null byte
        start = sum(sregvalues)+row['startvalue']
        count = slen
        return (start, start+count)

    @classmethod
    def calculate_dest_sourcestrn(c, row, regs, sregs=None, eregs=None, s=""):
        if sregs is None or eregs is None:
            (sregs, eregs) = c.get_reg_lists(row)
        (sregvalues, eregvalues) = c.parse_reg_values(sregs, eregs, regs)
        slen = len(s) + 1  # include null byte
        start = sum(sregvalues)+row['startvalue']
        count = regs[row['destsubtract']]
        count = count if count > slen else slen
        return (start, start+count)

    @classmethod
    def get_type_names(c):
        return c.rangetypes.keys()

    @classmethod
    def enum(c):
        return tables.Enum(c.get_type_names())

    @classmethod
    def range_calculator(c, number):
        e = c.enum()
        name = e(number)
        return c.rangetypes[name]


LongWriteRangeType.rangetypes = {
        'count': LongWriteRangeType.calculate_dest_count,
        'maxaddr': LongWriteRangeType.calculate_dest_maxaddr,
        'sourcestr': LongWriteRangeType.calculate_dest_sourcestr,
        'sourcestrn': LongWriteRangeType.calculate_dest_sourcestrn,
    }


class LongWrites(tables.IsDescription):
    breakaddr = tables.UInt32Col()  # where write loop starts
    writeaddr = tables.UInt32Col()  # where write loop starts
    contaddr = tables.UInt32Col()  # pc after loop
    sreg0 = tables.StringCol(4)  # registers we need to read to determine each write destination
    sreg1 = tables.StringCol(4)  # add all these values
    sreg2 = tables.StringCol(4)  # then start incrementing by writesize
    sreg3 = tables.StringCol(4)
    sreg4 = tables.StringCol(4)
    ereg0 = tables.StringCol(4)  # registers to read to determine until what destination to write
    ereg1 = tables.StringCol(4)  # add all these values
    ereg2 = tables.StringCol(4)
    ereg3 = tables.StringCol(4)
    ereg4 = tables.StringCol(4)
    destsubtract = tables.StringCol(4)
    endvalue = tables.UInt32Col()
    startvalue = tables.UInt32Col()
    writesize = tables.UInt32Col()  # number of bytes to increments write dest each time
    interval = tables.UInt32Col()  # # bytes per count
    thumb = tables.BoolCol()  # if write is at thumb address
    inplace = tables.BoolCol()
    rangetype = tables.EnumCol(tables.Enum(LongWriteRangeType.enum()), 'count', base='uint8')

class LongWrites2(tables.IsDescription):
    breakaddr = tables.UInt32Col()  # where write loop starts
    writeaddr = tables.UInt32Col()  # where write loop starts
    contaddr = tables.UInt32Col()  # pc after loop
    thumb = tables.BoolCol()  # if write is at thumb address
    inplace = tables.BoolCol()
    writesize = tables.UInt32Col()
    start = tables.UInt32Col()
    end = tables.UInt32Col()


class SkipEntry(tables.IsDescription):
    pc = tables.UInt32Col()
    disasm = tables.StringCol(256)
    thumb = tables.BoolCol()
    resumepc = tables.UInt32Col()
    isfunction = tables.BoolCol()


class LongWrite2DescriptorGenerator():
    def __init__(self, name, inplace, table):
        self.table = table
        self.stage = table.stage
        self.name = name
        self.inplace = inplace

    def generate_descriptor(self):
        labels = WriteSearch.find_labels(labeltool.LongwriteLabel, "",
                                         self.stage, self.name)
        if len(labels) == 0:
            return None
        write = ""
        for l in labels:
            if l.value == "BREAK":
                lineno = self.table._get_real_lineno(l, False)
                write = "%s:%d" % (l.filename, lineno)
            break
        if not write:
            return {}
        (writestart, writeend) = utils.line2addrs(write, self.stage)
        return LongWrite2Descriptor(writestart, writeend,
                                    self.inplace, self.table)


class LongWriteDescriptor():

    def __init__(self, breakline, writeline, resumeaddr, destregs,
                 calcregs, subreg, writetype, interval, inplace, table):
        self.stage = table.stage
        self.table = table
        self.breakline = breakline
        self.breakaddr = self.table._get_line_addr(self.breakline, True)
        self.inplace = inplace
        self.writetype = LongWriteRangeType.enum()[writetype]
        self.interval = interval
        self.resumeaddr = None
        self.valid = False
        self.writeaddr = None
        self.calcregs = calcregs
        self.subreg = subreg
        self.destregs = destregs

        if writeline == "":
            self.writeline = self.breakline
        else:
            self.writeline = writeline
        writestart = self.table._get_line_addr(self.writeline, True)

        # find first write after breakpoint or write addr
        checkaddr = writestart
        self.thumb = self.table.thumbranges.overlaps_point(checkaddr)

        # resume after first conditional branch after write instruction
        r2.get(self.stage.elf, "s 0x%x" % writestart)
        if self.thumb:
            r2.get(self.stage.elf, "e asm.bits=16" )
            r2.gets(self.stage.elf, "ahb 16")
        else:
            r2.get(self.stage.elf, "e asm.bits=32" )
            r2.gets(self.stage.elf, "ahb 32")

        r2.get(self.stage.elf, "pd")
        i = r2.get(self.stage.elf, "pdj")
        for instr in i:
            if u"invalid" == instr["type"] or ("disasm" in instr and u"invalid" == instr["disasm"]):
                continue
            mne = instr["disasm"].split()[0]
            if not self.table.ia.is_mne_memstore(mne):
                continue

            self.value = b"%s" % instr["bytes"]
            self.disasm = instr["disasm"]
            self.writeaddr = instr["offset"]
            break
        if not self.writeaddr:
            print "Longwrite not found at for (%s)" % (self.__dict__)
            return
        writes = self.table.writestable.where("0x%x == pc" % (self.writeaddr))
        try:
            write = next(writes)
        except:
            print "Longwrite not found at %x (%s)" % (self.writeaddr, self.__dict__)
            return
        self.writesize = write['writesize']
        write['halt'] = False
        write.update()
        self.funname = db_info.get(self.stage).addr2functionname(self.writeaddr)
        self.instr = self.table.ia.disasm(self.value, self.thumb, self.writeaddr)

        if len(self.destregs) == 0:  # lookup register that holds destination
            self.destregs = self.table.ia.needed_regs(self.instr)
            if "cpsr" in self.destregs:
                self.destregs.remove("cpsr")
        if not resumeaddr == "":
            checkaddr = self.table._get_line_addr(resumeaddr, True)
        else:
            checkaddr = self.writeaddr

        # resume after first conditional branch after write instruction
        #while self.resumeaddr is None and i < 1024:
        #print "searching for resume after write %x" % self.writeaddr
        r2.gets(self.stage.elf, "s 0x%x" % self.writeaddr)
        if self.thumb: # force r2 to use the correct instruction size. sigh.
            r2.gets(self.stage.elf, "ahb 16")
            r2.gets(self.stage.elf, "e asm.bits=16")
        else:
            r2.gets(self.stage.elf, "ahb 32")
            r2.gets(self.stage.elf, "e asm.bits=32")

        for i in r2.get(self.stage.elf, "pdj 14"):
            pass
        for i in r2.get(self.stage.elf, "pdj 14"):
            if (not "disasm" in i) or u"invalid" == i["type"] or u"invalid" == i["disasm"]:
                continue
            checkvalue = b"%s" % i["bytes"]
            addr = i['offset']
            # for some reason, this time around capstone chokes
            # if I decode the hex-encoded string instruction value
            ck = self.table.ia.disasm(checkvalue, self.thumb, addr)
            if (ck.mnemonic[0] == 'b') and \
               (1 in ck.groups) and \
               (self.table.ia.has_condition_suffix(ck)):  # its a conditional branch!
                self.resumeaddr = checkaddr + len(ck.bytes)
                break
            else:
                checkaddr = checkaddr + len(ck.bytes)
        if self.resumeaddr:
            self.valid = True
        self.table.writestable.flush()


    def populate_row(self, r):
        if not self.valid:
            return
        r['breakaddr'] = self.breakaddr
        r['contaddr'] = self.resumeaddr
        r['startvalue'] = 0
        r['endvalue'] = 0
        r['rangetype'] = self.writetype
        r['interval'] = self.interval
        r['destsubtract'] = self.subreg
        r['inplace'] = self.inplace
        r['writeaddr'] = self.writeaddr
        r['writesize'] = self.writesize
        r['thumb'] = self.thumb

        for i in range(0, 5):
            r['sreg%d' % i] = ''
            r['ereg%d' % i] = ''
        i = 0
        for sr in self.destregs:
            if type(sr) is str:
                r['sreg%d' % i] = sr
                i = + 1
            elif type(sr) is int:  # assume it's an int
                r['startvalue'] = sr

        i = 0
        for er in self.calcregs:
            if type(er) is str:
                r['ereg%d' % i] = er
                i = + 1
            elif type(er) is int:  # assume it's an int
                r['endvalue'] = er

    def get_info(self):
        if not self.valid:
            return "Invalid write descriptor at %x *%s)" % (self.breakaddr,
                                                            self.breakline)
        return "in function %s: break at %x, write at %x, resume at %x." \
            "addr regs = %s calc reg %s, subreg = %s, disasm %s value %s." \
            % (self.funname, self.breakaddr, self.writeaddr,
               self.resumeaddr, str(self.destregs), str(self.calcregs),
               self.subreg, self.disasm, self.value.encode('hex'))


class LongWrite2Descriptor():
    def __init__(self, start, end,
                 inplace, table):
        self.stage = table.stage
        self.table = table
        self.inplace = inplace
        self.valid = False
        self.start = start
        self.end = end
        self.thumb = self.table.thumbranges.overlaps_point(self.start)
        self.info = LongWriteInfo(self.stage.elf, self.start, self.end, self.thumb)
        self.info.calculate_info()
        print self.table.ia
        print self.info
        print self.info.write_ins
        ins = self.table.ia.disasm(b"%s" % self.info.write_ins["bytes"].decode("hex"),
                                   self.thumb,
                                   self.info.write_ins["offset"])
        self.write_size = self.table.ia.calculate_store_size(ins)
        print self.info
        self.breakaddr = self.info.start_ins_addr
        self.writeaddr = self.info.write_ins_addr
        self.contaddr = self.info.finish_ins_addr
        writes = self.table.writestable.where("0x%x == pc" % (self.writeaddr))
        try:
            write = next(writes)
        except Exception as e:
            print e
            print "Longwrite not found at %x (%s)" % (self.writeaddr, self.__dict__)
            return
        self.valid = True
        self.writesize = write['writesize']
        r2.get(self.stage.elf, "s 0x%x" % self.writeaddr)
        if self.thumb:
            r2.get(self.stage.elf, "e asm.bits=16" )
            r2.gets(self.stage.elf, "ahb 16")
        else:
            r2.get(self.stage.elf, "e asm.bits=32" )
            r2.gets(self.stage.elf, "ahb 32")

        r2.get(self.stage.elf, "pd 1")
        i = r2.get(self.stage.elf, "pdj 1")[0]
        self.value = b"%s" % i["bytes"]
        self.disasm = i["disasm"]

        write['halt'] = False
        write.update()
        self.funname = db_info.get(self.stage).addr2functionname(self.writeaddr)
        self.instr = self.table.ia.disasm(self.value, self.thumb, self.writeaddr)
        self.table.writestable.flush()

    def populate_row(self, r):
        if not self.valid:
            return
        r['breakaddr'] = self.breakaddr
        r['contaddr'] = self.contaddr
        r['inplace'] = self.inplace
        r['writeaddr'] = self.writeaddr
        r['thumb'] = self.thumb
        r['writesize'] = self.writesize
        r['start'] = self.start
        r['end'] = self.end

    def get_info(self):
        if not self.valid:
            return "Invalid write descriptor at %x *%s)" % (self.breakaddr,
                                                            self.breakline)
        return "in function %s: break at %x, write at %x, resume at %x." \
            "value %s." \
            % (self.funname, self.breakaddr, self.writeaddr,
               self.resumeaddr, self.value.encode('hex'))


class RelocDescriptor():
    def __init__(self, name, relocbegin,
                 relocrdy, cpystart, cpyend, reldst, stage, delorig, symname="", mod=0xffffffff):
        self.name = name
        self.symname = symname
        self.begin = relocbegin
        self.beginaddr = -1
        self.ready = relocrdy
        self.readyaddr = -1
        self.cpystart = cpystart
        self.cpystartaddr = -1
        self.cpyend = cpyend
        self.cpyendaddr = -1
        self.dst = reldst
        self.dstaddr = -1
        self.delorig = delorig
        self.stage = stage
        self.reloffset = 0
        self.relmod = mod
        self._calculate_addresses()

    def lookup_label_addr(self, label):
        lineno = WriteSearch.get_real_lineno(label, False, self.stage)
        loc = "%s:%d" % (label.filename, lineno)
        return utils.get_line_addr(loc, True, self.stage,
                                   srcdir=Main.get_runtime_config("temp_target_src_dir"))

    def set_reloffset(self, offset):
        self.reloffset = offset

    def _calculate_addresses(self):
        # DST, CPYSTART, CPYEND, BEGIN, READY
        for value in ["begin", "ready", "cpystart", "cpyend", "dst"]:
            item = getattr(self, value)
            if item is None:  # then lookup label
                l = WriteSearch.find_label(labeltool.RelocLabel, value.upper(),
                                           self.stage, self.name)

                if l is not None:
                    setattr(self, value+"addr", self.lookup_label_addr(l))
                else:
                    raise Exception("cannot find label value "
                                    "%s stage %s name %s" % (value,
                                                             self.stage.stagename,
                                                             self.name))
            else:
                setattr(self, value+"addr", item)

    def get_row_information(self):
        # DST, CPYSTART, CPYEND, BEGIN, READY
        info = {
            'relocpc': self.readyaddr,
            'relmod': self.relmod,
            'startaddr': self.cpystartaddr,
            'relbegin': self.beginaddr,
            'size': self.cpyendaddr - self.cpystartaddr,
            'reloffset': self.reloffset,
            'reldelorig': self.delorig,
            'symname': self.symname,
            'name': self.name,
        }
        return info


class SkipDescriptorGenerator():
    def __init__(self, name, table, adjuststart=0, adjustend=0):
        self.name = name
        self.adjuststart = adjuststart
        self.adjustend = adjustend
        self.table = table
        self.stage = table.stage

    def get_row_information(self):
        row = {}
        labels = WriteSearch.find_labels(labeltool.SkipLabel, "",
                                         self.stage, self.name)
        startaddr = -1
        endaddr = -1
        start = ""
        end = ""
        elf = self.stage.elf
        srcdir = Main.get_runtime_config("temp_target_src_dir")
        isfunc = False
        for l in labels:
            if not l.name == self.name:
                continue
            if l.value == "START":
                lineno = self.table._get_real_lineno(l, False)
                start = "%s:%d" % (l.filename, lineno)
            elif l.value == "END":
                lineno = self.table._get_real_lineno(l, True)
                end = "%s:%d" % (l.filename, lineno)
            elif l.value == "FUNC":
                isfunc = True
                lineno = self.table._get_real_lineno(l, False)
                start = "%s:%d" % (l.filename, lineno)
                startaddr = self.table._get_line_addr(start, True)
                f = pytable_utils.get_unique_result(self.table.funcstable, ("(startaddr <= 0x%x) & (0x%x < endaddr)" % (startaddr, startaddr)))
                (startaddr, endaddr) = (f['startaddr'], f['endaddr'])
                r2.get(elf, "s 0x%x" % startaddr)
                thumb = False
                if self.table.thumbranges.overlaps_point(startaddr):
                    thumb = True
                if thumb:
                    r2.get(self.stage.elf, "e asm.bits=16")
                    r2.gets(self.stage.elf, "ahb 16")
                else:
                    r2.get(self.stage.elf, "e asm.bits=32")
                    r2.gets(self.stage.elf, "ahb 32")

                disasm = r2.get(elf, "pd 2")
                disasm = r2.get(elf, "pdj 2")

                if disasm[0]["disasm"].startswith("push"):
                    firstins = disasm[1]
                else:
                    firstins = disasm[0]
                startaddr = firstins["offset"]
                #print "start %s,%x" % (startaddr, endaddr)
            elif l.value == "NEXT":
                lineno = self.table._get_real_lineno(l, False)
                start = "%s:%d" % (l.filename, lineno)
                end = "%s:%d" % (l.filename, lineno)
            if lineno == -1:
                return None
        if (startaddr < 0) and (endaddr < 0):
            # move startaddr after any push instructions
            startaddr = self.table._get_line_addr(start, True)
            endaddr = self.table._get_line_addr(end, False)
            r2.get(elf, "s 0x%x" % startaddr)
            thumb = False
            if self.table.thumbranges.overlaps_point(startaddr):
                thumb = True

            if thumb:
                r2.gets(self.stage.elf, "ahb 16")
                r2.get(self.stage.elf, "e asm.bits=16" )
            else:
                r2.gets(self.stage.elf, "ahb 32")
                r2.get(self.stage.elf, "e asm.bits=32" )
            disasm = r2.get(elf, "pd 2")
            disasm = r2.get(elf, "pdj 2")
            if "disasm" in disasm[0]:
                if (disasm[0][u"disasm"].startswith("push")):
                    # don't include push instruction
                    startins = disasm[1]
                else:
                    startins = disasm[0]
                startaddr = startins["offset"]

        s = startaddr + self.adjuststart
        e = endaddr + self.adjustend
        if e < s:
            t = s
            s = e
            e = t
        row['pc'] = s
        row['resumepc'] = e
        row['isfunction'] = isfunc
        row['thumb'] = self.table.thumbranges.overlaps_point(row['pc'])
        return row


class ThumbRanges():
    @staticmethod
    def find_thumb_ranges(stage):
        cc = Main.cc
        elf = stage.elf
        thumb = intervaltree.IntervalTree()
        arm = intervaltree.IntervalTree()
        data = intervaltree.IntervalTree()
        cmd = "%snm -S -n --special-syms %s 2>/dev/null" % (cc, elf)
        output = subprocess.check_output(cmd, shell=True).split('\n')
        prev = None
        lo = 0
        dta = re.compile('\s+[a-zA-Z]\s+\$[tad]$')
        for o in output:
            o = o.strip()
            if dta.search(o):
                hi = int(o[:8], 16)
                if (prev is not None) and (not lo == hi):
                    i = intervaltree.Interval(lo, hi)
                    if prev == 't':
                        thumb.add(i)
                    elif prev == 'a':
                        arm.add(i)
                    elif prev == 'd':
                        data.add(i)
                    else:
                        raise Exception
                lo = hi
                prev = o[-1]
            else:
                continue
        res = (thumb, arm, data)
        for r in res:
            r.merge_overlaps()
            r.merge_equals()
        return res


class WriteSearch():
    def __init__(self, createdb, stage, verbose=False, readonly=False):
        self.verbose = verbose
        outfile = Main.get_static_analysis_config("db", stage)

        self.stage = stage
        self.ia = InstructionAnalyzer()
        self.relocstable = None
        self.stageexits = None
        self.writestable = None
        self.smcstable = None
        self.srcstable = None
        self.funcstable = None
        self.longwritestable = None
        self.skipstable = None
        self.verbose = verbose
        (self._thumbranges, self._armranges, self._dataranges) = (None, None, None)

        if createdb:
            m = "w"
            self.h5file = tables.open_file(outfile, mode=m,
                                           title="%s target static analysis"
                                           % stage.stagename)
            self.group = self.h5file.create_group("/", 'staticanalysis',
                                                  "%s target static analysis"
                                                  % stage.stagename)
        else:
            mo = "a"
            self.h5file = tables.open_file(outfile, mode=mo,
                                           title="%s target static analysis"
                                           % stage.stagename)
            self.group = self.h5file.get_node("/staticanalysis")
        r2.cd(self.stage.elf, Main.get_runtime_config("temp_target_src_dir"))
        def q():
            try:
                r2.files[self.stage.elf].quit()
            except IOError:
                pass
        atexit.register(q)

    @classmethod
    def _get_src_labels(cls):
        return Main.get_runtime_config("labels")()

    def open_all_tables(self):
        self.relocstable = self.group.relocs
        self.stageexits = self.group.stageexits
        self.writestable = self.group.writes
        self.smcstable = self.group.smcs
        self.srcstable = self.group.srcs
        self.funcstable = self.group.funcs
        self.longwritestable = self.group.longwrites

        self.skipstable = self.group.skips

    def print_relocs_table(self):
        for r in self.relocstable.iterrows():
            print self.reloc_row_info(r)
        for l in self.find_labels(labeltool.RelocLabel, "",
                                  self.stage, ""):
            print l

    def setup_missing_tables(self):
        print "setting up tables for stage %s" % self.stage.stagename
        try:
            self.funcstable = self.group.funcs
        except tables.exceptions.NoSuchNodeError:
            self.create_funcs_table()
        try:
            self.stageexits = self.group.stageexits
        except tables.exceptions.NoSuchNodeError:
            self.create_stageexit_table()
        try:
            self.relocstable = self.group.relocs
        except tables.exceptions.NoSuchNodeError:
            self.create_relocs_table()
        try:
            self.writestable = self.group.writes
            self.smcstable = self.group.smcs
            self.srcstable = self.group.srcs
        except tables.exceptions.NoSuchNodeError:
            self.create_writes_table()
        try:
            self.longwritestable = self.group.longwrites
        except tables.exceptions.NoSuchNodeError:
            self.create_longwrites_table()

        try:
            self.skipstable = self.group.skips
        except tables.exceptions.NoSuchNodeError:
            self.create_skip_table()

    def _setthumbranges(self):
        (self._thumbranges, self._armranges, self._dataranges) = Main.get_runtime_config("thumb_ranges", self.stage)()



    @property
    def thumbranges(self):
        if not self._thumbranges:
            self._setthumbranges()
        return self._thumbranges

    @property
    def armranges(self):
        if not self._armranges:
            self._setthumbranges()
        return self._armranges

    @property
    def dataranges(self):
        if not self._dataranges:
            self._setthumbranges()
        return self._dataranges

    def _get_write_pc_or_zero(self, dstinfo):
        framac = True
        startlineaddr = self._get_line_addr(dstinfo.key(), True, framac)
        endlineaddr = self._get_line_addr(dstinfo.key(), False, framac)
        if (startlineaddr < 0) or (endlineaddr < 0):
            return 0

        query = "(0x%x <= pc) & (pc < 0x%x)" % (startlineaddr, endlineaddr)
        write = pytable_utils.get_rows(self.writestable, query)
        if len(write) == 1:
            return write[0]['pc']
        else:
            print "0 or more than 1 write (%d) in %s" % (len(write), query)
            #raise Exception('?')
            # either 0 or more than zero results
            return 0

    def create_skip_table(self):
        self.skipstable = self.h5file.create_table(self.group, 'skips',
                                                   SkipEntry,
                                                   "other instructions to skip (besides smc)")

        # TODO: REPLACE ALL OF THIS WITH CODE THAT GENERATES THIS FROM LABELS
        # get all instructions for sdelay
        skiplines = []
        for l in WriteSearch.find_labels(labeltool.SkipLabel, "", self.stage, ""):
            skiplines.append(SkipDescriptorGenerator(l.name, self))

        skiplabels = skiplines
        r = self.skipstable.row
        for s in skiplabels:
            info = s.get_row_information()
            for (k, v) in info.iteritems():
                r[k] = v
            if self.verbose:
                print "skip %s (%x,%x) isfunc %s" % (s.name, r['pc'],
                                                     r['resumepc'], r['isfunction'])
            r.append()
        self.skipstable.flush()
        self.h5file.flush()

        #print "SKIPS------"
        #for l in skiplines:
        #    print l.__dict__
        # skiplines = [
        #     SkipDescriptorGenerator("do_sdrc_init0", self),
        #     SkipDescriptorGenerator("do_sdrc_init1", self),
        #     SkipDescriptorGenerator("do_sdrc_init2", self),
        #     SkipDescriptorGenerator("write_sdrc_timings0", self),
        #     SkipDescriptorGenerator("write_sdrc_timings1", self),
        #     SkipDescriptorGenerator("per_clocks_enable0", self),
        #     SkipDescriptorGenerator("per_clocks_enable2", self, 0, 0),
        #     SkipDescriptorGenerator("per_clocks_enable3", self),
        #     SkipDescriptorGenerator("write_sdrc_timings", self),
        #     # SkipDescriptorGenerator("mmc_init_stream", self),
        #     SkipDescriptorGenerator("mmc_init_stream0", self),
        #     SkipDescriptorGenerator("mmc_init_stream1", self),
        #     SkipDescriptorGenerator("mmc_init_setup1", self),
        #     SkipDescriptorGenerator("mmc_reset_controller_fsm", self),
        #     SkipDescriptorGenerator("mmc_write_data0", self),
        #     SkipDescriptorGenerator("mmc_write_data1", self),
        #     SkipDescriptorGenerator("mmc_read_data0", self),
        #     SkipDescriptorGenerator("mmc_complete_op", self),
        #     SkipDescriptorGenerator("mmc_write_data0", self),
        #     SkipDescriptorGenerator("omap_hsmmc_set_ios", self),
        #     SkipDescriptorGenerator("omap_hsmmc_send_cmd", self),
        #     SkipDescriptorGenerator("omap_hsmmc_send_cmd1", self),
        # ]

        # skipfuns = [
        #     SkipDescriptorGenerator("sdelay", self),
        #     SkipDescriptorGenerator("wait_on_value", self),
        #     SkipDescriptorGenerator("udelay", self),
        #     SkipDescriptorGenerator("__udelay", self),
        #     SkipDescriptorGenerator("_set_gpio_direction", self),
        #     SkipDescriptorGenerator("_get_gpio_direction", self),
        #     SkipDescriptorGenerator("omap3_invalidate_l2_cache_secure", self),
        #     SkipDescriptorGenerator("_get_gpio_value", self),
        #     SkipDescriptorGenerator("get_sdr_cs_size", self),
        #     SkipDescriptorGenerator("get_sdr_cs_offset", self),
        #     SkipDescriptorGenerator("make_cs1_contiguous", self),
        #     SkipDescriptorGenerator("get_cpu_id", self),
        #     SkipDescriptorGenerator("set_muxconf_regs", self),
        #     SkipDescriptorGenerator("get_osc_clk_speed", self),
        #     SkipDescriptorGenerator("per_clocks_enable", self),
        #     SkipDescriptorGenerator("timer_init", self),
        #     SkipDescriptorGenerator("go_to_speed", self),
        # ]

        # if self.stage.stagename == 'spl':  # we may need to add more ranges in the main target
        #     skiplines.extend([  # identify_nand_chip
        #         SkipDescriptorGenerator("identify_nand_chip0", self),
        #         SkipDescriptorGenerator("identify_nand_chip1", self),
        #     ]
        #     )
        #     skipfuns.extend([
        #         SkipDescriptorGenerator("nand_command", self)
        #     ])
        # else:
        #     skiplines = skiplines
        #     skipfuns = skipfuns

        #skiplabels = skipfuns + skiplines

    @classmethod
    def get_real_lineno(cls, l, prev, stage):
        lineno = l.lineno
        fullpath = os.path.join(l.path, l.filename)
        addr = -1
        while addr < 0:
            if not prev:
                lineno = labeltool.SrcLabelTool.get_next_non_label(lineno, fullpath)
            else:
                lineno = labeltool.SrcLabelTool.get_prev_non_label(lineno, fullpath)
                # print "lineno %s, %s" % (lineno, fullpath)
            if lineno is None:
                addr = -1
                break
            addr = utils.get_line_addr("%s:%d" % (l.filename, lineno), True, stage,
                                       srcdir=Main.get_runtime_config("temp_target_src_dir"))

        if addr < 0:
            return -1
        else:
            return lineno

    def _get_real_lineno(self, l, prev=False):
        return WriteSearch.get_real_lineno(l, prev, self.stage)

    def get_framac_line_addr(self, line, start):
        return utils.get_line_addr(line, start, self.stage,
                                   srcdir=Main.get_runtime_config("temp_target_src_dir"))

    def _get_line_addr(self, line, start=True, framac=False):
        if framac:
            return self.get_framac_line_addr(line, start)
        else:
            return utils.get_line_addr(line, start, self.stage,
                                       srcdir=Main.get_runtime_config("temp_target_src_dir"))

    def create_longwrites_table(self):
        self.longwritestable = self.h5file.create_table(self.group, 'longwrites',
                                                        LongWrites2, "long writes to precompute")
        skips = []
        #print "LONGWRITES--"
        if not self.is_arm():
            return
        for r in self.stage.longwrites:
            skips.append(LongWrite2DescriptorGenerator(r.name,
                                                      r.inplace,
                                                      self))
        for s in skips:
            r = self.longwritestable.row
            sdesc = s.generate_descriptor()
            if not sdesc:
                print "We didn't find any longwrite labels for %s" % s.name
                continue
            # to prevent duplicate entries
            query = "breakaddr == 0x%x" % sdesc.breakaddr
            descs = pytable_utils.get_rows(self.longwritestable, query)
            if len(descs) > 0:
                print "found duplicate longwrite at breakpoint 0x%x" % sdesc.breakaddr
                continue
            if not sdesc.valid:
                "longwrite is not value, continuing"
                continue
            sdesc.populate_row(r)
            if self.verbose:
                print sdesc.get_info()
            r.append()
            self.longwritestable.flush()
        self.longwritestable.cols.breakaddr.create_index(kind='full')
        self.longwritestable.flush()
        self.writestable.flush()
        self.h5file.flush()
        #for s in skips:
        #    print s.__dict__


        # skips = [
        #     LongWriteDescriptorGenerator("memset", [], ["r2"], "",
        #                                  'count', 1, False, self),
        #     LongWriteDescriptorGenerator("memcpy", [], ["r2"], "",
        #                                  'count', 1, False, self),
        #     LongWriteDescriptorGenerator("bss", [], ["r1"], "",
        #                                  'maxaddr', 1, False, self),
        #     LongWriteDescriptorGenerator("mmc_read_data", [], ["r8"],
        #                                  "", 'count', 4, False, self),
        # ]

        # if self.stage.stagename == "spl":
        #     skips = skips
        # else:  # strcpy doesn't work properly, disabling for now
        #     mainskips = [
        #         LongWriteDescriptorGenerator("memmove", [], ["r2"],
        #                                      "", 'count', 1, False, self),
        #         LongWriteDescriptorGenerator("relocate_code", [], ["r2"],
        #                                      "r1", 'count', 1, False, self),
        #         # LongWriteDescriptorGenerator("strncpy", ["r0"], ["r1"],
        #         #                              "r2", 'sourcestrn',
        #         #                              1, False, self),
        #         # LongWriteDescriptorGenerator("_do_env_set", ["r0"], ["r2"],
        #         #                              "", 'sourcestr',
        #         #                              1, False, self),
        #         # LongWriteDescriptorGenerator("strcpy", ["r0"], ["r1"],
        #         #                              "", 'sourcestr',
        #         #                              1, False, self),
        #         LongWriteDescriptorGenerator("cp_delay", [], [99],
        #                                      "", 'count', 0, True, self),
        #         LongWriteDescriptorGenerator("string", [], ["r0"],
        #                                      "", 'count', 1, False, self),
        #         # LongWriteDescriptorGenerator("strcat", [], ["r1"], "",
        #         #                              "sourcestr", 1, False, self)

        #     ]
        #     skips.extend(mainskips)

    @classmethod
    def find_label(cls, lclass, value, stage, name):
        res = cls.find_labels(lclass, value, stage, name)
        if not (len(res) == 1):
            raise Exception("Found 0 or +1 labels of class=%s, value=%s, stage=%s, name=%s"
                            % (lclass.__name__, value, stage.stagename, name))
        return res[0]

    @classmethod
    def find_labels(cls, lclass, value, stage, name):
        all_labels = cls._get_src_labels()
        results = []
        if lclass not in all_labels.iterkeys():
            return []
        labels = all_labels[lclass]
        for l in labels:
            if ((stage is None) or (l.stagename == stage.stagename)) \
               and ((len(name) == 0) or (l.name == name)) \
               and ((len(value) == 0) or (l.value == value)):
                results.append(l)
        return results

    @classmethod
    def get_relocation_information(cls, stage):
        rs = []
        for r in stage.reloc_descrs:
            path = getattr(r, "path")
            path = Main.populate_from_config(path)

            generator = getattr(r, "generator")
            sys.path.append(os.path.dirname(path))
            name = re.sub(".py", "", os.path.basename(path))
            mod = importlib.import_module(name)
            sys.path.pop()
            g = getattr(mod, generator)
            r = g(Main, stage, r.name, RelocDescriptor, utils)
            rs.append(r)
        return rs


    def create_stageexit_table(self):
        self.stageexits = self.h5file.create_table(self.group, 'stageexits',
                                                   StageExitInfo, "stage exit info")
        sls = WriteSearch.find_labels(labeltool.StageinfoLabel, "EXIT", self.stage, "")
        r = self.stageexits.row
        for l in sls:
            lineno = self._get_real_lineno(l)
            if lineno < 0:
                print "couldn't find label at %s" % l
                continue
            loc = "%s:%d" % (l.filename, lineno)
            addr = utils.get_line_addr(loc, True, self.stage,
                                       srcdir=Main.get_runtime_config("temp_target_src_dir"))
            success = True if l.name == "success" else False
            r['addr'] = addr
            r['line'] = loc
            r['success'] = success
            r.append()
        self.stageexits.flush()

    def create_relocs_table(self):
        self.relocstable = self.h5file.create_table(self.group,
                                                    'relocs', RelocInfo, "relocation information")
        infos = WriteSearch.get_relocation_information(self.stage)
        i = 0
        for info in infos:
            r = self.relocstable.row
            for (k, v) in info.iteritems():
                r[k] = v
            r['cardinal'] = i
            i += 1
            if self.verbose:
                print "%s addr range being relocated (0x%x,0x%x) by 0x%x bytes. Breakpoint at %x" \
                    % (self.stage.stagename, r['startaddr'], r['startaddr']+r['size'],
                       r['reloffset'], r['relocpc'])
                print self.reloc_row_info(r)
            r.append()
        self.relocstable.flush()
        self.relocstable.cols.startaddr.create_index(kind='full')
        self.relocstable.cols.relocpc.create_index(kind='full')
        self.relocstable.cols.cardinal.create_index(kind='full')
        self.relocstable.flush()
        self.h5file.flush()

    def closedb(self, flushonly=True):
        try:
            self.writestable.reindex_dirty()
        except AttributeError:
            pass
        try:
            self.smcstable.reindex_dirty()
        except AttributeError:
            pass
        try:
            self.srcstable.reindex_dirty()
        except AttributeError:
            pass
        try:
            self.funcstable.reindex_dirty()
        except AttributeError:
            pass
        if flushonly:
            self.h5file.flush()
        else:
            self.h5file.close()
            self.writestable = None
            self.smcstable = None
            self.srcstable = None
            self.funcstable = None
            self.relocstable = None
            self.longwritestable = None
            self.stageexits = None

    def _get_addr_info(self, addr):
        WriteSearch.get_addr_info(addr,
                                  self.writestable,
                                  self.srcstable,
                                  self.funcstable,
                                  self.relocstable,
                                  self.longwritestable,
                                  self.skipstable,
                                  self.smcstable)

    @classmethod
    def get_addr_info(cls, addr, writes, srcs, funcs, relocs, longwrites, skips, smcs=None):
        print "------------- info for %x -------------" % addr
        print "writes --"
        rows = pytable_utils.get_rows(writes, "pc == 0x%x" % addr)
        map(lambda r: pytable_utils._print(cls.write_row_info(r)), rows)

        if smcs is not None:
            print "smcs --"
            rows = pytable_utils.get_rows(smcs, "pc == 0x%x" % addr)
        map(lambda r: pytable_utils._print(cls.smc_row_info(r)), rows)

        print "srcs --"
        rows = pytable_utils.get_rows(srcs, "addr == 0x%x" % addr)
        map(lambda r: pytable_utils._print(cls.src_row_info(r)), rows)

        print "funcs --"
        rows = pytable_utils.get_rows(funcs,
                                      "(startaddr <= 0x%x) & (0x%x < endaddr)" % (addr, addr))
        map(lambda r: pytable_utils._print(cls.func_row_info(r)), rows)

        print "longwrites --"
        rows = pytable_utils.get_rows(longwrites,
                                      "((breakaddr <= 0x%x) & (0x%x <= contaddr)) |"
                                      "((breakaddr <= 0x%x) & (0x%x <= writeaddr))"
                                      % (addr, addr, addr, addr))
        map(lambda r: pytable_utils_print(cls.longwrite_row_info(r)), rows)

        print "skips --"
        rows = pytable_utils.get_rows(skips,
                                      "(pc <= 0x%x) & (0x%x <= resumepc)"
                                      % (addr, addr))
        map(lambda r: pytable_utils._print(cls.skip_row_info(r)), rows)
        print "---------------------------------------"

    @classmethod
    def write_row_info(cls, r):
        regs = ", ".join([reg for reg in [r['reg%d' % i] for i in range(0, 5)] if len(reg) > 0])
        return "pc=0x{:x}, thumb={}, regs=({}) writesz={}, halt={}"\
            .format(r['pc'], str(r['thumb']), regs, r['writesize'], str(r['halt']))

    @classmethod
    def src_row_info(cls, r):
        return "pc=0x{:x}, thumb={}, mne={}, disasm={}, ivalue={}, ilen={}, src={}, line={}"\
            .format(r['addr'], r['thumb'], r['mne'],
                    r['disasm'], r['ivalue'].encode('hex'),
                    r['ilength'], r['src'], r['line'])

    def reloc_row_info(self, r):
        return "Reloc {} ({:x}-{:x}) to {:x} starting at pc {:x} ready at pc {:x}".format(
            r['name'],
            r['startaddr'], r['startaddr'] + r['size'],
            r['startaddr'] + r['reloffset'],
            r['relbegin'], r['relocpc'])

    @classmethod
    def func_row_info(cls, r):
        return "name={}, startaddr={:x}, endaddr={:x}".format(
            r['fname'], r['startaddr'], r['endaddr'])

    @classmethod
    def smc_row_info(cls, r):
        return "pc={:x}, thumb={}".format(r['pc'], r['thumb'])

    @classmethod
    def skip_row_info(cls, r):
        return "pc={:x}, resumepc={:x}, thumb={}, disasm={}".format(
            r['pc'], r['resumepc'], r['thumb'], r['disasm']
        )

    @classmethod
    def longwrite_row_info(cls, r):
        sregs = ", ".join([reg for reg in [r['sreg%d' % i] for i in range(0, 5)] if len(reg) > 0])
        eregs = ", ".join([reg for reg in [r['ereg%d' % i] for i in range(0, 5)] if len(reg) > 0])
        rangetype = LongWriteRangeType.rangetypes.keys()[r['rangetype']]
        return "break={:x}, write={:x}, cont={:x}, sregs=({}), eregs=({}), " \
            "destsubtract={}, endvalue=0x{:x}, startvalue=0x{:x}, writesz=0x{:x}, " \
            "interval={}, thumb={}, inplace={}, rangetype={}".format(
                r['breakaddr'], r['writeaddr'], r['contaddr'], sregs,
                eregs, r['destsubtract'], r['endvalue'], r['startvalue'],
                r['writesize'], r['interval'], r['thumb'], r['inplace'], rangetype
            )
    def is_arm(self):
        elf = self.stage.elf
        o = Main.shell.run_cmd("%sreadelf -h %s| grep Machine" % (Main.cc, elf))
        o = o.split()
        return o[1] == "ARM"


    def create_writes_table(self, start=0, stop=0):
        self.writestable = self.h5file.create_table(self.group, 'writes',
                                                    WriteEntry,
                                                    "statically determined pc \
                                                    values for write instructions")
        self.smcstable = self.h5file.create_table(self.group, 'smcs', SmcEntry,
                                                  "statically determined pc values \
                                                  for smc instructions")
        self.srcstable = self.h5file.create_table(self.group, 'srcs',
                                                  SrcEntry, "source code info")
        # now look at instructions
        if not self.is_arm():
            return
        srcdir = Main.get_runtime_config("temp_target_src_dir")

        allranges = intervaltree.IntervalTree()
        for s in utils.get_section_headers(self.stage):
            if s['flags'].endswith('x'):
                if s['size'] == 0:
                    continue
                allranges.add(intervaltree.Interval(s['address'], s['address'] + s['size']))
        allranges.merge_overlaps()


        r = self.writestable.row
        smcr = self.smcstable.row
        allranges = self.thumbranges | self.armranges

        # loop through all instructions as according to debug symbols
        for (ra, thumb) in [(self.thumbranges, True), (self.armranges, False)]:
            for ir in ra:
                #r2.get(self.stage.elf, "s 0x%x" % ir.begin)
                #pc = ir.begin
                #if thumb:
                #    r2.gets(self.stage.elf, "e asm.bits=16")
                #else:
                #    r2.gets(self.stage.elf, "e asm.bits=32")
                #if thumb:
                #    step = 2
                #else:
                #    step = 4
                #r2.gets(self.stage.elf, 'e asm.arch=arm')
                pc_next = ir.begin
                # print "\nanal (%x,%x), %s" % (ir.begin, ir.end, thumb)

                while pc_next < ir.end:
                    # sys.stdout.write("%x, " % pc_next)
                    pc = pc_next
                    p = False
                    #if pc_next == 0x40208b50:
                    #    p = True
                    r2.gets(self.stage.elf, "s 0x%x" % pc)
                    if thumb: # force r2 to use the correct instruction size. sigh.
                        r2.gets(self.stage.elf, "ahb 16")
                        r2.gets(self.stage.elf, "e asm.bits=16")
                    else:
                        r2.gets(self.stage.elf, "ahb 32")
                        r2.gets(self.stage.elf, "e asm.bits=32")
                    r2.get(self.stage.elf, "pd 1")
                    ins_info = r2.get(self.stage.elf, "pdj 1")[0]
                    if p:
                        for k,v in ins_info.iteritems():
                            print "%s: %s" % (k, v)
                        print "offset %x" % ins_info["offset"]
                    insadded = False
                    if not "disasm" in ins_info or u"invalid" == ins_info["type"] or u"invalid" == ins_info["disasm"]:
                        print "invalid instruction according to r2: pc: %x, is thumb? %s. Using capstone to disassemble" % (pc, thumb)
                        if 'bytes' in ins_info: # get results of capstone disassembly
                            inscheck = self.ia.disasm(b"%s" % ins_info['bytes'].decode("hex"), thumb, pc)
                            ins_info['disasm'] = inscheck.mnemonic + " " + inscheck.op_str
                        else:
                            print ins_info
                            raise Exception()
                    pc = ins_info['offset']
                    dis = ins_info['disasm']
                    val = ins_info['bytes']
                    mne = dis.split()[0]
                    ins = b"%s" % val.decode('hex')
                    pc_next += ins_info['size']
                    #... just in case radare2 doesn't properly report invalid instructions
                    try:
                        inscheck = self.ia.disasm(ins, thumb, pc)
                    except StopIteration:
                        print "Radare2 disassembled invalid instruction 0x%x (%s) as %s" % (pc, val, ins_info)
                        continue
                    if mne != inscheck.mnemonic:
                        if thumb:
                            r2.gets(self.stage.elf, "e asm.bits=16")
                            r2.gets(self.stage.elf, "ahb 16")
                        else:
                            r2.gets(self.stage.elf, "ahb 32")
                            r2.gets(self.stage.elf, "e asm.bits=32")
                        print "R2 and capstone disagree at %x %s" % (pc, thumb)
                        print "CAPSTONE --->"
                        print "addr: %x" % inscheck.address
                        print "op: %s" % inscheck.op_str
                        print "mne: %s" % inscheck.mnemonic
                        print "byres: %s" % ["%x" %b for b in inscheck.bytes]
                        print "size: %s" % inscheck.size
                        print "r2 ------------------------>"
                        print r2.gets(self.stage.elf, "e asm.bits")
                        for (k,v) in ins_info.iteritems():
                            print "%s: %s" % (k, v)
                        r2.get(self.stage.elf, "s 0x%x" % pc)
                        print r2.gets(self.stage.elf, "pd 1")
                        if self.ia.is_mne_memstore(mne) or self.ia.is_mne_memstore(inscheck.mnemonic):
                            raise Exception
                        print "... But I guess it doesn't matter because neither instruction modifies memory."
                    if mne and self.ia.is_mne_memstore(mne):
                        if self.dataranges.overlaps_point(pc):
                            continue
                        r['thumb'] = thumb
                        r['pc'] = pc
                        r['halt'] = True
                        regs = self.ia.needed_regs(inscheck)
                        if len(regs) > 4:
                            raise Exception("Sorry, too many registers")
                        for i in range(len(regs)):
                            r['reg%d' % i] = regs[i]
                        size = self.ia.calculate_store_size(inscheck)

                        r['writesize'] = size
                        insadded = True
                        r.append()
                    elif mne == 'smc':  # add to smcs table
                        smcr['pc'] = pc
                        mne = 'smc'
                        thumb = False
                        if self.thumbranges.overlaps_point(pc):
                            thumb = True
                        smcr['thumb'] = thumb
                        insadded = True
                        smcr.append()
                        if self.verbose:
                            print "smc at 0x%x" % pc
                    if insadded: # also cache source code information related to instruction
                        s = self.srcstable.where("addr == 0x%x" % (pc))
                        try:
                            s = next(s)
                            # is in table, do nothing
                        except StopIteration:
                            srcr = self.srcstable.row
                            srcr['addr'] = pc
                            srcr['line'] = utils.addr2line(pc, self.stage)
                            srcr['src'] = utils.line2src(srcr['line'])
                            srcr['ivalue'] = ins
                            srcr['ilength'] = len(ins)
                            srcr['thumb'] = thumb
                            srcr['disasm'] = dis
                            srcr['mne'] = mne
                            srcr.append()
                            self.srcstable.flush()
                        insadded = False
        self.writestable.flush()
        self.writestable.cols.pc.create_index(kind='full')
        self.writestable.flush()
        self.smcstable.flush()
        self.smcstable.cols.pc.create_index(kind='full')
        self.smcstable.flush()
        self.srcstable.cols.addr.create_index(kind='full')
        self.srcstable.cols.line.create_index(kind='full')
        self.srcstable.flush()


        self.smcstable.flush()
        self.h5file.flush()

    def create_funcs_table(self): # using symbol information to get function location and length
        # symbol information (lenfth) does not always agree with objdump, but that's ok
        # (example: u-boot, get_tbclk)
        self.funcstable = self.h5file.create_table(self.group, 'funcs',
                                                    FuncEntry, "function info")
        cmd = "%snm -S -n --special-syms %s 2>/dev/null" % (Main.cc, self.stage.elf)
        output = subprocess.check_output(cmd, shell=True).split('\n')
        r = self.funcstable.row
        for o in output:
            cols = o.split()
            if len(cols) == 4:
                (addr, size, typ, name) = cols
                addr = int(addr, 16)
                size = int(size, 16)
                r['fname'] = name
                r['startaddr'] = addr
                r['endaddr'] = addr + size
                r.append()
        self.funcstable.cols.startaddr.create_index(kind='full')
        self.funcstable.cols.endaddr.create_index(kind='full')
        self.funcstable.flush()
        self.h5file.flush()


        #     if len(cols) == 3 and dta.search(o):
        #         if last_name is not None:
        #             r['fname'] = last_name
        #             r['startaddr'] = last_addr
        #             r['endaddr'] = last_addr + last_size
        #             r.append()
        #         last_addr = None
        #         last_name = None
        #         last_size = None
        #         last_typ = None
        #     elif len(cols) == 4:
        #         (addr, size, typ, name) = cols
        #         size = int(size, 16)
        #         addr = int(addr, 16)
        #         typ = typ.lower()
        #         if last_name is not None: # then last ends were next begins
        #             r['fname'] = last_name
        #             r['startaddr'] = last_addr
        #             r['endaddr'] = addr
        #             r.append()
        #         last_name = name
        #         last_addr = addr
        #         last_size = size
        #         last_typ = typ
        # if last_name is not None:
        #     r['fname'] = last_name
        #     r['startaddr'] = last_addr
        #     r['endaddr'] = last_addr + last_size
        #     r.append()
