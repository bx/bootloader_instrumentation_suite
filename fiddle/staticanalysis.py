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
from memory_tree import intervaltree
import testsuite_utils as utils
import labeltool
import pytable_utils
from config import Main
import numpy
import importlib
import db_info
from ia import InstructionAnalyzer
import r2_keeper as r2


# def int_repr(self):
#     return "({0:08X}, {1:08X})".format(self.begin, self.end)


# intervaltree.Interval.__str__ = int_repr
# intervaltree.Interval.__repr__ = int_repr



class LongWriteInfo():
    def __init__(self, elf, start, end, thumb):
        r2.run_aab(elf) # run basic block analysis
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
    pc = tables.UInt64Col()
    pclo = tables.UInt32Col()
    pchi = tables.UInt32Col()
    thumb = tables.BoolCol()
    reg0 = tables.StringCol(4)
    reg1 = tables.StringCol(4)
    reg2 = tables.StringCol(4)
    reg3 = tables.StringCol(4)
    reg4 = tables.StringCol(4)
    writesize = tables.Int64Col()
    halt = tables.BoolCol()  # whether to insert a breakpoint here


class SrcEntry(tables.IsDescription):
    addr = tables.UInt64Col()
    addrlo = tables.UInt32Col()
    addrhi = tables.UInt32Col()
    line = tables.StringCol(512)  # file/lineno
    src = tables.StringCol(512)  # contents of source code at this location
    ivalue = tables.StringCol(12)
    ilength = tables.UInt8Col()
    thumb = tables.BoolCol()
    mne = tables.StringCol(10)
    disasm = tables.StringCol(256)


class RelocInfo(tables.IsDescription):
    startaddr = tables.UInt64Col()  # first address in relocation block
    startaddrlo = tables.UInt32Col()  # first address in relocation block
    startaddrhi = tables.UInt32Col()  # first address in relocation block
    size = tables.UInt64Col()  # number of relocated bytes
    relocpc = tables.UInt64Col()  # what the pc is once it is relocated
    relocpclo = tables.UInt32Col()  # what the pc is once it is relocated
    relocpchi = tables.UInt32Col()  # what the pc is once it is relocated
    reldelorig = tables.BoolCol()  # whether to delete the original once relocated
    reloffset = tables.Int64Col()  # (orig addr + offset) % relmod  = new address
    relmod = tables.UInt64Col()
    relbegin = tables.UInt64Col()  # address of where relocation starts happening
    name = tables.StringCol(255)
    symname = tables.StringCol(128)
    cardinal = tables.UInt8Col()


class StageExitInfo(tables.IsDescription):
    addr = tables.UInt64Col()  # non-relocated addr
    addrlo = tables.UInt32Col()  # non-relocated addr
    addrhi = tables.UInt32Col()  # non-relocated addr
    success = tables.BoolCol()
    line = tables.StringCol(512)  # file/lineno


class SmcEntry(tables.IsDescription):
    pc = tables.UInt64Col()
    pclo = tables.UInt32Col()
    pchi = tables.UInt32Col()
    thumb = tables.BoolCol()


class FuncEntry(tables.IsDescription):
    fname = tables.StringCol(40)  # name of function pc is located
    startaddr = tables.UInt64Col()  # first address in relocation block
    startaddrlo = tables.UInt32Col()  # first address in relocation block
    startaddrhi = tables.UInt32Col()  # first address in relocation block
    endaddr = tables.UInt64Col()  # first address in relocation block
    endaddrlo = tables.UInt32Col()  # first address in relocation block
    endaddrhi = tables.UInt32Col()  # first address in relocation block


class LongWrites(tables.IsDescription):
    breakaddr = tables.UInt64Col()  # where write loop starts
    breakaddrlo = tables.UInt32Col()  # where write loop starts
    breakaddrhi = tables.UInt32Col()  # where write loop starts
    writeaddr = tables.UInt64Col()  # where write loop starts
    writeaddrlo = tables.UInt32Col()  # where write loop starts
    writeaddrhi = tables.UInt32Col()  # where write loop starts
    contaddr = tables.UInt64Col()  # pc after loop
    thumb = tables.BoolCol()  # if write is at thumb address
    inplace = tables.BoolCol()
    writesize = tables.UInt64Col()
    start = tables.UInt64Col()
    startlo = tables.UInt32Col()
    starthi = tables.UInt32Col()
    end = tables.UInt64Col()
    endlo = tables.UInt32Col()
    endhi = tables.UInt32Col()


class SkipEntry(tables.IsDescription):
    pc = tables.UInt64Col()
    pclo = tables.UInt32Col()
    pchi = tables.UInt32Col()
    disasm = tables.StringCol(256)
    thumb = tables.BoolCol()
    resumepc = tables.UInt64Col()
    resumepclo = tables.UInt32Col()
    resumepchi = tables.UInt32Col()
    isfunction = tables.BoolCol()


class LongWriteDescriptorGenerator():
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
        return LongWriteDescriptor(writestart, writeend,
                                    self.inplace, self.table)


class LongWriteDescriptor():
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

        ins = self.table.ia.disasm(b"%s" % self.info.write_ins["bytes"].decode("hex"),
                                   self.thumb,
                                   self.info.write_ins["offset"])
        self.write_size = self.table.ia.calculate_store_size(ins)
        self.breakaddr = self.info.start_ins_addr
        self.writeaddr = self.info.write_ins_addr
        self.contaddr = self.info.finish_ins_addr
        writes = self.table.writestable.where("(0x%x == pclo) & (0x%x == pchi)" % (utils.addr_lo(self.writeaddr),
                                                                                    utils.addr_hi(self.writeaddr)))
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
        r['breakaddrlo'] = utils.addr_lo(self.breakaddr)
        r['breakaddrhi'] = utils.addr_hi(self.breakaddr)
        r['contaddr'] = self.contaddr
        r['inplace'] = self.inplace
        r['writeaddr'] = self.writeaddr
        r['writeaddrlo'] = utils.addr_lo(self.writeaddr)
        r['writeaddrhi'] = utils.addr_hi(self.writeaddr)
        r['thumb'] = self.thumb
        r['writesize'] = self.writesize
        r['start'] = self.start
        r['startlo'] = utils.addr_lo(self.start)
        r['starthi'] = utils.addr_hi(self.start)
        r['end'] = self.end
        r['endlo'] = utils.addr_lo(self.end)
        r['endhi'] = utils.addr_hi(self.end)

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
            'relocpclo': utils.addr_lo(self.readyaddr),
            'relocpchi': utils.addr_hi(self.readyaddr),
            'relmod': self.relmod,
            'startaddr': self.cpystartaddr,
            'startaddrlo': utils.addr_lo(self.cpystartaddr),
            'startaddrhi': utils.addr_hi(self.cpystartaddr),
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
                f = pytable_utils.get_unique_result(self.table.funcstable, ("(startaddrlo <= 0x%x) & (0x%x < endaddrlo) & (startaddrhi <= 0x%x) & (0x%x <= endaddrhi)" %
                                                                            (utils.addr_lo(startaddr),
                                                                             utils.addr_lo(startaddr),
                                                                             utils.addr_hi(startaddr),
                                                                             utils.addr_hi(startaddr))))

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

        s = long(startaddr + self.adjuststart)
        e = long(endaddr + self.adjustend)
        if e < s:
            t = s
            s = e
            e = t
        row['pc'] = s
        row['pclo'] = utils.addr_lo(s)
        row['pchi'] = utils.addr_hi(s)
        row['resumepc'] = e
        row['resumepclo'] = utils.addr_lo(e)
        row['resumepchi'] = utils.addr_hi(e)
        row['isfunction'] = isfunc
        row['thumb'] = self.table.thumbranges.overlaps_point(row['pc'])
        return row


class ThumbRanges():
    @staticmethod
    def find_thumb_ranges(stage, noop=False):
        cc = Main.cc
        elf = stage.elf
        thumb = intervaltree.IntervalTree()
        arm = intervaltree.IntervalTree()
        data = intervaltree.IntervalTree()
        if noop:
            return (thumb, arm, data)
        cmd = "%snm -S -n --special-syms %s 2>/dev/null" % (cc, elf)
        output = subprocess.check_output(cmd, shell=True).split('\n')
        prev = None
        lo = 0
        dta = re.compile('\s+[a-zA-Z]\s+\$[tad]$')
        for o in output:
            o = o.strip()
            if dta.search(o):
                hi = long(o[:8], 16)
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

        query = "(0x%x <= pclo) & (0x%x <= pchi) & (pclo < 0x%x) & (pchi <= 0x%x)" % \
            (utils.addr_lo(startlineaddr),
             utils.addr_hi(startlineaddr),
             utils.addr_lo(endlineaddr),
             utils.addr_hi(endlineaddr))
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
                                                        LongWrites, "long writes to precompute")
        skips = []
        if not self.is_arm():
            return
        r2.run_aab(self.stage.elf) # run basic block analysis
        for r in self.stage.longwrites:
            skips.append(LongWriteDescriptorGenerator(r.name,
                                                      r.inplace,
                                                      self))
        for s in skips:
            r = self.longwritestable.row
            sdesc = s.generate_descriptor()
            if not sdesc:
                print "We didn't find any longwrite labels for %s" % s.name
                continue
            # to prevent duplicate entries
            query = "(breakaddrlo == 0x%x) & (breakaddrhi == 0x%x)" % \
                (utils.addr_lo(sdesc.breakaddr), utils.addr_hi(sdesc.breakaddr))
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
        self.longwritestable.cols.breakaddrlo.create_index(kind='full')
        self.longwritestable.cols.breakaddrhi.create_index(kind='full')
        self.longwritestable.flush()
        self.writestable.flush()
        self.h5file.flush()


    @classmethod
    def find_label(cls, lclass, value, stage, name):
        res = cls.find_labels(lclass, value, stage, name)
        if not (len(res) == 1):
            raise Exception("Found 0 or +1 labels of class=%s, value=%s, stage=%s, name=%s"
                            % (cls.__name__, value, stage.stagename, name))
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
            r['addrlo'] = utils.addr_lo(addr)
            r['addrhi'] = utils.addr_hi(addr)
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
        self.relocstable.cols.startaddrlo.create_index(kind='full')
        self.relocstable.cols.startaddrhi.create_index(kind='full')
        self.relocstable.cols.relocpclo.create_index(kind='full')
        self.relocstable.cols.relocpchi.create_index(kind='full')

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
    def _is_arm(self, elf):
        o = Main.shell.run_cmd("%sreadelf -h %s| grep Machine" % (Main.cc, elf))
        o = o.split()
        return o[1] == "ARM"

    def is_arm(self):
        elf = self.stage.elf
        return self._is_arm(elf)


    def update_from_trace(self, tracewrites):
        for w in tracewrites:
            pc = long(w["pc"])
            thumb = self.thumbranges.overlaps_point(pc)
            s = self.srcstable.where("(addrlo == 0x%x) & (addrhi == 0x%x)" %
                                     (utils.addr_lo(pc),
                                      utils.addr_hi(pc)))
            try:
                s = next(s)
                # is in table, do nothing
            except StopIteration:
                r2.gets(self.stage.elf, "s 0x%x" % pc)
                i = r2.get(self.stage.elf, "pdj 1")[0]
                ins = b"%s" % i["bytes"]
                dis = i["disasm"]
                mne = dis.split()[0]
                srcr = self.srcstable.row
                srcr['addr'] = pc
                srcr['addrlo'] = utils.addr_lo(pc)
                srcr['addrhi'] = utils.addr_hi(pc)
                srcr['line'] = utils.addr2line(pc, self.stage)
                srcr['src'] = utils.line2src(srcr['line'])
                srcr['ivalue'] = ins
                srcr['ilength'] = len(ins)
                srcr['thumb'] = thumb
                srcr['disasm'] = dis
                srcr['mne'] = mne
                srcr.append()
                ws = self.writestable.row
                ws['thumb'] = thumb
                ws['pc'] = pc
                ws['pclo'] = utils.addr_lo(pc)
                ws['pchi'] = utils.addr_hi(pc)
                ws['writesize'] = w['reportedsize']
                ws['halt'] = False
                ws.append
        self.srcstable.flush()
        self.srcstable.reindex()
        self.writestable.flush()
        self.writestable.reindex()
        self.h5file.flush()

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
                allranges.add(intervaltree.Interval(long(s['address']),
                                                    long(s['address'] + s['size'])))
        allranges.merge_overlaps()

        r = self.writestable.row
        smcr = self.smcstable.row
        allranges = self.thumbranges | self.armranges

        # loop through all instructions as according to debug symbols
        for (ra, thumb) in [(self.thumbranges, True), (self.armranges, False)]:
            for ir in ra:
                pc_next = ir.begin
                while pc_next < ir.end:
                    pc = pc_next
                    p = False
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
                        r['pclo'] = utils.addr_lo(pc)
                        r['pchi'] = utils.addr_hi(pc)
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
                        smcr['pclo'] = utils.addr_lo(pc)
                        smcr['pchi'] = utils.addr_hi(pc)
                        mne = 'smc'
                        thumb = False
                        if self.thumbranges.overlaps_point(pc):
                            thumb = True
                        smcr['thumb'] = thumb
                        insadded = True
                        smcr.append()
                        if self.verbose:
                            print "smc at 0x%x" % pc
                    if insadded:  # also cache source code information related to instruction
                        s = self.srcstable.where("(addrlo == 0x%x) & (addrhi == 0x%x)" %
                                                 (utils.addr_lo(pc),
                                                  utils.addr_hi(pc)))
                        try:
                            s = next(s)
                            # is in table, do nothing
                        except StopIteration:
                            srcr = self.srcstable.row
                            srcr['addr'] = pc
                            srcr['addrlo'] = utils.addr_lo(pc)
                            srcr['addrhi'] = utils.addr_hi(pc)
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
        self.writestable.cols.pclo.create_index(kind='full')
        self.writestable.cols.pchi.create_index(kind='full')
        self.smcstable.flush()
        self.smcstable.cols.pclo.create_index(kind='full')
        self.smcstable.cols.pchi.create_index(kind='full')
        self.srcstable.flush()
        self.srcstable.cols.addrlo.create_index(kind='full')
        self.srcstable.cols.addrhi.create_index(kind='full')
        self.srcstable.cols.line.create_index(kind='full')
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
                addr = long(addr, 16)
                size = long(size, 16)
                r['fname'] = name
                r['startaddr'] = addr
                r['startaddrlo'] = utils.addr_lo(addr)
                r['startaddrhi'] = utils.addr_hi(addr)
                r['endaddr'] = addr + size
                r['endaddrlo'] = utils.addr_lo(addr + size)
                r['endaddrhi'] = utils.addr_hi(addr + size)
                r.append()
        self.funcstable.cols.startaddrlo.create_index(kind='full')
        self.funcstable.cols.endaddrlo.create_index(kind='full')
        self.funcstable.cols.startaddrhi.create_index(kind='full')
        self.funcstable.cols.endaddrhi.create_index(kind='full')

        self.funcstable.flush()
        self.h5file.flush()
