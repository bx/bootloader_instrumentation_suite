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

from unicorn import *
from unicorn.arm_const import *

import logging
import re
import tables
import qemusimpleparse
import testsuite_utils as utils
from config import Main
import capstone
from capstone.arm import *
import staticanalysis
import traceback
import pytable_utils
from memory_tree import intervaltree
import db_info
import substage
import sys
import pure_utils
from capstone import *
import os
l = logging.getLogger("")


class FramaCDstEntry(tables.IsDescription):
    line = tables.StringCol(512)  # file/lineno
    lvalue = tables.StringCol(512)  # lvalue as reported by framac
    dstlo = tables.UInt64Col()  # low value of write dst range
    dstlolo = tables.UInt32Col()  # low value of write dst range
    dstlohi = tables.UInt32Col()  # low value of write dst range
    dsthi = tables.UInt64Col()  # high value of write dst range
    dsthilo = tables.UInt32Col()  # high value of write dst range
    dsthihi = tables.UInt32Col()  # high value of write dst range
    dst_not_in_ram = tables.BoolCol()  # true if range is not RAM
    writepc = tables.UInt64Col()  # corresponding store instruction PC to src line (if just 1)
    writepclo = tables.UInt32Col()  # corresponding store instruction PC to src line (if just 1)
    writepchi = tables.UInt32Col()  # corresponding store instruction PC to src line (if just 1)
    origpc = tables.UInt64Col()  # corresponding store instruction PC to src line (if just 1)
    origpclo = tables.UInt32Col()  # corresponding store instruction PC to src line (if just 1)
    origpchi = tables.UInt32Col()  # corresponding store instruction PC to src line (if just 1)
    substage = tables.UInt8Col()


class WriteDstTable():
    def _find_mux_pc(self, dst):
        user = {'res': None,
                'dst': long(dst)}

        def code_hook(emu, access, addr, size, value, user):
            dst = long(user['dst'])
            if long(addr) == dst:
                pc = emu.reg_read(UC_ARM_REG_PC)
                user['res'] = pc

            return True
        user['dst'] = dst
        user['dstlo'] = utils.addr_lo(dst)
        user['dsthi'] = utils.addr_hi(dst)
        h = self.emu.hook_add(UC_HOOK_MEM_WRITE, code_hook, user_data=user)
        if self._thumb:
            self.emu.emu_start(self._mux_start | 1, self._mux_end)
        else:
            self.emu.emu_start(self._mux_start, self._mux_end)
        self.emu.hook_del(h)
        if user['res'] is None:
            raise Exception("DSF %x" % dst)
        return user['res']

    def __init__(self, h5file, group, stage, name, desc=""):
        self.h5file = h5file
        self.group = group
        self.stage = stage
        self._name = name
        self.desc = desc
        self.tables = {}
        if hasattr(stage, "write_dst_init"):
            getattr(self, getattr(stage, "write_dst_init"))()
        self.thumbranges = getattr(Main.raw.runtime.thumb_ranges, self.stage.stagename)()[0]
        self.open()

    def name(self, num):
        return "%s_%s" % (self._name, num)

    def open(self, force=False):
        nums = substage.SubstagesInfo.substage_numbers(self.stage)
        for s in nums:
            self._init_table(s, force)

    def purge(self):
        self.tables = {}
        self.open(True)

    def _init_table(self, num, force=False):
        try:
            self.tables[num] = getattr(self.group, self.name(num))
            if force:
                self.h5file.remove_node(self.group, self.name(num))
                self.tables[num] = None
        except tables.exceptions.NoSuchNodeError:
            self.tables[num] = None

        if self.tables[num] is None:
            self.tables[num] = self.h5file.create_table(self.group, self.name(num),
                                                        FramaCDstEntry, self.desc)
            self.tables[num].cols.writepclo.create_index(kind='full')
            self.tables[num].cols.writepchi.create_index(kind='full')
            self.tables[num].cols.line.create_index(kind='full')
            self.tables[num].cols.substage.create_index(kind='full')
            self.tables[num].flush()
            self.h5file.flush()

    def flush_table(self):
        nrows = 0
        for t in self.tables.itervalues():
            try:
                t.reindex_dirty()
            except:
                pass
            t.flush()
        self.h5file.flush()

    def _addr_inter_is_not_ram(self, i):
        hw = Main.get_hardwareclass_config()
        return i in hw.non_ram_ranges

    def uboot_mux_init(self):
        self._mux_name = "set_muxconf_regs"
        (self._mux_start, self._mux_end) = utils.get_symbol_location_start_end(self._mux_name,
                                                                               self.stage)
        self._mux_start += 2
        self._mux_end -= 2
        if self.thumbranges.overlaps_point(self._mux_start):
            self.cs = capstone.Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            self.cs.detail = True
            self._thumb = True
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        else:
            self.cs = capstone.Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.cs.detail = True
            self._thumb = False
            self.emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        entrypoint = self._mux_start
        headers = pure_utils.get_section_headers(elf)
        for h in headers:
            if h['size'] > 0:
                codeaddr = h['virtaddr']
                break
        alignedstart = self._mux_start & 0xFFFFF0000
        size = 2*1024*1024
        fileoffset = alignedstart
        elf = stage.elf
        code = open(elf, "rb").read()[self._mux_start-fileoffset:self._mux_end-fileoffset]
        hw = Main.get_hardwareclass_config()
        for i in hw.addr_range:
            if i.begin == 0:
                size = i.end
            else:
                size = i.begin - i.end
            self.emu.mem_map(i.begin, size, UC_PROT_ALL)

        self.emu.mem_write(self._mux_start, code)
        self.emu.reg_write(self.stage.elf.entrypoint, ARM_REG_SP)

    def uboot_mux(self, dstinfo):
        # hack
        path = dstinfo.path
        cmd = 'grep -n "MUX_BEAGLE();" %s' % path
        lineno = Main.shell.run_cmd(cmd, catcherror=True)
        if lineno:
            # so sorry, this is a hack to deal with the annoying amount of writes
            # squished into a u-boot macro
            lineno = int(lineno.split(":")[0])
            if path.endswith("board/ti/beagle/beagle.c") and lineno == dstinfo.lineno:
                dstinfo.pc = self._find_mux_pc(v.begin)

        else:
            dstinfo.pc = db_info.get(self.stage).get_write_pc_or_zero_from_dstinfo(dstinfo)

    def add_dsts_entry(self, dstinfo):
        num = dstinfo.substage
        if num not in self.tables.iterkeys():
            self._init_table(num)
        r = self.tables[num].row
        for v in dstinfo.values:
            r['dstlo'] = v.begin
            r['dstlolo'] = utils.addr_lo(v.begin)
            r['dstlohi'] = utils.addr_hi(v.begin)
            r['dsthi'] = v.end
            r['dsthilo'] = utils.addr_lo(v.end)
            r['dsthihi'] = utils.addr_hi(v.end)
            r['dst_not_in_ram'] = self._addr_inter_is_not_ram(v)
            r['substage'] = dstinfo.substage
            line = dstinfo.key()
            r['line'] = line
            r['lvalue'] = dstinfo.lvalue
            if not dstinfo.pc:
                if hasattr(self.stage, "write_dest_hook"):
                    hook = getattr(self, getattr(self.stge, "write_dest_hook"))
                    hook(dstinfo)

            if dstinfo.pc == 0:
                print "cannot resove just one write instruction from %s" % dstinfo.__dict__
                continue
            r['writepc'] = dstinfo.pc
            r['writepclo'] = utils.addr_lo(dstinfo.pc)
            r['writepchi'] = utils.addr_hi(dstinfo.pc)
            r['origpc'] = dstinfo.origpc if dstinfo.origpc else long(r['writepc'])
            r['origpclo'] = utils.addr_lo(long(r['origpc']))
            r['origpchi'] = utils.addr_hi(long(r['origpc']))
            r.append()

    def print_dsts_info(self):
        self.flush_table()
        num_writes = db_info.get(self.stage).num_writes()
        num_framac_writes = sum([len(pytable_utils.get_rows(t, "dst_not_in_ram == True"))
                                 for t in self.tables.itervalues()])
        print "%d of %d writes exclusively write "\
            "to register memory" % (num_framac_writes,
                                    num_writes)
        for t in self.tables.itervalues():
            for r in t.iterrows():
                print "%s (%x) -> (%x,%x). substage: %s" % \
                    (r['line'], r['writepc'], r['dstlo'], r['dsthi'], r['substage'])

    def nrows(self):
        return sum([t.nrows for t in self.tables.itervalues()])


class WriteDstResult():
    regexp = re.compile("^\[dst\] \[(0[xX][0-9a-fA-F]+), (0[xX][0-9a-fA-F]+)\] "
                        "([\(\)a-zA-Z0-9\-\_\[\]\> \*\&\.]+) in "
                        "([\/a-zA-Z0-9\_\-\.]+):([0-9]+) .. ([\S]+)$")

    @classmethod
    def is_dst_result(cls, line):
        return cls.regexp.match(line.strip()) is not None

    @classmethod
    def from_line(cls, line, stage):
        res = cls.regexp.match(line.strip())
        if res is None:
            raise Exception("%s is not a framac dst result")
        else:
            min_value = long(res.group(1), 0)
            max_value = long(res.group(2), 0)
            #if max_value > 0xFFFFFFFF:
            #    max_value = 0xFFFFFFFF
            lvalue = res.group(3)
            path = res.group(4)
            # somewhat of a hack to get relative path
            root = Main.get_target_cfg().software_cfg.root
            if path.startswith(root):
                path = os.path.relpath(path, root)
                path = os.path.join(Main.raw.runtime.temp_target_src_dir, path)
            elif path.startswith(Main.test_suite_path):  # not sure why this happens
                path = os.path.relpath(path, Main.test_suite_path)
                path = os.path.join(Main.raw.runtime.temp_target_src_dir, path)
            elif path.startswith("/tmp/tmp"):
                path = "/".join(path.split("/")[3:])
                path = os.path.join(Main.raw.runtime.temp_target_src_dir, path)
            lineno = int(res.group(5))
            callstack = res.group(6)
            # somewhat of a hack for muxconf
            return cls(path, lineno, lvalue,
                       [intervaltree.Interval(min_value, max_value)],
                       callstack=callstack, stage=stage)

    def add_value(self, v):
        self.values.add(v)

    def __init__(self, path, lineno, lvalue, values, pc=None, origpc=None,
                 substage_name=None, callstack="", stage=None):
        self.path = path
        self.pc = pc
        self.origpc = origpc
        self.lineno = lineno
        self.values = intervaltree.IntervalTree()
        for v in values:
            self.values.add(v)
        self.lvalue = lvalue
        self.stage = stage
        if substage_name is None and callstack:
            policy = getattr(Main.raw.policies.substages_file, self.stage.stagename)
            get_config('policy_file', self.stage)
            self.substages = substage.SubstagesInfo.substage_names_from_file(policy)
            self.substages[0] = "frama_go"
            called_fns = callstack.split("->")
            called_fns = filter(len, called_fns)
            called_fns.reverse()
            for f in called_fns:
                if f in self.substages:
                    substage_name = self.substages.index(f)
                    break
        self.substage = substage_name

    def __eq__(self, other):
        return (self.substage == other.substage) and \
            (((self.path == other.path) and
              (self.lineno == other.lineno)) or (self.pc == other.pc))

    def __ne__(self, other):
        return not self.__eq__(other)

    def resolve_writepc(self):
        pass

    def key(self):
        # use relative path from target root
        root = Main.raw.runtime.temp_target_src_dir
        p = re.sub(root+'/', '', self.path)
        r = "%s:%d" % (p, self.lineno)
        return r

    def __str__(self):
        return "%s %s" % (self.key(), self.values)


class TraceWriteEntry(tables.IsDescription):
    index = tables.UInt32Col()
    pid = tables.UInt32Col()
    dest = tables.UInt64Col()
    destlo = tables.UInt32Col()
    desthi = tables.UInt32Col()
    pc = tables.UInt64Col()
    pclo = tables.UInt32Col()
    pchi = tables.UInt32Col()
    relocatedpc = tables.UInt64Col()
    relocatedpclo = tables.UInt32Col()
    relocatedpchi = tables.UInt32Col()
    lr = tables.UInt64Col()
    lrlo = tables.UInt32Col()
    lrhi = tables.UInt32Col()
    relocatedlr = tables.UInt64Col()
    relocatedlrlo = tables.UInt32Col()
    relocatedlrhi = tables.UInt32Col()
    time = tables.Float64Col()
    reportedsize = tables.Int64Col()
    cpsr = tables.UInt64Col()
    substage = tables.UInt8Col()
    callindex = tables.UInt32Col()


class TraceWriteRange(tables.IsDescription):
    index = tables.UInt32Col()
    destlo = tables.UInt64Col()
    destlo = tables.UInt32Col()
    destlolo = tables.UInt32Col()
    destlohi = tables.UInt32Col()
    desthi = tables.UInt64Col()
    desthilo = tables.UInt32Col()
    desthihi = tables.UInt32Col()
    pc = tables.UInt64Col()
    pclo = tables.UInt32Col()
    pchi = tables.UInt32Col()
    relocatedpc = tables.UInt64Col()
    relocatedpclo = tables.UInt32Col()
    relocatedpchi = tables.UInt32Col()
    lr = tables.UInt64Col()
    lrlo = tables.UInt32Col()
    lrhi = tables.UInt32Col()
    relocatedlr = tables.UInt64Col()
    relocatedlrlo = tables.UInt32Col()
    relocatedlrhi = tables.UInt32Col()
    byteswritten = tables.UInt64Col()
    numops = tables.UInt64Col()
    cpsr = tables.UInt64Col()
    caller = tables.StringCol(40)
    substage = tables.UInt8Col()


class TraceTable():
    h5tablename = "writes"
    writerangetablename = "write_ranges"
    consolidatedwriterangetablename = "write_ranges_consolidated"

    def __init__(self, outfile, stage, create=False, write=False):
        self.stage = stage
        self.stagename = stage.stagename
        self.cc = Main.cc
        (self._thumbranges, self._armranges, self._dataranges) = (None, None, None)
        self.outname = outfile
        self.create = create
        self.writestable = None
        if create:
            m = "w"
        else:
            self.h5file = tables.open_file(self.outname, mode="a",
                                           title="QEMU tracing information")
            try:
                self.writestable = self.get_group().writes
                m = "a"
                self.trace_count = self.writestable.nrows + 1
            except tables.exceptions.NoSuchNodeError:
                # go ahead and create table
                m = "w"
                self.h5file.close()

        if self.writestable is None:
            self.h5file = tables.open_file(self.outname, mode=m,
                                           title="QEMU tracing information")
            group = self.h5file.create_group("/", self.stagename,
                                             "Memory write information")
            self.writestable = self.h5file.create_table(group, TraceTable.h5tablename,
                                                        TraceWriteEntry,
                                                        "memory write information")
            self.trace_count = 1
            self.writestable.cols.relocatedpclo.create_index(kind='full')
            self.writestable.cols.relocatedpchi.create_index(kind='full')
            self.writestable.cols.pclo.create_index(kind='full')
            self.writestable.cols.pchi.create_index(kind='full')
            self.writestable.cols.destlo.create_index(kind='full')
            self.writestable.cols.desthi.create_index(kind='full')
            self.writestable.cols.index.create_index(kind='full')
            self.writestable.cols.callindex.create_index(kind='full')
            self.writestable.flush()
            self.hisotable = None
        if self.has_histogram():
            self.histotable = getattr(self.get_group(), 'writerange')
        self.init_writerangetable()
        self._mdthumb = None
        self._mdarm = None

        self._rinfos = None
        self._pcmax = None

    @property
    def pcmax(self):
        if self._pcmax is None:
            rmax = max([r['startaddr']+r['size']+r['reloffset'] for r in self.rinfos])
            self._pcmax = self._stage_pcmax if self._stage_pcmax > rmax else rmax
        return self._pcmax

    def _setthumbranges(self):
        (self._thumbranges,
         self._armranges,
         self._dataranges) = getattr(Main.raw.runtime.thumb_ranges, self.stage.stagename)()

    @property
    def rinfos(self):
        if self._rinfos is None:
            self._rinfos = staticanalysis.WriteSearch.get_relocation_information(self.stage)
        return self._rinfos

    @property
    def mdthumb(self):
        if self._mdthumb is None:
            self._mdthumb = capstone.Cs(capstone.CS_ARCH_ARM,
                                        capstone.CS_MODE_THUMB + capstone.CS_MODE_V8)
            self._mdthumb.detail = True
        return self._mdthumb

    @property
    def mdarm(self):
        if self._mdarm is None:
            self._mdarm = capstone.Cs(capstone.CS_ARCH_ARM,
                                      capstone.CS_MODE_ARM + capstone.CS_MODE_V8)
            self._mdarm.detail = True
        return self._mdarm

    @property
    def thumbranges(self):
        if self._thumbranges is None:
            self._setthumbranges()
        return self._thumbranges

    @property
    def armranges(self):
        if self._armranges is None:
            self._setthumbranges()
        return self._armranges

    @property
    def dataranges(self):
        if self._dataranges is None:
            self._setthumbranges()
        return self._dataranges

    def close(self, flush_only=False):
        db_info.get(self.stage).flush_staticdb()

        print "captured %s writes" % self.writestable.nrows
        self.h5file.flush()
        if not flush_only:
            self.h5file.close()

    def get_group(self):
        return self.h5file.get_node("/"+self.stagename)

    def instr2mne(self, dis):
        return dis.split()[0]

    def init_writerangetable(self):
        self.writerangetable = WriteDstTable(self.h5file,
                                             self.get_group(),
                                             self.stage,
                                             TraceTable.writerangetablename,
                                             "write information")
        self.writerangetable_consolidated = WriteDstTable(self.h5file,
                                                          self.get_group(),
                                                          self.stage,
                                                          TraceTable.consolidatedwriterangetablename,
                                                          "consolidated write information")

    def histograminfo(self, outfile=None, csvfile=None):
        group = self.get_group()
        rangetable = group.writerange
        ret = ''
        if outfile:
            outfile = open(outfile, 'w')
        if csvfile:
            csvfile = open(csvfile, 'w')
            csvfile.write("idx,pc,lrpc,numops,numbytes,substage,fn,lr,note,nudge\n")
        try:
            rs = rangetable.read_sorted('index')
        except ValueError:
            rangetable.cols.index.create_index(kind='full')
            rangetable.cols.index.reindex()
            rs = rangetable.read_sorted('index')
        i = 0
        for rangerow in rs:
            # print "%x" % rangerow['pc']
            (sdisasm, ssrc) = db_info.get(self.stage).disasm_and_src_from_pc(rangerow['pc'])
            pcfname = ''
            lrfname = ''
            pcfname = db_info.get(self.stage).addr2functionname(rangerow['pc'])
            lrfname = db_info.get(self.stage).addr2functionname(rangerow['lr'])

            r = "pc=%x/[%x] (%s) lr=%x (%s) [%x-%x] (%d) %d times -- %s -- %s\n" % \
                (rangerow['relocatedpc'], rangerow['pc'], pcfname, rangerow['lr'],
                 lrfname, rangerow['destlo'], rangerow['desthi'], rangerow['byteswritten'],
                 rangerow['numops'], sdisasm, ssrc)
            n = rangerow['byteswritten']
            if n < 0:
                n = n * -1
            r2 = "%s,0x%x,0x%x,%s,%s,%s,%s,%s,,\n" % (i,
                                                 rangerow['pc'],
                                                 rangerow['lr'],
                                                 rangerow['numops'], n,
                                                 rangerow['substage'],
                                                 pcfname, lrfname)
            if outfile:
                outfile.write(r)
            if csvfile:
                if rangerow['numops'] > 1:
                    csvfile.write(r2)
            else:
                ret = ret + r
            i += 1
        if outfile:
            outfile.close()
        if csvfile:
            csvfile.close()
        return ret

    def update_writes(self, line, pc, lo, hi, stage, origpc=None, substage=None):
        if not pc:
            (path, lineno) = line.split(':')
            lineno = int(lineno)
        else:
            (path, lineno) = ('', 0)
        if not origpc:
            origpc = pc
        w = WriteDstResult(path, lineno,
                           '',
                           [intervaltree.Interval(long(lo),
                                                  long(hi))],
                           pc, origpc, substage_name=substage)
        if lo > hi:
            print "%x > %x at %x" % (lo, hi, pc)
            traceback.print_stack()
        self.writerangetable.add_dsts_entry(w)

    def consolidate_write_table(self, framac=False):
        populated = False
        for t in self.writerangetable_consolidated.tables.itervalues():
            if t.nrows > 0:
                populated = True
                break
        if populated:
            self.writerangetable_consolidated.purge()
        last = None
        sortindex = 'line' if framac else 'writepclo'
        intervals = intervaltree.IntervalTree()
        r = None
        substagenums = substage.SubstagesInfo.substage_numbers(self.stage)
        writepc = None
        line = None
        lvalue = None
        dst_not_in_ram = True
        for n in substagenums:
            if n not in self.writerangetable_consolidated.tables.keys():
                self.writerangetable_consolidated._init_table(n)
            if n > 0:  # add last interval to previous table
                self._add_intervals_to_table(self.writerangetable_consolidated.tables[n-1],
                                             intervals,
                                             writepc, line, lvalue, dst_not_in_ram,
                                             n-1)
            print "# block writes in stage [%s]: %s" % (n, self.writerangetable.tables[n].nrows)

            last = None
            lvalue = None
            dst_not_in_ram = True
            writepc = None
            line = None
            count = 0
            intervals = intervaltree.IntervalTree()  # clear intervals

            if not framac:
                uppers = set(self.writerangetable.tables[n].read_sorted('writepchi', field='writepchi'))
                for u in uppers:
                    q = "writepchi==0x%x" % u
                    for r in self.writerangetable.tables[n].read_sorted(sortindex):
                        if not r['writepchi'] == u:
                            continue
                        if not last == r[sortindex]:
                            if last is not None:
                                self._add_intervals_to_table(self.writerangetable_consolidated.tables[n],
                                                             intervals,
                                                             writepc,
                                                             line,
                                                             lvalue,
                                                             dst_not_in_ram,
                                                             n)
                            intervals = intervaltree.IntervalTree()  # clear intervals
                            writepc = long(r['writepc'])
                            line = r['line']
                            lvalue = r['lvalue']
                            dst_not_in_ram = r['dst_not_in_ram']
                            last = r[sortindex]
                        if last is None:
                            last = r[sortindex]
                        dst_not_in_ram = dst_not_in_ram and r['dst_not_in_ram']
                        intervals.addi(long(r['dstlo']), long(r['dsthi']))
            else:
                for r in self.writerangetable.tables[n].read_sorted(sortindex): # same as above. having scope troubles so copy/pasting this code
                    if not last == r[sortindex]:
                        if last is not None:
                            self._add_intervals_to_table(self.writerangetable_consolidated.tables[n],
                                                         intervals,
                                                         writepc,
                                                         line,
                                                         lvalue,
                                                         dst_not_in_ram,
                                                         n)
                        intervals = intervaltree.IntervalTree()  # clear intervals
                        writepc = long(r['writepc'])
                        line = r['line']
                        lvalue = r['lvalue']
                        dst_not_in_ram = r['dst_not_in_ram']
                        last = r[sortindex]
                    if last is None:
                        last = r[sortindex]
                    dst_not_in_ram = dst_not_in_ram and r['dst_not_in_ram']
                    intervals.addi(long(r['dstlo']), long(r['dsthi']))

            if intervals: # and remaining interval to last stage
                self._add_intervals_to_table(self.writerangetable_consolidated.tables[n],
                                             intervals,
                                             writepc, line, lvalue, dst_not_in_ram, n)
        self.writerangetable_consolidated.flush_table()
        # for n in substagenums:
        #     print "# unique written regions for "\
        #         "stage %s: %s" % (n,
        #                                self.writerangetable_consolidated.tables[n].nrows)

    def _add_intervals_to_table(self, table, intervals, pc, line, lvalue, dst, substage):
        intervals.merge_overlaps()
        intervals.merge_equals()
        intervals.merge_overlaps()
        r = table.row
        for i in intervals:
            r['writepc'] = pc
            r['writepclo'] = utils.addr_lo(long(pc))
            r['writepchi'] = utils.addr_hi(long(pc))
            r['line'] = line
            r['lvalue'] = lvalue
            r['dst_not_in_ram'] = dst
            r['substage'] = substage
            r['dstlo'] = i.begin
            r['dstlolo'] = utils.addr_lo(i.begin)
            r['dstlohi'] = utils.addr_hi(i.begin)
            r['dsthi'] = i.end
            r['dsthilo'] = utils.addr_lo(i.end)
            r['dsthihi'] = utils.addr_hi(i.end)
            r.append()

    def has_histogram(self):
        return hasattr(self.get_group(), 'writerange')

    def histogram(self):
        group = self.get_group()

        if hasattr(group, 'writerange'):
            # make the table again, just in case
            group.writerange.remove()
        self.histotable = self.h5file.create_table(group, 'writerange',
                                              TraceWriteRange, "qemu memory write ranges")
        self.histotable.cols.index.create_index(kind='full')
        histotable = self.histotable
        srcdir = Main.raw.runtime.temp_target_src_dir
        relocatedpc = 0
        relocatedlr = 0
        size = 0
        byteswritten = 0
        destlo = 0
        currentrow = None
        line = ''
        index = 0
        push = False
        pc = -1
        sub = -1
        for writerow in self.writestable.read_sorted('index'):
            if (long(writerow['relocatedpc']) == relocatedpc) and \
               (long(writerow['relocatedlr']) == relocatedlr) and \
               ((destlo + byteswritten) == long(writerow['dest'])):
                # append to current row
                currentrow['byteswritten'] += size
                byteswritten = currentrow['byteswritten']
                if push:
                    currentrow['destlo'] = currentrow['desthi'] - byteswritten
                    currentrow['destlolo'] = utils.addr_lo(long(currentrow['destlo']))
                    currentrow['destlohi'] = utils.addr_hi(long(currentrow['destlo']))
                else:
                    currentrow['desthi'] = currentrow['destlo'] + byteswritten
                    currentrow['desthilo'] = utils.addr_lo(long(currentrow['desthi']))
                    currentrow['desthihi'] = utils.addr_hi(long(currentrow['desthi']))
                currentrow['numops'] += 1
            else:
                # create a new row
                if currentrow is not None:
                    if push:
                        push = False
                    currentrow.append()
                # start a new row
                currentrow = self.histotable.row
                pc = long(writerow['pc'])
                relocatedpc = long(writerow['relocatedpc'])
                relocatedpclo = utils.addr_lo(relocatedpc)
                relocatedpchi = utils.addr_hi(relocatedpc)
                relocatedlr = long(writerow['relocatedlr'])
                relocatedlrlo = utils.addr_lo(relocatedlr)
                relocatedlrhi = utils.addr_hi(relocatedlr)
                currentrow['cpsr'] = writerow['cpsr']
                currentrow['lr'] = long(writerow['lr'])
                currentrow['lrlo'] = utils.addr_lo(long(writerow['lr']))
                currentrow['lrhi'] = utils.addr_hi(long(writerow['lr']))
                lr = writerow['lr']
                sub = writerow['substage']
                currentrow['numops'] = 1
                currentrow['pc'] = pc
                currentrow['pclo'] = utils.addr_lo(pc)
                currentrow['pchi'] = utils.addr_hi(pc)
                currentrow['relocatedpc'] = relocatedpc
                currentrow['relocatedpclo'] = utils.addr_lo(relocatedpc)
                currentrow['relocatedpchi'] = utils.addr_hi(relocatedpc)
                currentrow['relocatedlr'] = relocatedlr
                currentrow['relocatedlrlo'] = utils.addr_lo(relocatedlr)
                currentrow['relocatedlrhi'] = utils.addr_hi(relocatedlr)
                currentrow['substage'] = sub
                currentrow['index'] = index
                index += 1
                size = db_info.get(self.stage).pc_write_size(pc)
                if size < 0:
                    desthi = long(writerow['dest'])
                    currentrow['desthi'] = desthi
                    currentrow['desthilo'] = utils.addr_lo(desthi)
                    currentrow['desthihi'] = utils.addr_hi(desthi)
                    currentrow['destlo'] = long(desthi - size)
                    currentrow['destlolo'] = utils.addr_lo(long(currentrow['destlo']))
                    currentrow['destlohi'] = utils.addr_hi(long(currentrow['destlo']))
                    size = -1*size
                    push = True
                else:
                    push = False
                    destlo = long(writerow['dest'])
                    currentrow['destlo'] = destlo
                    currentrow['destlolo'] = utils.addr_lo(destlo)
                    currentrow['destlohi'] = utils.addr_hi(destlo)

                    currentrow['desthi'] = long(destlo + size)
                    currentrow['desthilo'] = utils.addr_lo(long(currentrow['desthi']))
                    currentrow['desthihi'] = utils.addr_hi(long(currentrow['desthi']))

                byteswritten = size
                currentrow['byteswritten'] = size

        if currentrow is not None:
            currentrow.append()  # append last row
        histotable.flush()
        histotable.reindex()
        substagenums = substage.SubstagesInfo.substage_numbers(self.stage)
        print histotable.nrows
        for i in substagenums:
            print "# block writes for substage %d: %d" % (i,
                                                         len([n for n in histotable.where("substage == %d" % i)]))
        self.h5file.flush()

    def index_write_table(self):
        self.h5file.flush()

    def add_write_entry(self, time, pid, size,
                        dest, pc, lr, cpsr,
                        callindex=0, substagenum=None):
        #if self.pcmin > self.pcmax:
        #    print "PC not in range %x %x (%x)" % (self.pcmin, self.pcmax, pc)
            # traceback.print_stack()
        #if (pc <= self.pcmax) and (pc >= self.pcmin):
            # get relocation info from writesearch database
        #index = self.trace_count
        r = self.writestable.row
        r['pid'] = pid
        r['dest'] = dest
        r['relocatedpc'] = pc
        r['relocatedpclo'] = utils.addr_lo(pc)
        r['relocatedpchi'] = utils.addr_hi(pc)
        r['relocatedlr'] = lr
        r['relocatedlrlo'] = utils.addr_lo(lr)
        r['relocatedlrhi'] = utils.addr_hi(lr)
        r['time'] = time
        r['reportedsize'] = size
        r['callindex'] = callindex
        r['index'] = self.trace_count
        r['cpsr'] = cpsr
        r['pc'] = pc
        r['pclo'] = utils.addr_lo(pc)
        r['pchi'] = utils.addr_hi(pc)
        r['lr'] = lr
        r['lrlo'] = utils.addr_lo(lr)
        r['lrhi'] = utils.addr_hi(lr)
        if substagenum is not None:
            r['substage'] = substagenum
        for rinfo in self.rinfos:
            offset = rinfo['reloffset']
            start = (rinfo['startaddr']+offset)
            end = start + rinfo['size'] + offset
            # if pc is in a relocated dest range  (for now we assume no overlap)
            if (start <= pc) and (pc <= end):
                r['pc'] = pc - offset
                r['pclo'] = utils.addr_lo(long(r['pc']))
                r['pchi'] = utils.addr_hi(long(r['pc']))
                r['lr'] = lr - offset
                r['lrlo'] = utils.addr_lo(long(r['lr']))
                r['lrhi'] = utils.addr_hi(long(r['lr']))
                break
        self.trace_count += 1
        r.append()
