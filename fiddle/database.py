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
import intervaltree
import db_info
import substage
import sys
import pure_utils
from capstone import *
import os
l = logging.getLogger("")


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr

class FramaCDstEntry(tables.IsDescription):
    line = tables.StringCol(512)  # file/lineno
    lvalue = tables.StringCol(512)  # lvalue as reported by framac
    dstlo = tables.UInt32Col()  # low value of write dst range
    dsthi = tables.UInt32Col()  # high value of write dst range
    dst_not_in_ram = tables.BoolCol()  # true if range is not RAM
    writepc = tables.UInt32Col()  # corresponding store instruction PC to src line (if just 1)
    origpc = tables.UInt32Col()  # corresponding store instruction PC to src line (if just 1)
    substage = tables.UInt8Col()


class WriteDstTable():
    def _find_mux_pc(self, dst):
        user = {'res': None,
                'dst': long(dst)}

        def code_hook(emu, access, addr, size, value, user):
            dst = long(user['dst'])
            if addr == dst:
                pc = emu.reg_read(UC_ARM_REG_PC)
                user['res'] = pc

            return True
        user['dst'] = dst
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
            self.tables[num].cols.line.create_index(kind='full')
            self.tables[num].cols.writepc.create_index(kind='full')
            self.tables[num].cols.substage.create_index(kind='full')
            self.tables[num].flush()
            self.h5file.flush()

    def flush_table(self):
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
        headers = pure_utils.get_program_headers(Main.cc, elf)
        for h in headers:
            if h['filesz'] > 0:
                codeaddr = h['virtaddr']
                break
        alignedstart = self._mux_start & 0xFFFFF0000
        size = 2*1024*1024
        fileoffset = alignedstart
        elf = stage.elf        
        code = open(elf, "rb").read()[self._mux_start-fileoffset:self._mux_end-fileoffset]
        hw = Main.get_hardwareclass_config()
        for i in hw.addr_range:
            self.emu.mem_map(begin, (i.end+1)-begin)
            
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
            r['dsthi'] = v.end
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
            r['origpc'] = dstinfo.origpc if dstinfo.origpc else r['writepc']
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
            min_value = int(res.group(1), 0)
            max_value = int(res.group(2), 0)
            if max_value > 0xFFFFFFFF:
                max_value = 0xFFFFFFFF
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
    dest = tables.UInt32Col()
    pc = tables.UInt32Col()
    relocatedpc = tables.UInt32Col()
    lr = tables.UInt32Col()
    relocatedlr = tables.UInt32Col()
    time = tables.Float32Col()
    reportedsize = tables.Int32Col()
    cpsr = tables.UInt32Col()
    substage = tables.UInt8Col()


class TraceWriteRange(tables.IsDescription):
    index = tables.UInt32Col()
    destlo = tables.UInt32Col()
    desthi = tables.UInt32Col()
    pc = tables.UInt32Col()
    relocatedpc = tables.UInt32Col()
    lr = tables.UInt32Col()
    relocatedlr = tables.UInt32Col()
    byteswritten = tables.UInt32Col()
    numops = tables.UInt32Col()
    cpsr = tables.UInt32Col()
    caller = tables.StringCol(40)
    substage = tables.UInt8Col()


class TraceTable():
    h5tablename = "writes"
    writerangetablename = "write_ranges"
    consolidatedwriterangetablename = "write_ranges_consolidated"


    def __init__(self, outfile, stage, create=False, write=False):
        self.stage = stage
        #self.pcmin = stage.minpc
        #self._stage_pcmax = stage.maxpc
        self.stagename = stage.stagename
        self.cc = Main.cc
        (self._thumbranges, self._armranges, self._dataranges) = (None, None, None)
        self.outname = outfile
        self.create = create
        print "Open trace database create %s write %s, %s" % (create, write, outfile)
        if create:
            m = "a"
        self.writestable = None
        if not create:
            self.h5file = tables.open_file(self.outname, mode="a",
                                           title="QEMU tracing information")
            try:
                self.writestable = self.get_group().writes
            except tables.exceptions.NoSuchNodeError:
                # go ahead and create table
                m = "a"
                self.h5file.close()

        if self.writestable is None:
            self.h5file = tables.open_file(self.outname, mode=m,
                                           title="QEMU tracing information")
            group = self.h5file.create_group("/", self.stagename,
                                             "Memory write information")
            self.writestable = self.h5file.create_table(group, TraceTable.h5tablename,
                                                        TraceWriteEntry,
                                                        "memory write information")
            self.writestable.cols.relocatedpc.create_index(kind='full')
            self.writestable.cols.pc.create_index(kind='full')
            self.writestable.cols.index.create_index(kind='full')
            self.writestable.cols.dest.create_index(kind='full')

            self.writestable.flush()

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
            (sdisasm, ssrc) = db_info.get(self.stage).disasm_and_src_from_pc(rangerow['pc'])
            pcfname = ''
            lrfname = ''
            try:
                pcfname = next(db_info.get(self.stage).func_at_addr(rangerow['pc']))
            except StopIteration:
                pass
            try:
                lrfname = next(db_info.get(self.stage).func_at_addr(rangerow['lr']))
            except StopIteration:
                pass

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
                           [intervaltree.Interval(lo,
                                                  hi)],
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
        sortindex = 'line' if framac else 'writepc'
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
            if n > 0:  # add last interval
                self._add_intervals_to_table(self.writerangetable_consolidated.tables[n],
                                             intervals,
                                             writepc, line, lvalue, dst_not_in_ram,
                                             n)
            last = None
            lvalue = None
            dst_not_in_ram = True
            writepc = None
            line = None
            count = 0
            intervals = intervaltree.IntervalTree()  # clear intervals
            print "writerange[%s] %s" % (n, self.writerangetable.tables[n].nrows)
            for r in self.writerangetable.tables[n].read_sorted(sortindex):
                count += 1
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
                    writepc = r['writepc']
                    line = r['line']
                    lvalue = r['lvalue']
                    dst_not_in_ram = r['dst_not_in_ram']
                    last = r[sortindex]
                if last is None:
                    last = r[sortindex]
                dst_not_in_ram = dst_not_in_ram and r['dst_not_in_ram']
                intervals.addi(r['dstlo'], r['dsthi'])
            if intervals:
                self._add_intervals_to_table(self.writerangetable_consolidated.tables[n],
                                             intervals,
                                             writepc, line, lvalue, dst_not_in_ram, n)
        self.writerangetable_consolidated.flush_table()
        for n in substagenums:
            print "write range consolidated "\
                "stage %s nrows %s" % (n,
                                       self.writerangetable_consolidated.tables[n].nrows)

    def _add_intervals_to_table(self, table, intervals, pc, line, lvalue, dst, substage):
        intervals.merge_overlaps()
        intervals.merge_equals()
        intervals.merge_overlaps()
        r = table.row
        for i in intervals:
            r['writepc'] = pc
            r['line'] = line
            r['lvalue'] = lvalue
            r['dst_not_in_ram'] = dst
            r['substage'] = substage
            r['dstlo'] = i.begin
            r['dsthi'] = i.end
            r.append()

    def has_histogram(self):
        return hasattr(self.get_group(), 'writerange')

    def histogram(self):
        group = self.get_group()

        if hasattr(group, 'writerange'):
            # make the table again, just in case
            group.writerange.remove()
        histotable = self.h5file.create_table(group, 'writerange',
                                              TraceWriteRange, "qemu memory write ranges")
        histotable.cols.index.create_index(kind='full')
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
        substage = -1
        for writerow in self.writestable.read_sorted('index'):
            if (writerow['relocatedpc'] == relocatedpc) and \
               (writerow['relocatedlr'] == relocatedlr) and \
               ((destlo + byteswritten) == writerow['dest']):
                # append to current row
                currentrow['byteswritten'] += size
                byteswritten = currentrow['byteswritten']
                if push:
                    currentrow['destlo'] = currentrow['desthi'] - byteswritten
                else:
                    currentrow['desthi'] = currentrow['destlo'] + byteswritten
                currentrow['numops'] += 1
            else:
                # create a new row
                if currentrow is not None:
                    if push:
                        push = False
                    currentrow.append()
                # start a new row
                currentrow = histotable.row
                pc = writerow['pc']
                relocatedpc = writerow['relocatedpc']
                relocatedlr = writerow['relocatedlr']
                currentrow['cpsr'] = writerow['cpsr']
                currentrow['lr'] = writerow['lr']
                lr = writerow['lr']
                substage = writerow['substage']
                currentrow['numops'] = 1
                currentrow['pc'] = pc
                currentrow['relocatedpc'] = relocatedpc
                currentrow['relocatedlr'] = relocatedlr
                currentrow['substage'] = substage
                currentrow['index'] = index
                index += 1
                size = db_info.get(self.stage).pc_write_size(pc)
                if size < 0:
                    desthi = writerow['dest']
                    currentrow['desthi'] = desthi
                    currentrow['destlo'] = desthi - size
                    size = -1*size
                    push = True
                else:
                    push = False
                    destlo = writerow['dest']
                    currentrow['destlo'] = destlo
                    currentrow['desthi'] = destlo + size
                byteswritten = size
                currentrow['byteswritten'] = size

                lrilength = 0
                lrthumb = False
                lrdisasm = ''
                lrfunc = ''

                # check if lr information is in src table
                if not self.thumbranges.overlaps_point(lr) or self.dataranges.overlaps_point(lr):
                    # lr not code!
                    continue
                if db_info.get(self.stage).addr_in_srcs_table(lr):
                    #  do nothing, already in table
                    continue
                else:
                    lrthumb = self.thumbranges.overlaps_point(lr)
                    lrilength = 4
                    if lrthumb:
                        lrilength = 2
                    (lrvalue, lrdisasm, lrfunc) = \
                        utils.addr2disasmobjdump(lr, lrilength,
                                                 self.stage, lrthumb)
                    db_info.get(self.stage).add_source_code_info_row(lrthumb,
                                                                     lr,
                                                                     lrvalue,
                                                                     lrdisasm)
                # now try to add to func table
                if len(lrfunc) > 0:
                    if db_info.get(self.stage).addr_in_funcs_table(lr):
                        # do nothing
                        continue
                    else:
                        cmd = "%sgdb -ex 'dir %s' -ex 'disassemble/r %s' --batch --nh --nx  %s" \
                              % (self.cc, srcdir, lrfunc, self.stage.elf)
                        output = Main.shell.run_multiline_cmd(cmd)
                        try:
                            start = output[1].split('\t')
                        except IndexError:
                            continue
                        startaddr = int(start[0].split()[0], 16)
                        end = output[-3].split('\t')
                        endaddr = int(end[0].split()[0], 16)
                        db_info.get(self.stage).add_funcs_table_row(lrfunc, startaddr, endaddr)

        if currentrow is not None:
            currentrow.append()  # append last row
        self.writerangetable.flush_table()
        histotable.flush()
        histotable.reindex()
        histotable.flush()
        self.h5file.flush()

    def index_write_table(self):
        self.h5file.flush()

    def add_write_entry(self, time, pid, size,
                        dest, pc, lr, cpsr, index=0, num=None):
        #if self.pcmin > self.pcmax:
        #    print "PC not in range %x %x (%x)" % (self.pcmin, self.pcmax, pc)
            # traceback.print_stack()
        #if (pc <= self.pcmax) and (pc >= self.pcmin):
            # get relocation info from writesearch database
        r = self.writestable.row
        r['pid'] = pid
        r['dest'] = dest
        r['relocatedpc'] = pc
        r['relocatedlr'] = lr
        r['time'] = time
        r['reportedsize'] = size
        if index > 0:
            r['index'] = index
        else:
            r['index'] = self.writestable.nrows
        r['cpsr'] = cpsr
        r['pc'] = pc
        r['lr'] = lr
        if num is not None:
            r['substage'] = num
        for rinfo in self.rinfos:
            offset = rinfo['reloffset']
            start = (rinfo['startaddr']+offset)
            end = start + rinfo['size'] + offset
            # if pc is in a relocated dest range  (for now we assume no overlap)
            if (start <= pc) and (pc <= end):
                r['pc'] = pc - offset
                r['lr'] = lr - offset
                break
        r.append()

        
