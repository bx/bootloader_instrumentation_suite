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

from config import Main
import staticanalysis
import pytable_utils
import addr_space
import atexit
import sys
import substage
import database
import re
import intervaltree
import traceback

_singletons = {}
_mmapdb = None


def get(*args, **kwargs):
    global _singletons
    if len(args) > 0:
        key = args[0]
    else:
        key = "any"
    if key not in _singletons.iterkeys():
        _singletons[key] = DBInfo(*args, **kwargs)
    obj = _singletons[key]
    return obj


def policydb(*args, **kwargs):
    return get(*args, **kwargs)._pdb


def create(*args, **kwargs):
    key = args[0]
    typ = args[1]
    if len(args) > 2:
        args = args[2:]
    else:
        args = ()
    if typ == "mmapdb":
        key = "all"
    elif key == "all":
        raise Exception("need to specify a stage to open db %s" % typ)
    obj = get(key, args, kwargs)
    if typ == "staticdb":
        obj._sdb.create()
    elif typ == "policydb":
        obj._pdb.close()
        obj._pdb.create(**kwargs)
    elif typ == "mmapdb":
        obj._mdb.create()
    elif typ == "tracedb":
        obj._tdb._create()
    return obj


class DBObj():
    def __init__(self, stage):
        self.stage = stage
        self.append = None
        self._db = None

    def open(self, **kwargs):
        if not self._db:
            self._open(**kwargs)

    def _reopen(self, append=True, **kwargs):
        self.close()
        self._open(append=True, **kwargs)

    def create(self, **kwargs):
        if self._db:
            raise Exception("Databse already open %s, %s, %s" % (self._db,
                                                                 self.stage,
                                                                 self.__dict__))
        self._create(**kwargs)
        self._reopen(**kwargs)

    def close(self):
        if self._db:
            self._close()
            del self._db
            self._db = None

    @property
    def db(self, append=None):
        if append is not None and (append is not self.append):
            self._reopen(append)
        elif self._db is None:
            self._open(self.append)
        return self._db


class PolicyDB(DBObj):
    def _open(self, append=False, trace=False, create_policy=False):
        self._db = substage.SubstagesInfo(self.stage)
        self._db.open_dbs(trace)

    def _close(self):
        self._db.close_dbs()

    def flush(self):
        if self._db:
            self._db.close_dbs(True)

    def _create(self, create_policy=False, trace=False):
        self._db = substage.SubstagesInfo(self.stage)
        self._db.create_dbs(trace)


class MMapDB(DBObj):
    def _open(self, append=False):
        self._db = addr_space.AddrSpaceInfo()
        mmapdb_path = Main.raw.static_analysis.mmap.db
        self._db.open_dbs(mmapdb_path, False)

    def _create(self):
        self._db = addr_space.AddrSpaceInfo()
        mmapdb_path = Main.raw.static_analysis.mmap.db
        self._db.open_dbs(mmapdb_path, True)

    def _close(self):
        self._db.close_dbs()

    def flush(self):
        if self._db:
            self._db.close_dbs(True)


class StaticDB(DBObj):
    def _open(self, append=False):
        self._db = staticanalysis.WriteSearch(False, self.stage, False, not append)
        self._db.open_all_tables()
        if self._db.writestable:
            print "opening staticdb nwrite %s" % (self._db.writestable.nrows)

    def _create(self):
        self._db = staticanalysis.WriteSearch(True, self.stage, False)
        self._db.setup_missing_tables()

    def _close(self):
        if self._db.writestable:
            print "closing staticdb nwrite %s" % (self._db.writestable.nrows)
        self._db.closedb(False)

    def flush(self):
        if self._db:
            self._db.closedb(True)


class TraceDB(DBObj):
    def _open(self, append=False):
        dbpath = getattr(Main.raw.runtime.trace.db, self.stage.stagename)
        self._db = database.TraceTable(dbpath, self.stage, False, True)
        print "open tracedb nwrite %s (%s)" % (self._db.writestable.nrows, self.stage.stagename)

    def _create(self):
        dbpath = getattr(Main.raw.runtime.trace.db, self.stage.stagename)
        self._db = database.TraceTable(dbpath, self.stage, True, True)

    def _close(self):
        print "close tracedb nwrite %s (%s)" % (self._db.writestable.nrows, self.stage.stagename)
        self._db.close()

    def flush(self):
        if self._db:
            self._db.close(True)


class DBInfo():
    def __init__(self, *args, **kwargs):
        global _mmapdb
        self.key = args[0]
        self.stage = args[0]
        # single _mmapdb is shared by all stages
        if _mmapdb is None:
            _mmapdb = MMapDB("all")
        self._mdb = _mmapdb
        if self.key == "all" or self.key is None:
            self._sdb = None
            self._pdb = None
            self._tdb = None
        else:
            self._sdb = StaticDB(self.stage)
            self._pdb = PolicyDB(self.stage)
            self._tdb = TraceDB(self.stage)

    def _closeall(self):
        for db in [self._mdb, self._sdb, self._pdb, self._tdb]:
            if db:
                db.close()

    def name_in_relocs_table(self, name):
        return pytable_utils.has_results(self._sdb.db.relocstable, 'name == "%s"' % name)

    def reloc_offset_and_mod_from_cardinal(self, cardinal):
        r = pytable_utils.get_unique_result(self._sdb.db.relocstable, 'cardinal == %s' % cardinal)
        return (r['reloffset'], r['relmod'])

    def reloc_info_by_cardinal(self, names):
        rows = pytable_utils.get_sorted(self._sdb.db.relocstable, 'cardinal')
        for r in filter(lambda x: x['name'] in names, rows):
            yield (r['name'], r['relbegin'], r['size'], r['reloffset'])

    def mmap_var_loc(self, name):
        res = pytable_utils.get_unique_result(self._pdb.db.var_table,
                                              'name == "%s"' % name)
        return (res['startaddr'], res['endaddr'])

    def symbol_names_with(self, substr):
        return [r['name'] for r in
                pytable_utils.query(self._pdb.db.var_table,
                                    "contains(name, \"%s\")" % substr)]

    def reloc_names_in_substage(self, substagenum):
        return [r['name'] for r in pytable_utils.query(self._pdb.db.substage_reloc_info_table,
                                                       'substagenum == %s' % substagenum)]

    def reloc_info(self):
        fields = self._sdb.db.relocstable.colnames

        return [{f: r[f] for f in fields}
                for r in self._sdb.db.relocstable.iterrows()]

    def longwrites_info(self):
        fields = self._sdb.db.longwritestable.colnames
        def longwrites_dict(r):
            d = {}
            reg_row = re.compile("^[es]reg[0-9]+$")
            for f in fields:
                if not reg_row.match(f):
                    d[f] = r[f]
            return d
        return [longwrites_dict(r)
                for r in self._sdb.db.longwritestable.iterrows()]

    def smcs_info(self):
        fields = self._sdb.db.smcstable.colnames

        def smcs_dict(r):
            d = {}
            for f in fields:
                d[f] = r[f]
            return d
        return [smcs_dict(r)
                for r in self._sdb.db.smcstable.iterrows()]

    def is_smc(self, pc):
        query = "pc == 0x%x" % pc
        return pytable_utils.has_results(self._sdb.db.smcstable, query)

    def longwrites_calculate_dest_addrs(self, row, rangetype, regs,
                                        sregs=None, eregs=None, string=None):
        calculator = staticanalysis.LongWriteRangeType.range_calculator(rangetype)
        return calculator(row, regs, sregs, eregs, string)

    def is_longwrite_string(self, rangetype):
        return (rangetype == (staticanalysis.LongWriteRangeType.enum().sourcestrn)) \
            or (rangetype == (staticanalysis.LongWriteRangeType.enum().sourcestr))

    def pc_writes_info(self, pc):
        fields = ['pc', 'thumb', 'reg0', 'reg1', 'reg2',
                  'reg3', 'reg4', 'writesize', 'halt']

        return {f: r[f] for f in fields
                for r in
                pytable_utils.query(self._sdb.db.writestable, "pc == 0x%x" % pc)}

    def stage_exits(self):
        return [(r['addr'], r['line'], r['success'])
                for r in self._sdb.db.stageexits.iterrows()]

    def num_writes(self):
        return self._sdb.db.writestable.nrows

    def skip_pc(self, pc):
        query = "(pc <= 0x%x) & (0x%x < resumepc)" % (pc, pc)
        return pytable_utils.has_results(self._sdb.db.skipstable, query)

    def skip_info(self, pc):
        query = "pc == 0x%x" % (pc)
        return [{"resumepc": r["resumepc"],
                 "thumb": r["thumb"]}
                for r in pytable_utils.query(self._sdb.db.skipstable, query)]

    def is_pc_longwrite(self, pc):
        query = "0x%x == writeaddr" % pc
        return pytable_utils.has_results(self._sdb.db.longwritestable, query)

    def write_info(self):
        return [(r['pc'], r['halt']) for r in self._sdb.db.writestable.iterrows()]

    def stepper_write_info(self, pc):
        fields = self._sdb.db.writestable.colnames

        def writes_dict(r):
            d = {}
            for f in fields:
                d[f] = r[f]
            return d
        query = "pc == 0x%x" % pc
        return [writes_dict(r) for r in pytable_utils.query(self._sdb.db.writestable, query)]

    def src_write_info(self, pc):
        fields = self._sdb.db.srcstable.colnames
        def srcss_dict(r):
            d = {}
            for f in fields:
                d[f] = r[f]
            return d

        query = "addr == 0x%x" % pc
        return [srcs_dict(r) for r in pytable_utils.query(self._sdb.db.srcstable, query)]

    def add_trace_write_entry(self, time, pid, size,
                              dest, pc, lr, cpsr, index=0, num=None):
        self._tdb.db.add_write_entry(time, pid, size, dest, pc,
                                     lr, cpsr, index, num)

    def get_write_pc_or_zero_from_dstinfo(self, dstinfo):
        return self._sdb.db._get_write_pc_or_zero(dstinfo)

    def add_range_dsts_entry(self, dstinfo):
        self._tdb.db.writerangetable.add_dsts_entry(dstinfo)

    def print_range_dsts_info(self):
        self._tdb.db.writerangetable.print_dsts_info()

    def update_trace_writes(self, line, pc, lo, hi, stage, origpc=None, substage=None):
        self._tdb.db.update_writes(line, pc, lo, hi, stage, origpc, substage)

    def get_substage_writes(self, substage):
        fields = self._tdb.db.writestable.colnames

        def writes_dict(r):
            d = {}
            for f in fields:
                d[f] = r[f]
            return d
        query = "substage == %s" % substage
        return [writes_dict(r) for r in pytable_utils.query(self._tdb.db.writestable, query)]

    def trace_histogram(self):
        self._sdb._reopen(True)
        self._tdb.db.histogram()

    def generate_write_range_file(self, out, out2):
        self._tdb._reopen(append=True)
        self._sdb._reopen(append=True)
        self._tdb.db.histogram()
        self._tdb.db.histograminfo(out, out2)

    def consolidate_trace_write_table(self):
        self._tdb.db.histogram()
        self._tdb.db.consolidate_write_table()

    def flush_tracedb(self):
        if self._tdb:
            self._tdb.flush()

    def flush_staticdb(self):
        if self._sdb:
            self._sdb.flush()

    def allowed_substage_writes(self, substage):
        return self._pdb.db.allowed_writes(substage)

    def check_trace(self):
        self._pdb.db.check_trace(self._get_writerangetable())

    def _get_writestable(self, hwname):
        if "framac" in hwname:
            return self._tdb.db.writerangetable_consolidated
        else:
            return self._tdb.db.writestable

    def _get_writerangetable(self):
        return self._tdb.db.writerangetable_consolidated

    # def function_locations(self, name):
    #     return [(r['startaddr'], r['endaddr'])
    #             for r in pytable_utils.get_rows(self._sdb.db.funcstable, 'fname == b"%s"' % name)]

    def pc_write_size(self, pc):
        res = pytable_utils.query(self._sdb.db.writestable,
                                  "pc == 0x%x" % pc)
        try:
            r = next(res)
            return r['writesize']
        except:
            return 0

    def addr_in_srcs_table(self, pc):
        return pytable_utils.has_results(self._sdb.db.srcstable, "addr == 0x%x" % pc)

    def addr_in_funcs_table(self, pc):
        return pytable_utils.has_results(self._sdb.db.funcstable,
                                         "(startaddr <= 0x%x) & (0x%x < endaddr)" % (pc, pc))

    def addr2functionname(self, addr):
        rs = pytable_utils.get_rows(self._sdb.db.funcstable,
                                   ("(startaddr <= 0x%x) & (0x%x < endaddr)" % (addr, addr)))
        if rs:
            return rs[0]['fname']
        else:
            return ''


    def disasm_and_src_from_pc(self, pc):
        r = pytable_utils.query(self._sdb.db.srcstable, "addr == 0x%x" % pc)
        r = next(r)
        return (r["disasm"], r["src"])

    def add_source_code_info_row(self, thumb, addr, ivalue, disasm):
        r = self._sdb.db.srcstable.row
        r['thumb'] = thumb
        r['addr'] = addr
        r['ivalue'] = ivalue
        r['ilength'] = len(ivalue)
        r['mne'] = (disasm.split())[0]
        r['disasm'] = disasm
        r.append()
        self._sdb.db.srcstable.flush()

    def write_info_by_index(self):
        fields = self._sdb.db.writestable.colnames
        for r in pytable_utils.get_sorted(self._sdb.db.writestable, "index"):
            yield {f: r[f] for f in fields}

    def write_interval_info(self, hwname, pclo=None, pchi=None,
                            substage_names=[], substage_entries={}):
        wt = self._get_writestable(hwname)
        if "framac" in hwname:
            return [(r['destlo'], r['desthi']) for r in
                    pytable_utils.get_rows('(%d <= writepc) & (writepc < %d)' % (pclo, pchi))]
        else:
            fns = substage_entries
            substages = substage_names
            num = 0
            intervals = {n: intervaltree.IntervalTree() for n in substages}

            for r in wt.read_sorted('index'):
                pc = r['pc']
                if num < len(fns) - 1:
                    # check if we found the entrypoint to the next stage
                    (lopc, hipc) = substage_entries[num + 1]
                    if (lopc <= pc) and (pc < hipc):
                        num += 1
                if num in substages:
                    start = r['dest']
                    end = start + pytable_utils.get_rows(wt, 'pc == %d' %
                                                         r['pc'])[0]['writesize']
                    intervals[num].add(intervaltree.Interval(start, end))
            return intervals

    def write_trace_intervals(self, interval, table):
        r = table.row
        for (num, iset) in interval.iteritems():
            for i in iset:
                lo = i.begin
                hi = i.end
                r['minaddr'] = lo
                r['maxaddr'] = hi
                r['substagenum'] = num
                r.append()
        table.flush()

def close():
    global _singletons
    for v in _singletons.itervalues():
        v._closeall()


atexit.register(close)
