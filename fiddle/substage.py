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

import os
import csv
import sys
import re
import glob
import numpy
import tables
import intervaltree
import pytable_utils
import run_cmd
import StringIO
import pickle
from collections import Iterable
from config import Main
import hashlib
import subprocess
import substages_parser
import db_info
import pymacs_request
import testsuite_utils as utils
import addr_space
def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr
BOOKKEEPING = "bookkeeping"
substage_types = tables.Enum([BOOKKEEPING,
                              "loading", "patching"])
region_types = tables.Enum(["future", 'global', 'patching',
                            'stack',
                            'symbol',
                            'readonly',
                            BOOKKEEPING])
vlist = ['rw', 'r', 'w', 'none', '?']
perms = tables.Enum(vlist + ["rwx", "x", "rx"])


class MemoryRegionInfo(tables.IsDescription):
    short_name = tables.StringCol(255)
    parent_name = tables.StringCol(255)
    name = tables.StringCol(255)
    comments = tables.StringCol(512)
    include_children = tables.BoolCol()
    reclassifiable = tables.BoolCol()
    do_print = tables.BoolCol()


class MemoryRegionAddrs(tables.IsDescription):
    short_name = tables.StringCol(255)
    startaddr = tables.UInt32Col()
    endaddr = tables.UInt32Col()


class SubstageRelocInfo(tables.IsDescription):
    substagenum = tables.UInt8Col()
    reloc_name = tables.StringCol(128)


class SubstageRegionPolicy(tables.IsDescription):
    default_perms = tables.EnumCol(perms,
                                   'rwx', base='uint8')
    short_name = tables.StringCol(255)
    symbol_name = tables.StringCol(255)  # symbol name in code
    symbol_elf_name = tables.StringCol(255)  # symbol name in elf filie
    region_type = tables.EnumCol(region_types, BOOKKEEPING, base='uint8')
    substagenum = tables.UInt8Col()
    new = tables.BoolCol()
    defined = tables.BoolCol()
    undefined = tables.BoolCol()
    writable = tables.BoolCol()
    reclassified = tables.BoolCol()
    allowed_symbol = tables.BoolCol()
    do_print = tables.BoolCol()


class SubstageContents(tables.IsDescription):
    substagenum = tables.UInt8Col(pos=1)
    functionname = tables.StringCol(255, pos=2)


class SubstageEntry(tables.IsDescription):
    substagenum = tables.UInt8Col(pos=1)
    functionname = tables.StringCol(255)
    name = tables.StringCol(255)
    stack = tables.StringCol(255)
    comments = tables.StringCol(255)
    substage_type = tables.EnumCol(substage_types,
                                   BOOKKEEPING, base='uint8')


class SubstageWriteIntervals(tables.IsDescription):
    substagenum = tables.UInt8Col()
    minaddr = tables.UInt32Col()
    maxaddr = tables.UInt32Col()


class SubstagesInfo():
    CUMULATIVE = "cumulative"
    SUBSTAGEONLY = "substageonly"
    interval_types = [CUMULATIVE, SUBSTAGEONLY]
    mmap_info_table_name = "mmap_info"
    mmap_addr_table_name = "mmap_addr"
    info_table_name = "info"
    region_policy_table_name = "region_policy"
    substage_reloc_table_name = "substage_reloc"

    def __init__(self, stage,
                 intervaltype=SUBSTAGEONLY):
        self.h5file = None
        self.h5mmap = None
        self.h5group = None
        self.var_table = None
        self.h5mmapgroup = None
        self.trace_intervals_table = None
        self.contents_table = None
        self.unresolved_interval_table = None
        self.interval_type = intervaltype
        self.stage = stage
        if isinstance(self.stage, str):
            self.stage = Main.stage_from_name(self.stage)
        self.substage_mmap_info_table = None
        self.substage_mmap_addr_table = None
        self.substage_reloc_info_table = None
        self.substage_info_table = None
        self.substage_region_policy_table = None
        if not hasattr(Main.raw.policies, "substages_file"):
            raise Exception("No substage or region definitions are available for processing")
        self.substage_file_path = Main.get_policy_config("substages_file", self.stage)
        self.mmap_file = Main.get_policy_config("regions_file", self.stage)        
        self.process_trace = False

    def _var_tablename(self):
        return "vars"

    def groupname(self):
        return "%s_%s" % (self.interval_type, self.stage.stagename)

    def mmapgroupname(self):
        return "%s_mmap" % self.stage.stagename

    def create_dbs(self,  trace):
        self.process_trace = trace
        self.open_dbs(trace)
        # if create_policy and not self.mmap_created:
        self.mmap_created = trace
        self.h5mmap.flush()
        self._create_var_table()
        self.populate_substage_policy_tables()
        self.h5mmap.flush()
        if self.process_trace:
            self.write_substages_file()
            self.populate_contents_table()
            self.populate_write_interval_table()
            self.h5mmap.flush()

        print "-----------imported following policy ---------"
        try:
            self.print_substage_tables()
        except IndexError:
            # a problem with pytables I cannot figure out
            # give up
            pass
            
        print "-------------------------------------------"
            

    def _create_var_table(self, substage=-1):
        fields = ["startaddr", "size", "kind", "name"]
        vtab = self.var_table
        if vtab.nrows > 0:
            return
        cc = Main.cc
        stage = self.stage
        sname = stage.stagename
        elf = stage.elf
        cmd = "%snm -n -S %s" % (cc, elf)
        f = StringIO.StringIO(Main.shell.run_cmd(cmd))
        reader = csv.DictReader(f, fields, delimiter=" ",
                                lineterminator="\n", skipinitialspace=True)
        row = vtab.row
        for r in reader:
            if r['name'] is not None:
                row['name'] = r['name'].strip()
                row['startaddr'] = int(r['startaddr'].strip(), 16)
                row['endaddr'] = row['startaddr'] + int(r['size'].strip(), 16)
                row['rawkind'] = r['kind'].strip()
                k = row['rawkind'].lower()
                if ('t' == k) or ('w' == k):
                    row['kind'] = getattr(addr_space.var_type, 'text')
                else:
                    row['kind'] = getattr(addr_space.var_type, 'staticvar')
                row['perms'] = getattr(addr_space.var_perms, 'rw')
                row['substage'] = substage
                row.append()
        vtab.flush()

    def print_var_table(self):
        for r in self.var_table.iterrows():
            perms = addr_space.var_perms(r['perms'])
            kind = addr_space.var_type(r['kind'])
            print "VAR: %s (0x%x -- 0x%x) (%s, %s, %s) at substage %d" % (r['name'],
                                                                          r['startaddr'],
                                                                          r['endaddr'],
                                                                          perms, kind,
                                                                          r['rawkind'],
                                                                          r['substage'])


    def get_intervals_for_substage(self, substage, intervals):
        stage_intervals = intervals[substage]
        other_intervals = intervaltree.IntervalTree()
        other_intervals = interaltree.IntervalTree([inter for inter in [i for (k, i) in
                                                                        intervals.iteritems()
                                                                        if not k == substage]])
        unique = stage_intervals - other_intervals
        return unique

    def divide_intervals(self, stages, table):
        divided_intervals = {i: intervaltree.IntervalTree() for i in stages}
        for r in table.iterrows():
            n = r["substagenum"]
            divided_intervals[n].add(intervaltree.Interval(r["minaddr"], r["maxaddr"]))
            if self.interval_type == self.CUMULATIVE:
                for i in range(n + 1, len(stages)):
                    divided_intervals[i].add(intervaltree.Interval(r["minaddr"], r["maxaddr"]))
        for i in divided_intervals.itervalues():
            i.merge_overlaps()
        return divided_intervals

    def get_intervals(self):
        if not self.trace_intervals_table:
            return intervaltree.IntervalTree()
        table = self.trace_intervals_table
        stages = self._substage_numbers()
        results = {i: [] for i in stages}
        divided_intervals = self.divide_intervals(stages, table)
        return divided_intervals  # results

    def print_all_intervals(self):
        self.print_intervals()

    def lookup_symbol_interval(self, name, num):
        (startaddr, endaddr) = db_info.get(self.stage).mmap_var_loc(name)
        reloc_names = db_info.get(self.stage).reloc_names_in_substage(num)
        varloc = intervaltree.Interval(startaddr, endaddr)
        for (rname, rbegin,
             rsize, roffset) in db_info.get(self.stage).reloc_info_by_cardinal(reloc_names):
            relrange = intervaltree.Interval(rbegin, rbegin + rsize)
            if relrange.contains_interval(varloc):
                offset = roffset
                varloc = intervaltree.Interval(varloc.begin + offset,
                                               varloc.end + offset)
        return varloc

    @classmethod
    def parse_frama_c_call_trace_stages(cls, f, fns):
        stages = {k: set() for k in range(0, len(fns))}
        entry = None
        with open(f, 'r') as fd:
            reader = csv.reader((l.replace('->', ',') for l in fd.readlines()),
                                skipinitialspace=True)
            for row in reader:
                row = list(row)
                if not entry:
                    entry = row[0]
                stages[0].update(row)
                for fn in range(1, len(fns)):
                    try:
                        i = row.index(fns[fn])
                    except:
                        i = -1
                    if i > 0:
                        stages[fn].update(row[i:])
        return stages

    @classmethod
    def write_framac_substage_files(cls, results, substageresultsdir):
        for i in results.iterkeys():
            f = os.path.join(substageresultsdir, "%d-substage-fns.txt" % i)
            with open(f, 'w') as fd:
                fd.write("\n".join(results[i]))
                fd.write("\n")

    def write_substages_file(self):
        stage = self.stage
        substages = self._substage_names()
        tracename = self.process_trace
        if "calltrace" in Main.raw.runtime.enabled_traces:
            cdb = getattr(Main.raw.runtime.trace.calltrace.files.org, self.stage.stagename)
        else:
            cdb = None
        if cdb and os.path.exists(cdb):
            path = getattr(Main.raw.runtime.trace.calltrace.files.el_file, self.stage.stagename)
            if os.path.exists(path):
                return
            calltrace_path = cdb
            failed = False
            substage_linenos = []
            for s in substages:
                if s == "_start":
                    n = 0
                else:
                    if not failed:
                        try:
                            n = self.get_function_lineno(s, calltrace_path)
                        except subprocess.CalledProcessError:
                            print "Did not find %s in %s" % (s, calltrace_path)
                            failed = True
                            n = self.get_function_lineno(s, calltrace_path, True)
                substage_linenos.append(n)
            outf = open(path, "w")
            outf.write("(setq substages '(%s))\n" % " ".join([str(i) for i in substage_linenos]))
            outf.close()

    @classmethod
    def get_function_lineno(cls, fn, path, last=False):
        if last:
            out = run_cmd.Cmd().run_cmd("wc -l %s | awk '{print ($1);}'" % (path))
            return int(out)
        out = run_cmd.Cmd().run_cmd("egrep -no ' > %s( |$)' %s" % (fn, path))
        if len(out) == 0:
            return None
        else:
            return int(out.split(":")[0])

    def get_raw_files(self, noprepare):
        stage = self.stage
        substages = self._substage_numbers()
        name = self._substage_names()
        substageresultsdir = getattr(Main.raw.postprocess.consolidate_writes.files.fn_lists, stage.stagename)
        tracename = self.process_trace
        calltrace_path = getattr(Main.raw.runtime.trace.calltrace.files.org, stage.stagename)   
        if calltrace_path and os.path.exists(calltrace_path) and substageresultsdir:
            pp = Main.raw.postprocess.consolidate_writes.files
            if not noprepare:
                el_path = getattr(pp.el_file, stage.stagename)  
                if os.path.exists(substageresultsdir):
                    return {}
                try:
                    pymacs_request.ask_emacs('(create-substage-calltraces "%s" "%s" "%s")' %
                                             (calltrace_path,
                                              el_path,
                                              substageresultsdir))
                except AssertionError as e:
                    print "Emacs data gathering not setup (%s, %s)\n" % (e, e.args)
                    return {}
            origdir = os.getcwd()
            os.chdir(substageresultsdir)
            files = [os.path.join(substageresultsdir, f) for f in glob.glob("*.txt")]
            if files:
                files.sort()
                return {i: files[i] for i in range(0, len(files))}
        return {}

    def populate_contents_table(self):
        stage = self.stage
        substages = self._substage_numbers()
        substagesnamename = self._substage_names()
        tracename = self.process_trace
        if self.contents_table.nrows > 0:
            return
        if 'framac' == tracename:            
            tracefile = etattr(Main.raw.runtime.trace.framac.files.callstack, self.stage.stagename)
            if os.path.exists(tracefile):
                results = self.parse_frama_c_call_trace_stages(tracefile, self.substage_file_path)
                row = self.contents_table.row                
                for s in substages:
                    for f in results[s]:
                        row["substagenum"] = s
                        row["functionname"] = f
                        row.append()
        elif "watchpoint" not in tracename:
            raws = self.get_raw_files(False)
            row = self.contents_table.row
            for (num, f) in raws.iteritems():
                fopen = open(f, "r")
                contents = fopen.read()                
                for n in contents.split():
                    row["substagenum"] = num
                    row["functionname"] = n
                    row.append()
                fopen.close()
        self.contents_table.flush()
        self.contents_table.cols.substagenum.reindex()

    def close_dbs(self, flush_only=False):
        if self.h5mmap is None:
            return
        self.h5mmap.flush()
        if not flush_only:
            self.h5mmap.close()
        if self.h5file:
            self.h5file.flush()
            if not flush_only:
                self.h5file.close()

    def calculate_trace_intervals(self, substages, tracename):
        fns = self._substage_names()
        num = 0
        substage_entries = {num: self.fun_info(fns[num + 1])
                            for num in range(0, len(fns) - 1)}
        intervals = db_info.get(self.stage).write_interval_info(tracename,
                                                                substages,
                                                                substage_entries)
        for i in intervals.iteritems():
            i.merge_overlaps()

        return intervals

    def fun_info(self, fun):
        #res = db_info.get(self.stage).function_locations(fun)
        #if len(res) == 0:
        return utils.get_symbol_location_start_end(fun, self.stage)
        #else:
        #    return res[0]

    def calculate_framac_intervals(self, substages):

        intervals = {n: intervaltree.IntervalTree() for n in substages}
        for num in substages:
            for r in pytable_utils.get_rows(self.trace_intervals_table,
                                            'substagenum == %s' % num):
                # lookup writes performed by this function
                f = r['functionname']
                (lopc, hipc) = self.fun_info(f)
                res = db_info.get(self.stage).write_interval_info(tracename, lopc, hipc)
                intervals[num] += intervaltree.IntervalTree([intervaltree.Interval(r[0],
                                                                                   r[1])
                                                             for r in res])

        return intervals

    def calculate_intervals(self, substages):
        tracename = self.process_trace
        frama_c = "framac" in tracename
        if frama_c:
            intervals = self.calculate_framac_intervals(substages)

        else:
            intervals = self.calculate_trace_intervals(substages, tracename)
        return intervals

    def populate_write_interval_table(self):
        substages = self._substage_numbers()
        if len(substages) < 1:
            print "No substages defined, not populating write interval table for %s" % (self.stage)
            return
        intervals = self.calculate_intervals(substages)
        db_info.get(self.stage).write_trace_intervals(intervals,
                                                      self.trace_intervals_table)

    def populate_substage_policy_tables(self):
        mmap_info = substages_parser.MmapFileParser(self.mmap_file)
        substage_info = substages_parser.SubstagesFileParser(self.stage,
                                                             self.substage_file_path,
                                                             mmap_info)
        self.populate_mmap_tables(mmap_info)
        self.populate_substage_reloc_info_table(substage_info)                                                
        self.populate_substage_info_table(substage_info)
        self.populate_policy_table(substage_info, mmap_info)

    def print_regions(self, info, addr):
        lines = []
        for i in info.iterrows():
            if not i['do_print']:
                continue
            name = i['short_name']
            longname = i['name']
            longname = ' (%s)' % longname if longname else ''
            addrs = []
            numaddrs = - 0
            for a in [r for r in addr.read_sorted('startaddr') if r['short_name'] == name]:
                if numaddrs > 7:
                    addrs.append('...')
                    break
                addrs.append("[0x%08x, 0x%08x]" % (a['startaddr'], a['endaddr']))
                numaddrs += 1
            addrs.sort()
            lines.append('Region: %s @{%s}' % (name,
                                               ', '.join(addrs)))

        lines.sort()
        for l in lines:
            print l

    def print_substage_tables(self):
        self.h5mmap.flush()
        print '----------regions----------'
        self.print_regions(self.substage_mmap_info_table,
                           self.substage_mmap_addr_table)
        print '----------substages----------'
        substages = self._substage_numbers()
        self.substage_info_table.flush_rows_to_index()

        for num in substages:
            for s in pytable_utils.get_rows(self.substage_info_table,
                                         'substagenum == %s' % num):
                print 'Substage %s (%s)  (name=%s) stack=%s type=%s' % \
                    (s['substagenum'], s['functionname'],
                     s['name'], s['stack'], substage_types(s['substage_type']))
        print '----------policies----------'
        for num in substages:
            print '-----for substage %s (%s) ----' % (num, self._substage_names()[num])

            new = set()
            defined = set()
            undefined = set()
            writable = set()
            reclassified = set()
            allregions = set()
            for s in self.substage_region_policy_table.iterrows():
                name = s['short_name']
                allregions.add(name)
                if s['substagenum'] == num:
                    if s['defined'] and s['do_print']:
                        defined.add(name)
                    if s['new'] and s['do_print']:
                        new.add(name)
                    if s['reclassified'] and s['do_print']:
                        reclassified.add(name)
                    if s['writable'] and s['do_print']:
                        writable.add(name)
                    if s['undefined'] and s['do_print']:
                        undefined.add(name)
            used = new | defined | writable | reclassified
            unusedregions = allregions - used
            print '%s total regions: %s new, %s defined -> %s writable | %s not writable' % \
                (len(allregions), len(new), len(defined), len(writable), len(unusedregions))
            rowinfo = {}
            for s in pytable_utils.get_rows(self.substage_region_policy_table,
                                            'substagenum == %s' % (num)):
                name = s['short_name']
                rowinfo[name] = (region_types(s['region_type']),
                                 perms(s['default_perms']))
            ds = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in defined])
            ns = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in new])
            us = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in undefined])
            ws = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in writable])
            cs = ', '.join(['(%s, %s, %s)' % (r,
                                              rowinfo[r][0], rowinfo[r][1]) for r in reclassified])
            ds = ds if ds else "[]"
            ns = ns if ns else "[]"
            us = us if us else "[]"
            ws = ws if ws else "[]"
            cs = cs if ds else "[]"
            if ds:
                print 'defined regions: %s' % ds
            if ns:
                print 'new regions: %s' % ns
            if us:
                print 'undefined regions: %s' % us
            if cs:
                print 'reclassified regions: %s' % cs
            if ws:
                print 'writable regions: %s' % ws

    def populate_policy_table(self, ss_info, mmap_info):
        regions = list(mmap_info.regions.iterkeys())
        policy_table = self.substage_region_policy_table
        if policy_table.nrows > 0:
            return
        policy_row = policy_table.row
        for s in ss_info.substages.itervalues():
            for r in mmap_info.regions.itervalues():
                policy_row['default_perms'] = getattr(perms, r.default_perms)
                policy_row['short_name'] = r.short_name
                policy_row['region_type'] = getattr(region_types, r.type_at_substage(s.num))
                policy_row['substagenum'] = s.num
                policy_row['new'] = r.short_name in s.new_regions
                policy_row['undefined'] = r.short_name in s.undefined_regions
                policy_row['defined'] = r.short_name in s.defined_regions
                policy_row['writable'] = r.short_name in s.writable_regions
                policy_row['reclassified'] = r.short_name in s.reclassified_regions
                policy_row['allowed_symbol'] = False
                policy_row['do_print'] = True
                if r.parent and r.parent._csv:
                    policy_row['do_print'] = False
                policy_row['symbol_name'] = ''
                policy_row['symbol_elf_name'] = ''
                policy_row.append()
            for v in s.allowed_symbols:
                pat = "^(%s)(.[\d]{5})?$" % v
                found = False
                for r in db_info.get(self.stage).symbol_names_with(v):
                    match = re.match(pat, r)
                    if match is None:
                        continue
                    else:
                        rname = self.region_name_from_symbol(v)
                        policy_row['default_perms'] = getattr(perms, 'rwx')
                        policy_row['short_name'] = rname
                        policy_row['symbol_elf_name'] = r
                        policy_row['symbol_name'] = v
                        policy_row['region_type'] = getattr(region_types, 'symbol')
                        policy_row['substagenum'] = s.num
                        policy_row['new'] = False
                        policy_row['defined'] = False
                        policy_row['undefined'] = False
                        policy_row['writable'] = True
                        policy_row['reclassified'] = False
                        policy_row['allowed_symbol'] = True
                        policy_row['do_print'] = True
                        policy_row.append()
                        #policy_row.update()
                        #policy_row._flushModRows()
                        
                        found = True
                        break
                if not found:
                    raise Exception("could not find symbol named %s" % v)
        policy_table.flush()

        policy_table.cols.substagenum.reindex()
        policy_table.cols.short_name.reindex()
        policy_table.flush()


    @classmethod
    def calculate_name_from_files(cls, f, f2):
        m = hashlib.md5()
        with open(f, 'r') as fd:
            m.update(fd.read())
        with open(f2, 'r') as fd:
            m.update(fd.read())
        return m.hexdigest()

    def region_name_from_symbol(self, v):
        return "_Symbols.%s" % (v)

    def populate_substage_reloc_info_table(self, ss_info):
        reloc_table = self.substage_reloc_info_table
        nums = sorted(ss_info.substages.iterkeys())
        if reloc_table.nrows > 0:
            return
        r = reloc_table.row        
        for n in nums:
            s = ss_info.substages[n]
            for relname in s.applied_relocs:
                r['substagenum'] = n
                r['reloc_name'] = relname
                r.append()
        reloc_table.cols.reloc_name.reindex()
        reloc_table.cols.substagenum.reindex()
        reloc_table.flush()

    def populate_substage_info_table(self, ss_info):
        if self.substage_info_table.nrows > 0:
            return
        info_row = self.substage_info_table.row
        for (num, s) in ss_info.substages.iteritems():
            info_row['substagenum'] = s.num
            info_row['stack'] = s.stack
            info_row['comments'] = s.comments
            info_row['functionname'] = s.fn
            info_row['substage_type'] = getattr(substage_types, s.substage_type)
            info_row.append()
        self.substage_info_table.cols.substagenum.reindex()
        self.substage_info_table.cols.functionname.reindex()
        self.substage_info_table.flush()
        self.h5mmap.flush()   


    def populate_mmap_tables(self, mmap_info):
        info_table = self.substage_mmap_info_table
        addr_table = self.substage_mmap_addr_table
        if addr_table.nrows > 0 or info_table.nrows > 0:
            return
        info_row = info_table.row
        addr_row = addr_table.row        
        for (short_name, region) in mmap_info.regions.iteritems():
            info_row['short_name'] = short_name
            info_row['parent_name'] = region.parent.short_name if region.parent else ''
            info_row['name'] = region.name
            info_row['comments'] = region.contents
            info_row['include_children'] = region.include_children
            info_row['do_print'] = True
            if region.parent and region.parent._csv:
                info_row['do_print'] = False
            info_row['reclassifiable'] = region.reclassifiable
            info_row.append()
            for a in region.addresses:
                addr_row['short_name'] = short_name
                addr_row['startaddr'] = a.begin
                addr_row['endaddr'] = a.end
                addr_row.append()
        info_table.cols.short_name.reindex()
        info_table.cols.parent_name.reindex()
        info_table.flush()
        addr_table.cols.short_name.reindex()
        addr_table.cols.startaddr.reindex()
        addr_table.cols.endaddr.reindex()
        addr_table.flush()
        self.h5mmap.flush()

    def print_intervals(self):
        table = self.trace_intervals_table
        if not table:
            return
        substages = self._substage_numbers()
        names = self._substage_names()
        for num in substages:
            name = names[num]
            print "%s intervals for substage %d" % (name, num)
            num = 0
            for a in [r for r in table.read_sorted('minaddr') if r['substagenum'] == num]:
                print '(0x%x, 0x%x)' % (a['minaddr'], a['maxaddr'])
                if num > 10:
                    print "..."
                    break
                num += 1
            print '---------------------------'
    
    def open_dbs(self, trace):
        self.process_trace = trace
        if trace:
            trace_db = getattr(getattr(Main.raw.runtime.trace, trace).files.db, self.stage.stagename)
            trace_db_done = Main.raw.runtime.trace.done
            if not (os.path.exists(trace_db_done) and os.path.exists(trace_db)):
                trace_db = None
        else:
            trace_db = None
        if not trace_db or not trace or not os.path.exists(trace_db):
            self.h5file = None
            self.h5group = None
            self.trace_intervals_table = None
            self.contents_table = None
        else:
            self.h5file = tables.open_file(trace_db, mode="a",
                                           title="%s substage info" %
                                           self.stage.stagename)
            groupname = self.groupname()
            try:
                self.h5group = self.h5file.create_group("/", groupname, "")
            except tables.exceptions.NodeError:
                self.h5group = self.h5file.get_node('/%s' % groupname)

            if not hasattr(self.h5group, 'substagecontents'):
                self.contents_table = self.h5file.create_table(
                    self.h5group, 'substagecontents', SubstageContents, "substage contents")
            else:
                self.contents_table = self.h5group.substagecontents
            if not hasattr(self.h5group, 'writeintervals'):
                self.trace_intervals_table = self.h5file.create_table(
                    self.h5group, 'writeintervals', SubstageWriteIntervals, "")
            else:
                self.trace_intervals_table = self.h5group.writeintervals
        mmap_db_path = Main.get_policy_config("db", self.stage)
        self.h5mmap = tables.open_file(mmap_db_path, mode="a",
                                       title="%s substage mmap info"
                                       % self.stage.stagename)
        try:
            self.h5mmapgroup = self.h5mmap.create_group("/",  self.mmapgroupname(), "")
            self.mmap_created = True
        except tables.exceptions.NodeError as e:
            self.h5mmapgroup = self.h5mmap.get_node('/%s' % self.mmapgroupname())
            self.mmap_created = False

        if not hasattr(self.h5mmapgroup, self.mmap_info_table_name):
            self.substage_mmap_info_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.mmap_info_table_name,
                MemoryRegionInfo, "")
            self.substage_mmap_info_table.cols.short_name.create_index(kind="full")
            self.substage_mmap_info_table.cols.parent_name.create_index(kind="full")
        else:
            self.substage_mmap_info_table = getattr(self.h5mmapgroup, self.mmap_info_table_name)

        if not hasattr(self.h5mmapgroup, self.mmap_addr_table_name):
            self.substage_mmap_addr_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.mmap_addr_table_name,
                MemoryRegionAddrs, "")
            self.substage_mmap_addr_table.cols.short_name.create_index(kind="full")
            self.substage_mmap_addr_table.cols.startaddr.create_index(kind="full")
            self.substage_mmap_addr_table.cols.endaddr.create_index(kind="full")
        else:
            self.substage_mmap_addr_table = getattr(self.h5mmapgroup, self.mmap_addr_table_name)

        if not hasattr(self.h5mmapgroup, self.info_table_name):
            self.substage_info_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(),
                self.info_table_name,
                SubstageEntry, "")
            self.substage_info_table.cols.substagenum.create_index(kind="full")
            self.substage_info_table.cols.functionname.create_index(kind="full")
        else:
            self.substage_info_table = getattr(self.h5mmapgroup, self.info_table_name)

        if not hasattr(self.h5mmapgroup, self.region_policy_table_name):
            self.substage_region_policy_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.region_policy_table_name,
                SubstageRegionPolicy, "")
            self.substage_region_policy_table.cols.substagenum.create_index(kind="full")
            self.substage_region_policy_table.cols.short_name.create_index(kind="full")
        else:
            self.substage_region_policy_table = getattr(self.h5mmapgroup,
                                                        self.region_policy_table_name)

        if not hasattr(self.h5mmapgroup, self.substage_reloc_table_name):
            self.substage_reloc_info_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.substage_reloc_table_name,
                SubstageRelocInfo, "")
            self.substage_reloc_info_table.cols.reloc_name.create_index(kind="full")
            self.substage_reloc_info_table.cols.substagenum.create_index(kind="full")
        else:
            self.substage_reloc_info_table = getattr(self.h5mmapgroup,
                                                     self.substage_reloc_table_name)
        if not hasattr(self.h5mmapgroup, self._var_tablename()):
            self.__create_var_table()
        else:
            self.var_table = getattr(self.h5mmapgroup, self._var_tablename())

    def __create_var_table(self):
            self.var_table = self.h5mmap.create_table(self.h5mmapgroup,
                                                      self._var_tablename(),
                                                      addr_space.VarEntry, "")
            vtab = self.var_table
            vtab.cols.startaddr.create_index(kind='full')
            vtab.cols.endaddr.create_index(kind='full')
            vtab.cols.substage.create_index(kind='full')

    def allowed_writes(self, substage):
        n = substage
        query = "(substagenum == %d) & (writable == True)" % (n)
        drs = self.substage_region_policy_table.where(query)
        iis = intervaltree.IntervalTree()
        for region in drs:
            if region['allowed_symbol']:
                sname = region['symbol_elf_name']
                iis.add(self.lookup_symbol_interval(sname, n))
            else:
                query = 'short_name == "%s"' % region['short_name']
                for r in self.substage_mmap_addr_table.where(query):
                    iis.add(intervaltree.Interval(r['startaddr'],
                                                  r['endaddr']))
        iis.merge_overlaps()
        iis.merge_equals()
        return iis

    def _substage_numbers(self):
        return self.substage_numbers(self.stage)

    def _substage_names(self):
        return self.substage_names(self.stage)

    @classmethod
    def substage_names_from_file(cls, f): 
        return substages_parser.SubstagesFileParser.get_substage_fns(f)
    
    @classmethod
    def substage_names(cls, stage):
        if not (("policies" in Main.raw.keys()) and ("substages_file" in Main.raw.policies.keys())):
            return []
        policy = Main.get_policy_config('substages_file', stage)
        return substages_parser.SubstagesFileParser.get_substage_fns(policy)

    @classmethod
    def substage_numbers(cls, stage):
        return range(len(cls.substage_names(stage)))

    def check_trace(self, table):
        violation = False
        snums = self._substage_numbers()
        print "---- CHECKING TRACE FOR WRITE VIOLATIONS -----"
        for n in snums:            
            allowed_writes = self.allowed_writes(n)
            for r in db_info.get(self.stage).get_substage_writes(n):
                size = r['reportedsize']
                if size < 0:
                    end = r['dest']
                    start = end + size  # + 1
                else:
                    start = r['dest']
                    end = start + size  # - 1
                if start == end:
                    res = allowed_writes.search(start)
                else:
                    res = allowed_writes.search(start, end)
                if not len(res) == 1:
                    write = r['relocatedpc']
                    print "Substage %d: invalid write by pc 0x%x to addr (%x,%x)" % (n,
                                                                                     write,
                                                                                     start,
                                                                                     end)
                    violation = True
                    #exit(0)
        if not violation:
            print "Policy was not violated :)"
            print "-------------------------------------------"
            return True
        else:
            print "-------------------------------------------"            
            return False
