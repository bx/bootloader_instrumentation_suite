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
import pickle
from collections import Iterable
from config import Main
import hashlib
import subprocess
import substages_parser
import db_info
import pymacs_request
import testsuite_utils as utils


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr
BOOKKEEPING = "bookkeeping"
substage_types = tables.Enum([BOOKKEEPING, "subsequent_substage_copy",
                              "subsequent_substage_setup", "stage_exit"])
region_types = tables.Enum(["subsequent_substage",
                           "input_parameters",
                            "output_parameters",
                            "text", 'stack',
                            'bookkeeping_readonly',
                            'symbol', "none",
                            BOOKKEEPING, "relocation_data", "registers", "vital"])
vlist = ['rw', 'r', 'w', 'none', '?']
perms = tables.Enum(vlist + ["rwx", "x", "rx"])


class MemoryRegionInfo(tables.IsDescription):
    short_name = tables.StringCol(255)
    parent_name = tables.StringCol(255)
    name = tables.StringCol(255)
    comments = tables.StringCol(512)
    include_children = tables.BoolCol()
    reclassifiable = tables.BoolCol()


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
    symbol_name = tables.StringCol(255)
    region_type = tables.EnumCol(region_types, BOOKKEEPING, base='uint8')
    substagenum = tables.UInt8Col()
    new = tables.BoolCol()
    in_process = tables.BoolCol()
    available = tables.BoolCol()
    writable = tables.BoolCol()
    reclassified = tables.BoolCol()
    used_bookkeeping = tables.BoolCol()
    allowed_symbol = tables.BoolCol()


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
        self.h5mmapgroup = None
        self.trace_intervals_table = None
        self.contents_table = None
        self.unresolved_interval_table = None
        self.interval_type = intervaltype
        self.stage = stage
        self.substage_mmap_info_table = None
        self.substage_mmap_addr_table = None
        self.substage_reloc_info_table = None
        self.substage_info_table = None
        self.substage_region_policy_table = None
        self.substage_file_path = Main.get_config("policy_file", self.stage)
        self.mmap_file = Main.get_config("regions_file", self.stage)

    def groupname(self):
        return "%s_%s" % (self.interval_type, self.stage.stagename)

    def mmapgroupname(self):
        return "%s_mmap" % self.stage.stagename

    def create_dbs(self, new_policy=True, new_trace=False):
        self.open_dbs(new_policy, new_trace)
        self.populate_substage_policy_tables()
        if new_trace:
            self.write_substages_file()
            self.populate_contents_table()
            self.populate_write_interval_table()

    def get_intervals_for_substage(self, substage, intervals):
        stage_intervals = intervals[substage]
        other_intervals = intervaltree.IntervalTree()
        other_intervals = interaltree.IntervalTree([inter for inter in [i for (k, i) in
                                                                        intervals.iteritems()
                                                                        if not k == substage]])
        unique = stage_intervals - other_intervals
        return unique

    def substage_numbers(self):
        substages = self._substages_entrypoints()
        return range(0, len(substages))

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
        table = self.trace_intervals_table
        stages = self.substage_numbers()
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
        substages = self._substages_entrypoints()
        substagesname = self.substages_names()
        tracename = Main.get_config("trace_traces")
        if 'framac' not in tracename:
            path = Main.get_config("policy_trace_el", self.stage)
            calltrace_path = Main.get_config("calltrace_db", self.stage)
            substage_linenos = [0]
            for s in substages:
                if s == "_start":
                    n = None
                else:
                    try:
                        n = self.get_function_lineno(s, calltrace_path)
                    except subprocess.CalledProcessError:
                        print "Did not find %s in %s" % (s, calltrace_path)
                        n = None
                if type(n) is int:
                    substage_linenos.append(n)
            substage_linenos.sort()
            outf = open(path, "w")
            outf.write("(setq substages '(%s))\n" % " ".join([str(i) for i in substage_linenos]))
            outf.close()

    @classmethod
    def get_function_lineno(cls, fn, path):
        out = run_cmd.Cmd().run_cmd("grep -no ' > %s' %s" % (fn, path))
        if len(out) == 0:
            return None
        else:
            return int(out.split(":")[0])

    def get_raw_files(self, noprepare):
        stage = self.stage
        substages = self._substages_entrypoints()
        name = self.substages_names()
        substageresultsdir = Main.get_config("policy_trace_fnlist_dir", self.stage)
        tracename = Main.get_config("trace_traces")
        if 'framac' not in tracename:
            calltrace_path = Main.get_config("calltrace_db", self.stage)
            if not noprepare:
                el_path = Main.get_config("policy_trace_el", self.stage)
                pymacs_request.ask_emacs('(create-substage-calltraces "%s" "%s" "%s")' %
                                         (calltrace_path,
                                          el_path,
                                          substageresultsdir))

        origdir = os.getcwd()
        os.chdir(substageresultsdir)
        files = [os.path.join(substageresultsdir, f) for f in glob.glob("*.txt")]
        if files:
            files.sort()
            return {i: files[i] for i in range(0, len(files))}
        else:
            return {}

    def _finish_table(self, table):
        table.flush()
        table.cols.substagenum.create_index(kind="full")
        table.flush()

    def populate_contents_table(self):
        stage = self.stage
        fns = self._substages_entrypoints()
        substagesnamename = self.substages_names()
        tracename = Main.get_config("trace_traces")
        if 'framac' in tracename:
            substages = range(0, len(fns))
            row = self.contents_table.row
            tracefile = Main.get_config("framac_callstacks", self.stage)
            if os.path.exists(tracefile):
                results = self.parse_frama_c_call_trace_stages(tracefile, self.substage_file_path)
                for s in substages:
                    for f in results[s]:
                        row["substagenum"] = s
                        row["functionname"] = f
                        row.append()
        else:
            raws = self.get_raw_files(False)
            for (num, f) in raws.iteritems():
                fopen = open(f, "r")
                contents = fopen.read()
                row = self.contents_table.row
                for n in contents.split():
                    row["substagenum"] = num
                    row["functionname"] = n
                    row.append()
                fopen.close()
        self._finish_table(self.contents_table)

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
        fns = self._substages_entrypoints()
        num = 0
        substages.sort()
        substage_entries = {num: self.fun_info(fns[num + 1])
                            for num in range(0, len(fns) - 1)}
        intervals = db_info.get(self.stage).write_interval_info(tracename,
                                                                substages,
                                                                substage_entries)
        for i in intervals.iteritems():
            i.merge_overlaps()

        return intervals

    def fun_info(self, fun):
        res = db_info.get(self.stage).function_locations(fun)
        if len(res) == 0:
            return utils.get_symbol_location_start_end(fun, self.stage)
        else:
            return res[0]

    def calculate_framac_intervals(self, substages):

        intervals = {n: intervaltree.IntervalTree() for n in substages}
        for num in substages:
            for r in pytable_utils.get_rows(interval_table,
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
        tracename = Main.get_config("trace_traces")
        frama_c = "framac" in tracename
        if frama_c:
            intervals = self.calculate_framac_intervals(substages)

        else:
            intervals = self.calculate_trace_intervals(substages, tracename)
        return intervals

    def populate_write_interval_table(self):
        substages = self.substage_numbers()
        if len(substages) <= 1:
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

        self.populate_mmap_tables(mmap_info, self.substage_mmap_info_table,
                                  self.substage_mmap_addr_table)
        self.populate_substage_reloc_info_table(substage_info,
                                                self.substage_reloc_info_table)
        self.populate_substage_info_table(substage_info,
                                          self.substage_info_table)
        self.populate_policy_table(substage_info, mmap_info,
                                   self.substage_region_policy_table)

    def print_regions(self, info, addr):
        for i in info.iterrows():
            name = i['short_name']
            longname = i['name']
            longname = ' (%s)' % longname if longname else ''
            addrs = []
            numaddrs = - 0
            for a in [r for r in addr.read_sorted('startaddr') if r['short_name'] == name]:
                if numaddrs > 7:
                    addrs.append('...')
                    break
                addrs.append("[0x%x, 0x%x]" % (a['startaddr'], a['endaddr']))
                numaddrs += 1
            print 'Region: %s%s @{%s} reclass=%s' % (name, longname,
                                                     ', '.join(addrs),
                                                     i['reclassifiable'])

    def print_substage_tables(self):
        print '----------regions----------'
        self.print_regions(self.substage_mmap_info_table,
                           self.substage_mmap_addr_table)
        print '----------substages----------'
        substages = self.substage_numbers()
        for num in substages:
            for s in pytable_utils.get_rows(self.substage_info_table,
                                         'substagenum == %s' % num):
                print 'Substage %s (%s)  (name=%s) stack=%s type=%s' % \
                    (s['substagenum'], s['functionname'],
                     s['name'], s['stack'], substage_types(s['substage_type']))
        print '----------policies----------'
        for num in substages:
            print '-----for substage %s ----' % (num)

            new = set()
            inprocess = set()
            available = set()
            writable = set()
            used_bookkeeping = set()
            reclassified = set()
            allregions = set()
            for s in self.substage_region_policy_table.iterrows():
                name = s['short_name']
                allregions.add(name)
                if s['substagenum'] == num:
                    if s['in_process']:
                        inprocess.add(name)
                    if s['new']:
                        new.add(name)
                    if s['reclassified']:
                        reclassified.add(name)
                    if s['writable']:
                        writable.add(name)
                    if s['used_bookkeeping']:
                        used_bookkeeping.add(name)
            used = new | inprocess | available | writable | reclassified | used_bookkeeping
            unusedregions = allregions - used
            print '%s total regions: %s new, %s in proccess -> %s writable | %s not writable' % \
                (len(allregions), len(new), len(inprocess), len(writable), len(unusedregions))
            rowinfo = {}
            for s in pytable_utils.get_rows(self.substage_region_policy_table,
                                            'substagenum == %s' % (num)):
                name = s['short_name']
                rowinfo[name] = (region_types(s['region_type']),
                                 perms(s['default_perms']))
            rs = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in available])
            ns = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in new])
            ps = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in inprocess])
            ws = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0], rowinfo[r][1]) for r in writable])
            us = ', '.join(['(%s, %s, %s)' % (r, rowinfo[r][0],
                                              rowinfo[r][1]) for r in used_bookkeeping])
            cs = ', '.join(['(%s, %s, %s)' % (r,
                                              rowinfo[r][0], rowinfo[r][1]) for r in reclassified])

            print 'available regions: %s' % rs
            print 'new regions: %s' % ns
            print 'inprocess regions: %s' % ps
            print 'writable regions: %s' % ws
            print 'reclassified regions: %s' % cs
            print 'used_bookkeeping regions: %s' % us

    def populate_policy_table(self, ss_info, mmap_info, policy_table):
        substages = list(ss_info.substages.iterkeys())
        regions = list(mmap_info.regions.iterkeys())
        policy_row = policy_table.row
        for s in ss_info.substages.itervalues():
            for r in mmap_info.regions.itervalues():
                    policy_row['default_perms'] = getattr(perms, r.default_perms)
                    policy_row['short_name'] = r.short_name
                    policy_row['region_type'] = getattr(region_types, r.type_at_substage(s.num))
                    policy_row['substagenum'] = s.num
                    policy_row['new'] = r.short_name in s.new_regions
                    policy_row['in_process'] = r.short_name in s.processed_regions
                    policy_row['available'] = r.short_name in s.available_regions
                    policy_row['writable'] = r.short_name in s.writable_regions
                    policy_row['used_bookkeeping'] = r.short_name in s.used_bookkeeping
                    policy_row['reclassified'] = r.short_name in s.reclassified_regions
                    policy_row['allowed_symbol'] = False
                    policy_row['symbol_name'] = ''
                    policy_row.append()
            if s.is_cooking_substage():
                for v in s.allowed_symbols:
                    pat = "^(%s)(.[\d]{5})?$" % v
                    for r in db_info.get(self.stage).symbol_names_with(pat):
                        res = re.match(pat, r)
                        if res is not None:
                            rname = self.region_name_from_symbol(v)
                            policy_row['default_perms'] = getattr(perms, 'rwx')
                            policy_row['short_name'] = rname
                            policy_row['symbol_name'] = r
                            policy_row['region_type'] = getattr(region_types, 'symbol')
                            policy_row['substagenum'] = s.num
                            policy_row['new'] = False
                            policy_row['in_process'] = False
                            policy_row['available'] = False
                            policy_row['writable'] = True
                            policy_row['used_bookkeeping'] = False
                            policy_row['reclassified'] = False
                            policy_row['allowed_symbol'] = True
                            policy_row.append()
                            break
        policy_table.flush()
        policy_table.cols.short_name.create_index(kind="full")
        policy_table.cols.substagenum.create_index(kind="full")
        policy_table.flush()

    @classmethod
    def substages_entrypoints(cls, f):
        return substages_parser.SubstagesFileParser.get_substage_fns(f)

    def _substages_entrypoints(self):
        return self.substages_entrypoints(self.substage_file_path)

    def substages_names(self):
        self.calculate_name_from_files(self.substage_file_path,
                                       self.mmap_file)

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

    def populate_substage_reloc_info_table(self, ss_info, reloc_table):
        nums = sorted(ss_info.substages.iterkeys())
        r = reloc_table.row
        for n in nums:
            s = ss_info.substages[n]
            for relname in s.applied_relocs:
                r['substagenum'] = n
                r['reloc_name'] = relname
                r.append()
        reloc_table.cols.reloc_name.create_index(kind="full")
        reloc_table.cols.substagenum.create_index(kind="full")
        reloc_table.flush()

    def populate_substage_info_table(self, ss_info, info_table):
        info_row = info_table.row
        for (num, s) in ss_info.substages.iteritems():
            info_row['substagenum'] = s.num
            info_row['stack'] = s.stack
            info_row['comments'] = s.comments
            info_row['functionname'] = s.fn
            info_row['substage_type'] = getattr(substage_types, s.substage_type)
            info_row.append()
        info_table.flush()
        info_table.cols.substagenum.create_index(kind="full")
        info_table.cols.functionname.create_index(kind="full")
        info_table.flush()

    def populate_mmap_tables(self, mmap_info, info_table, addr_table):
        info_row = info_table.row
        addr_row = addr_table.row
        for (short_name, region) in mmap_info.regions.iteritems():
            info_row['short_name'] = short_name
            info_row['parent_name'] = region.parent.short_name if region.parent else ''
            info_row['name'] = region.name
            info_row['comments'] = region.contents
            info_row['include_children'] = region.include_children
            info_row['reclassifiable'] = region.reclassifiable
            info_row.append()
            for a in region.addresses:
                addr_row['short_name'] = short_name
                addr_row['startaddr'] = a.begin
                addr_row['endaddr'] = a.end
                addr_row.append()
        info_table.flush()
        info_table.cols.short_name.create_index(kind="full")
        info_table.cols.parent_name.create_index(kind="full")
        info_table.flush()
        addr_table.flush()
        addr_table.cols.short_name.create_index(kind="full")
        addr_table.cols.startaddr.create_index(kind="full")
        addr_table.cols.endaddr.create_index(kind="full")
        addr_table.flush()

    def print_intervals(self):
        table = self.trace_intervals_table
        substages = self.substage_numbers()
        for num in substages:
            print "%s intervals for substage %d" % (name, num)
            for a in [r for r in table.read_sorted('minaddr') if r['substagenum'] == num]:
                print '(0x%x, 0x%x)' % (a['minaddr'], a['maxaddr'])
            print '---------------------------'

    def open_dbs(self, new_policy, new_trace):
        name = Main.get_config('policy_name', self.stage)
        tracemode = "w" if new_trace or new_policy else "r"
        policymode = "w" if new_policy else "r"
        if new_trace:
            trace_db = Main.get_config("policy_trace_db", self.stage)
            print "policy trace db %s" % trace_db
            self.h5file = tables.open_file(trace_db, mode=tracemode,
                                           title="%s substage info" %
                                           self.stage.stagename)
            groupname = self.groupname()
            if not tracemode == "r":
                self.h5group = self.h5file.create_group("/", groupname, "")
                self.contents_table = self.h5file.create_table(
                    self.h5group, 'substagecontents', SubstageContents, "substage contents")
                self.trace_intervals_table = self.h5file.create_table(
                    self.h5group, 'writeintervals', SubstageWriteIntervals, "")
            else:
                    self.h5group = self.h5file.get_node('/%s' % groupname)
                    self.contents_table = self.h5group.substagecontents
                    self.trace_intervals_table = getattr(self.h5group, 'writeintervals')
        mmap_db_path = Main.get_config("policy_db", self.stage)
        self.h5mmap = tables.open_file(mmap_db_path, mode=policymode,
                                       title="%s substage mmap info"
                                       % self.stage.stagename)
        if new_policy:
            self.h5mmapgroup = self.h5mmap.create_group("/",  self.mmapgroupname(), "")
            self.substage_mmap_info_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.mmap_info_table_name,
                MemoryRegionInfo, "")
            self.substage_mmap_addr_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.mmap_addr_table_name,
                MemoryRegionAddrs, "")
            self.substage_info_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.info_table_name,
                SubstageEntry, "")
            self.substage_region_policy_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.region_policy_table_name,
                SubstageRegionPolicy, "")
            self.substage_reloc_info_table = self.h5mmap.create_table(
                "/" + self.mmapgroupname(), self.substage_reloc_table_name,
                SubstageRelocInfo, "")

        else:
            self.h5mmapgroup = self.h5mmap.get_node("/%s" % self.mmapgroupname())
            self.substage_mmap_info_table = getattr(self.h5mmapgroup, self.mmap_info_table_name)
            self.substage_mmap_addr_table = getattr(self.h5mmapgroup, self.mmap_addr_table_name)
            self.substage_info_table = getattr(self.h5mmapgroup, self.info_table_name)
            self.substage_region_policy_table = getattr(self.h5mmapgroup,
                                                        self.region_policy_table_name)
            self.substage_reloc_info_table = getattr(self.h5mmapgroup,
                                                     self.substage_reloc_table_name)

    def allowed_writes(self, substage):
        n = substage
        query = "(substagenum == %d) & (writable == True)" % (n)
        drs = self.substage_region_policy_table.where(query)
        iis = intervaltree.IntervalTree()
        for region in drs:
            if region['allowed_symbol']:
                sname = region['symbol_name']
                iis.add(self.lookup_symbol_interval(sname, n))
            else:
                query = '(short_name == "%s")' % region['short_name']
                for r in self.substage_mmap_addr_table.where(query):
                    iis.add(intervaltree.Interval(r['startaddr'],
                                                  r['endaddr']))
        iis.merge_overlaps()
        iis.merge_equals()
        return iis

    def check_trace(self, tracedb):
        table = tracedb.writerangetable_consolidated
        ss = self._substages_entrypoints()
        self.open_dbs(False, False)
        for n in range(0, len(ss)):
            allowed_writes = self.allowed_writes(n)
            for r in table.table.where("substage == %d" % n):
                i = intervaltree.IntervalTree([intervaltree.Interval(r['dstlo'], r['dsthi'])])
                union = allowed_writes.union(i)
                union.merge_overlaps()
                if not (union == allowed_writes):
                    write = r['writepc'] if r['writepc'] else r['line']
                    print "Substage %d: invalid write by %x to (%x,%x)" % (n, write,
                                                                           r['dstlo'],
                                                                           r['dsthi'])
