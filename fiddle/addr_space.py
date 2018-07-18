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

import config
import pytable_utils
import intervaltree
import tables
import os
from config import Main
import csv
from fiddle_extra import parse_am37x_register_tables
import testsuite_utils as utils
register_map = {}


mmap_perms = tables.Enum(['rw', 'r', '?', 'rwx', 'x', 'w'])


mmap_type = tables.Enum(['special', 'reserved', 'rom', 'ram', 'registers',
                         'virtual', 'other', 'iva2.2'])


var_type = tables.Enum(['staticvar', 'register', 'othervar',
                        'heapvar', 'stackvar', 'text'])
vlist = ['rw', 'r', 'w', 'none', '?']
var_perms = tables.Enum(vlist)

perms = tables.Enum(vlist + ["rwx", "x", "rx"])


class MemMapEntry(tables.IsDescription):
    name = tables.StringCol(512)
    startaddr = tables.UInt64Col()
    startaddrlo = tables.UInt32Col()
    startaddrhi = tables.UInt32Col()
    endaddr = tables.UInt64Col()
    endaddrlo = tables.UInt32Col()
    endaddrhi = tables.UInt32Col()
    perms = tables.EnumCol(perms, '?', base='uint8')
    kind = tables.EnumCol(mmap_type, 'other', base='uint8')

#    new = tables.BoolCol()
#    in_process = tables.BoolCol()


class VarEntry(tables.IsDescription):
    name = tables.StringCol(512)
    startaddr = tables.UInt64Col()
    startaddrlo = tables.UInt32Col()
    startaddrhi = tables.UInt32Col()
    endaddr = tables.UInt64Col()
    endaddrlo = tables.UInt32Col()
    endaddrhi = tables.UInt32Col()
    substage = tables.Int16Col()
    kind = tables.EnumCol(var_type, 'othervar', base='uint8')
    perms = tables.EnumCol(var_perms, 'rw', base='uint8')
    rawkind = tables.StringCol(128)


class RegEntry(tables.IsDescription):
    name = tables.StringCol(512)
    address = tables.UInt64Col()
    addresslo = tables.UInt32Col()
    addresshi = tables.UInt32Col()
    width = tables.UInt8Col()
    reset = tables.StringCol(16)
    typ = tables.StringCol(16)
    offset = tables.UInt64Col()
    offsetlo = tables.UInt32Col()
    offsethi = tables.UInt32Col()
    table = tables.StringCol(256)


class AddrSpaceInfo():
    def __init__(self):
        self.grpname = 'memory'
        self.csvs = []
        self.reg_csvs = []
        for (f, i) in Main.get_hardwareclass_config()._files.iteritems():
            if i.type == "mmap":
                if getattr(i, "subtype", "") == "registers":
                    self.reg_csvs.append(Main.populate_from_config(i.path))
                else:
                    self.csvs.append(Main.populate_from_config(i.path))

        self.mem_tablename = "memmap"
        self.reg_tablename = "regs"
        self.h5group = None
        self.h5file = None
        self.memmap_table = None
        self.reg_table = None


    def open_dbs(self, loc, create=False):
        if create:
            self._create_tables(loc)
        else:
            self._open_tables(loc)

    def _create_tables(self, dbloc):
        dname = os.path.dirname(dbloc)
        self.h5file = tables.open_file(dbloc, mode="w",
                                       title="addr space info")
        self.h5group = self.h5file.create_group("/", self.grpname, "")
        self.memmap_table = self.h5file.create_table(self.h5group, self.mem_tablename,
                                                     MemMapEntry, "")
        self.reg_table = self.h5file.create_table(self.h5group, self.reg_tablename,
                                                  RegEntry, "")
        self._create_memmap_table()
        self._create_reg_table()


    def create_substage_memmap_table(self):
        for c in self.csvs:
            with open(c) as csvfile:
                fields = ['name', 'startaddr', 'endaddr', 'perms', 'kind']
                reader = csv.DictReader(csvfile, fields)
                r = self.memmap_table.row
                for entry in reader:
                    for f in fields:
                        if "addr" in f:
                            entry[f] = long(entry[f], 0)
                            entry[f+"lo"] = utils.addr_lo(long(entry[f]))
                            entry[f+"hi"] = utils.addr_hi(long(entry[f]))
                        else:
                            entry[f] = entry[f].strip().lower()
                            if f == 'perms':
                                entry[f] = getattr(mmap_perms, entry[f])
                            elif f == 'kind':
                                entry[f] = getattr(mmap_type, entry[f])
                        r[f] = entry[f]
                    #r['substage'] = substage
                    r.append()
        self.memmap_table.cols.startaddrlo.create_index(kind='full')
        self.memmap_table.cols.startaddrhi.create_index(kind='full')
        self.memmap_table.cols.endaddrlo.create_index(kind='full')
        self.memmap_table.cols.endaddrhi.create_index(kind='full')
        self.memmap_table.flush()

    def _create_memmap_table(self):
            self.create_substage_memmap_table()

    def print_memmap_table(self):
        for r in self.memmap_table.iterrows():
            perms = mmap_perms(r['perms'])
            kind = mmap_type(r['kind'])
            print "SECT: %s (0x%x -- 0x%x) (%s, %s)" % (r['name'],
                                                        r['startaddr'],
                                                        r['endaddr'],
                                                        perms, kind)

    def print_reg_table(self):
        for r in self.reg_table.iterrows():
            print "REG: %s (0x%x, %d bytes [offset %s]) (%s, %s) table %s" % (r['name'],
                                                                              r['address'],
                                                                              r['width'],
                                                                              r['offset'],
                                                                              r['typ'],
                                                                              r['reset'],
                                                                              r['table'])

    def _create_reg_table(self):
        for c in self.reg_csvs:
            (f, reader) = parse_am37x_register_tables.parsecsv(c)
            row = self.reg_table.row
            for r in reader:
                row['address'] = long(r['address'].strip(), 16) if r['address'] else 0
                row['addresslo'] = utils.addr_lo(long(row['address']))
                row['addresshi'] = utils.addr_hi(long(row['address']))
                row["offset"] = long(r["offset"].strip(), 16) if r["offset"] else 0
                row['offsetlo'] = utils.addr_lo(long(row['offset']))
                row['offsethi'] = utils.addr_hi(long(row['offset']))
                row["table"] = r["table"] if r["table"] else ""
                row["typ"] = r["typ"] if r["typ"] else ""
                row["width"] = long(r["width"]) if r["width"] else 0
                row["reset"] = r["reset"] if r["reset"] else ""
                row["name"] = r["name"] if r["name"] else ""
                if row['address'] == 0:
                    print "addr not found in %s" % r

                row.append()
            f.close()
        self.reg_table.cols.addresslo.create_index(kind='full')
        self.reg_table.cols.addresshi.create_index(kind='full')
        self.reg_table.flush()

    def _open_tables(self, loc):
        self.h5file = tables.open_file(loc, mode="r")
        self.h5group = self.h5file.get_node("/%s" % self.grpname)
        self.memmap_table = getattr(self.h5group, self.mem_tablename)
        self.reg_table = getattr(self.h5group, self.reg_tablename)

    def close_dbs(self, flush_only=False):
        if self.h5file:
            self.h5file.flush()
            if not flush_only:
                self.h5file.close()
                self.h5file = None
