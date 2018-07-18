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

import yaml
import intervaltree
import os
import config
import re
import sys
import testsuite_utils as utils
from fiddle_extra import parse_am37x_register_tables
from config import Main
from collections import OrderedDict
import db_info


def int_repr(self):
    return "({0:08X}, {1:08X})".format(self.begin, self.end)


intervaltree.Interval.__str__ = int_repr
intervaltree.Interval.__repr__ = int_repr


class OrderedDictYAMLLoader(yaml.Loader):
    def __init__(self, *args, **kwargs):
        yaml.Loader.__init__(self, *args, **kwargs)
        toplevel = True
        m = u'tag:yaml.org,2002:map'
        self.prev_constructor = self.yaml_constructors[m]
        self.add_constructor(m, type(self).construct_yaml_map)

    def construct_yaml_map(self, node):
        data = OrderedDict()
        yield data
        value = self.construct_mapping(node)
        data.update(value)

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
        else:
            raise yaml.constructor.ConstructorError(None, None,
                'expected a mapping node, but found %s' % node.id, node.start_mark)

        mapping = OrderedDict()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError, exc:
                raise yaml.constructor.ConstructorError('while constructing a mapping',
                    node.start_mark, 'found unacceptable key (%s)' % exc, key_node.start_mark)
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping


def get_value(d, key, default=None):
    defaults = {'type': 'bookkeeping',
                'perms': 'rwx',
                'name': '',
                'reclassifiable': False,
                'reclassified_regions': {},
                'contents': '',
                'csv': None,
                'values': [],
                'substage_type': 'bookkeeping',
                'processed_regions': [],
                'new_regions': [],
                'substage_types': [],
                'used_bookkeeping': [],
                'defined_regions': [],
                'undefined_regions': [],
                'subregion_types': [],
                'allowed_symbols': [],
                'regions': {},
                'comments': '',
                'stack': None,
                'include_children': False,
                'addresses': "children",
                'substagename': 'spl',
                'default_perms': 'rwx',
                'subregions': {}}
    if default is None and key in defaults.iterkeys():
        default = defaults[key]

    val = d[key] if key in d.iterkeys() else default
    val = val.strip() if type(val) == str else val
    return val


class MmapFileParser():
    def __init__(self, f):
        with open(f, "r") as o:
            self.data = dict(yaml.load(o))
        self._raw_regions = get_value(self.data, 'regions')
        self.values = get_value(self.data, 'values')
        self.substage_types = get_value(self.data, 'substage_types')
        self.subregion_types = get_value(self.data, 'subregion_types')
        self.stagename = get_value(self.data, 'stagename')
        self.stage = Main.stage_from_name(self.stagename)
        self.regions = {}
        for (k, v) in self._raw_regions.iteritems():
            self._parse(k, v, None)
        self._resolve_addresses()
        # self._resolve_addresses()
        for r in self.regions.itervalues():
            r.addresses.merge_overlaps()
            r.addresses.merge_equals()

        MmapRegion.check_regions(self.regions)

    def _parse(self, short_name, region_dict, parent):
        parentname = getattr(parent, 'short_name') if parent else ''
        short_name = parentname + "." + short_name if parentname else short_name
        if short_name in self.regions.iterkeys():
            raise KeyError("%s in %s" % (short_name, list(self.regions.iteritems())))
        current = MmapRegion(short_name, region_dict, self.stage, parent, self.values)
        self.regions[short_name] = current
        for (k, s) in current._raw_subregions.iteritems():
            self._parse(k, s, current)

    def _resolve_addresses(self):
        total = len(self.regions)
        numresolved = len([r for r in self.regions.itervalues() if r.addresses_resolved])
        lastresolved = 0
        regnames = self.regions.iterkeys()
        while (numresolved is not lastresolved) and (numresolved <= total):
            lastresolved = numresolved
            for name in regnames:
                r = self.regions[name]
                if not r.addresses_resolved:
                    r.resolve_addresses(self.regions, self.values)
                    if r.addresses_resolved:
                        numresolved += 1
                self.regions[name] = r


class SubstagesConfig():
    def __init__(self, fn, d, num, stage, prevstage, mmap_info):
        self.fn = fn
        self.num = num
        self.substage_type = get_value(d, 'substage_type').lower()
        prev_regions = prevstage.defined_regions if prevstage else set()
        self._new_regions = get_value(d, 'new_regions')
        self.new_regions = set()
        self.defined_regions = set(prev_regions)
        self._reclassified_regions = get_value(d, 'reclassified_regions')
        self.reclassified_regions = set()
        self._undefined_regions = get_value(d, 'undefined_regions')
        self.undefined_regions = set()
        self.allowed_symbols = get_value(d, 'allowed_symbols')
        self.reclassified_regions = set()
        self.comments = get_value(d, 'comments')
        self.writable_regions = set()
        stack = get_value(d, 'stack')
        prevstack = prevstage.stack if prevstage else None
        self.stack = stack if stack else prevstack

        self._setup_region_info(mmap_info.regions if mmap_info else {}, prev_regions)
        # convert from set to list
        for i in ['writable', 'reclassified', 'defined', 'new', 'undefined']:
            n = i + '_regions'
            s = getattr(self, n)
            setattr(self, n, list(s))
        self.new_reloc = False
        if self.is_cooking_substage() or self.is_patching_substage():
            # see if listed in reloc table
            if db_info.get(stage).name_in_relocs_table(self.fn):
                self.new_reloc = True
        self.applied_relocs = [] if prevstage is None else prevstage.applied_relocs
        if prevstage and prevstage.new_reloc:
            self.applied_relocs.append(prevstage.fn)

    @classmethod
    def is_cooking_substage_type(cls, typ):
        return typ in ['loading']

    def is_cooking_substage(self):
        return self.is_cooking_substage_type(self.substage_type)

    def is_patching_substage(self):
        return self.is_patching_substage_type(self.substage_type)

    @classmethod
    def is_patching_substage_type(cls, typ):
        return typ in ['patching']

    def _include_region(self, all_regions, r_name, r_list, remove=False, force=False):
        if not remove and r_name not in all_regions.iterkeys():
            raise Exception("No existing region named %s" % r_name)
        info = all_regions[r_name]
        if remove:
            if r_name in r_list:
                r_list.remove(r_name)
        else:
            r_list.add(r_name)
        if info.include_children or force:
            map(lambda x: self._include_region(all_regions, x, r_list, remove),
                info.children_names)

    def _setup_region_info(self, all_regions, prev_regions):
        for r in self._new_regions:
            self._include_region(all_regions, r, self.new_regions)
        for r in self._undefined_regions:
            self._include_region(all_regions, r, self.undefined_regions, force=True)
        reclass = {}
        self.defined_regions.update(prev_regions)
        self.defined_regions.update(self.new_regions)
        self.defined_regions.difference_update(self.undefined_regions)
        for (r, v) in self._reclassified_regions.iteritems():
            reclass[r] = set()
            self._include_region(all_regions, r, reclass[r], force=True)
            if r not in self.defined_regions:
                raise Exception("trying to reclassify region %s that is not defined in %s" % (r,
                                                                                                  self.defined_regions))

        self.defined_regions.update(self.new_regions)
        self.defined_regions.difference_update(self.undefined_regions)

        for (r, v) in reclass.iteritems():
            for n in v:
                all_regions[n].reclassification_rules[self.num] = self._reclassified_regions[r]
            self.reclassified_regions.update(v)

        for (n, r) in all_regions.iteritems():
            if n in self.defined_regions and MmapRegion.is_region_writable(self.substage_type, r.type_at_substage(self.num)):
                self.writable_regions.add(r.short_name)

    def __repr__(self):
        return "SubstagesConfig(num=%s, fn=%s, type=%s, regions=%s, writable=%s, allowed=%s)" % \
            (self.num,
             self.fn,
             self.substage_type, self.defined_regions,
             len(self.writable_regions), self.allowed_symbols)


class MmapRegion():
    def __init__(self, short_name, d, stage, parent=None, values={}):
        if parent is None:
            parent_type = None
            parent_default_perms = None
            parent_include_children = None
            parent_reclassifiable = None
        else:
            parent_type = parent.typ
            parent_default_perms = parent.default_perms
            parent_include_children = parent.include_children
            parent_reclassifiable = parent.reclassifiable
        self.stage = stage
        self.addresses = intervaltree.IntervalTree()
        self.short_name = short_name
        self.name = get_value(d, 'name')
        self._raw_typ = get_value(d, 'type', parent_type).lower()
        self._raw_addresses = get_value(d, 'addresses')
        self._raw_default_perms = get_value(d, 'default_perms', parent_default_perms)
        self._raw_subregions = get_value(d, 'subregions')
        self._raw_include_children = get_value(d, 'include_children', parent_include_children)
        self._raw_reclassifiable = get_value(d, 'reclassifiable', parent_reclassifiable)
        self._csv = get_value(d, 'csv')
        if self._csv:
            self._csv = Main.populate_from_config(self._csv)
        if parent and parent._csv:
            # if parent had csv, don't propigate csv definition
            self._csv = None
        self.contents = get_value(d, 'contents')
        self.children_names = [self.short_name + '.' + s for s in self._raw_subregions.iterkeys()]
        self.parent = parent
        self.addresses_resolved = False
        self._convert_from_raw(values)
        self.resolve_addresses(values=values)
        self.reclassification_rules = {0: self.typ}

    @classmethod
    def check_regions(cle, regions):
        for (k, v) in regions.iteritems():
            if not v.addresses_resolved:
                raise Exception("ERROR: did not resolve address for region %s %s" % (k, v))
            else:
                addrs = v.addresses
                for c in v.children_names:
                    child = regions[c]
                    for a in child.addresses:
                        res = addrs.search(a)
                        if len(res) < 1:
                            raise Exception("%s's region (%s) not inside parent's %s (%s)") % \
                                (child.short_name,
                                 child.addresses,
                                 v.short_name,
                                 v.addresses)

    def type_at_substage(self, substage):
        keys = filter(lambda x: x <= substage, sorted(self.reclassification_rules.iterkeys()))
        if len(keys) <= 1:
            keys = [0]
        return self.reclassification_rules[keys[-1]]

    @classmethod
    def is_region_writable(cls, substage_typ, region_typ):
        if SubstagesConfig.is_cooking_substage_type(substage_typ):
            return region_typ in ['stack',
                                  'future', 'global']
        elif SubstagesConfig.is_patching_substage_type(substage_typ):
            return region_typ in ['stack',
                                  'patching', 'global']

        else:
            return region_typ in ['stack', 'bookkeeping',
                                  'global']

    def _convert_from_raw(self, values):
        raw_fields = ['typ', 'default_perms', 'addresses', 'subregions',
                      'include_children', 'reclassifiable']
        for f in raw_fields:
            if f == 'addresses':
                self.resolve_addresses(values=values)
            else:
                setattr(self, f, getattr(self, "_raw_%s" % f))

    def __repr__(self):
        return "%s%s of type (%s) (parent %s, %s children) @[%s]" % (self.short_name,
                                                                     ' (%s) ' % self.name
                                                                     if self.name else '',
                                                                     self.reclassification_rules,
                                                                     self.parent.short_name
                                                                     if self.parent else 'None',
                                                                     len(self.children_names),
                                                                     self.addresses)

    def _resolve_special_addr_region(self, handle, allregions, values):
        if handle == 'remainder':
            parent = self.parent
            if self.parent and self.parent.addresses_resolved:
                siblings = [allregions[n] for n in
                            self.parent.children_names if n in allregions.iterkeys()]
                if not all(map(lambda x: x.short_name == self.short_name or x.addresses_resolved,
                           siblings)):
                    return False
                if not len(siblings) == len(self.parent.children_names):
                    return False
                remainder = intervaltree.IntervalTree(self.parent.addresses)
                for s in siblings:
                    if s.short_name == self.short_name:
                        continue
                    for i in s.addresses:
                        remainder.chop(i.begin, i.end)
                toremove = []
                self.addresses = remainder
                return True
        elif handle == 'children':
            res = intervaltree.IntervalTree()
            if len(self.children_names) == 0:
                return False
            for n in self.children_names:
                if n in allregions.iterkeys() and allregions[n].addresses_resolved:
                    res = res | allregions[n].addresses
                else:
                    return False
            self.addresses = res
            return True
        else:
            reg_name = handle.rsplit(".", 1)[0]
            if reg_name in allregions.iterkeys() and allregions[reg_name].addresses_resolved:
                res = self._resolve_region_relative(handle, allregions)
                if isinstance(res, type(handle)):
                    return False
                else:
                    self.addresses = intervaltree.IntervalTree([res])
                    return True
            else:
                return False

    def _add_addr_range(self, start, end):
        if isinstance(start, (int, long)) and isinstance(end, (int, long)):
            if not end >= start:
                raise Exception("start addr %x must be smaller than end address %x for %s" %
                                (start, end, self.short_name))
            self.addresses.add(intervaltree.Interval(long(start), long(end)))
        else:
            raise Exception("One of start addr (%s) end addr (%s) is not an int for %s" %
                            (start, end, self.short_name))

    def _resolve_region_relative(self, s, allregions):
        val = s
        split = s.split('.')
        if '.'.join(split[:-1]) in allregions.iterkeys():
            statedname = '.'.join(split[:-1])

            def _start(regname, begin):
                r = allregions[regname]
                ret = s
                if r.addresses_resolved:
                    if begin:
                        ret = min(r.addresses).begin
                    else:
                        ret = max(r.addresses).end
                return ret

            def _relocated(regname, fullname):
                r = allregions[regname]
                ret = s
                rend = fullname.rsplit(".", 1)[1]
                cardinalres = re.match("([\d])+_relocated", rend)
                cardinal = cardinalres.group(1)
                relocindex = re.sub("[._relocated]+", "", rend)
                if r.addresses_resolved:
                    start = min(r.addresses).begin
                    end = max(r.addresses).end
                    (offset,
                     mod) = db_info.get(self.stage).reloc_offset_and_mod_from_cardinal(relocindex)
                    ret = intervaltree.Interval(long((start + offset) % mod), long((end + offset) % mod))
                return ret

            suffixes = {
                '.start': lambda x: _start(x, True),
                '.end': lambda x: _start(x, False),
                '_relocated': lambda x: _relocated(x, s)
            }
            fullname = self.short_name + '.' + statedname
            regname = None
            if statedname in allregions.iterkeys():
                regname = statedname
            elif fullname in allregions.iterkeys():
                regname = fullname
            if regname:
                sn = [n for n in suffixes.iterkeys() if s.endswith(n)][0]
                val = suffixes[sn](regname)
        return val

    def _resolve_var_addr(self, s, allregions, values):
        val = s
        split = s.split('.')
        trysymbol = False
        if '.'.join(split[:-1]) in allregions.iterkeys():
            val = self._resolve_region_relative(s, allregions)
            return val

        if values and s in values.iterkeys():
            val = values[s]
            return val
        if config.Main.stage_from_name(split[0]):
            stage = config.Main.stage_from_name(split[0])
            #if not stage.post_build_setup_done:
            if len(split) > 1:
                attr = split[1]
                val = getattr(stage, attr, val)
                return val
        if s.startswith('.'):
            end = '.end'
            start = '.start'
            if s.endswith(end):
                (start, val) = utils.get_section_location(re.sub(end, '', s), self.stage)
            elif s.endswith(start):
                (val, end) = utils.get_section_location(re.sub(start, '', s), self.stage)
            if isinstance(val, (int, long)) and val < 0:
                val = s
            return val
        if not s.startswith('0x'):
            val = utils.get_symbol_location(s, self.stage)

            if val < 0:
                val = s
            return val
        else:
            val = long(s, 16)
        return val

    def _lookup_addr_value(self, s, allregions, values):
        val = None
        stmt = s.split()
        newstmt = []
        operators = {'+': lambda x, y: x + y,
                     '-': lambda x, y: x - y}
        for s in stmt:
            if s not in operators.iterkeys():
                a = self._resolve_var_addr(s, allregions, values)
            else:
                a = s
            newstmt.append(a)
        if len(newstmt) == 1 and isinstance(newstmt[0], (int, long)):
            val = newstmt[0]
        elif len(newstmt) > 1 and isinstance(newstmt[0], (int, long)):
            rest = newstmt
            results = rest[0]
            rest = rest[1:]
            while len(rest) >= 2:
                op = rest[0]
                remainder = rest[1]
                if len(rest) > 2:
                    rest = rest[2:]
                else:
                    rest = []
                if op in operators.iterkeys() and isinstance(remainder, (int, long)) and isinstance(results, (int, long)):
                    results = operators[op](results, remainder)
                else:
                    results = None
                    break
            val = results
        return val

    def _resolve_addr_region(self, a, allregions, values):
        if type(a) == list:
            (start, end) = a
            if isinstance(start, (int, long)) and isinstance(end, (int, long)):
                self._add_addr_range(start, end)
                return True
            else:
                if not isinstance(start, (int, long)):
                    sint = self._lookup_addr_value(start, allregions, values)
                else:
                    sint = start
                if not isinstance(end, (int, long)):
                    eint = self._lookup_addr_value(end, allregions, values)
                else:
                    eint = end
                if sint is not None and eint is not None:
                    self._add_addr_range(sint, eint)
                    return True
        else:
            return self._resolve_special_addr_region(s, allregions)
        return False

    def resolve_addresses(self, all_regions={}, values={}):
        all_resolved = True
        if self.addresses_resolved is True:
            return
        elif self._csv:
            (f, parsed) = parse_am37x_register_tables.parsecsv(self._csv)
            addrs = intervaltree.IntervalTree()
            for p in parsed:
                addr = p[parse_am37x_register_tables.TITable.ADDRESS]
                if addr:
                    addr = long(addr, 0)
                else:
                    continue
                wid = p[parse_am37x_register_tables.TITable.WIDTH]
                name = p[parse_am37x_register_tables.TITable.NAME]
                # create a unique name without spaces
                name = re.sub("[\s]", "", name) + (".%x" % addr)
                size = long(wid) / 8 if wid else 4
                i = intervaltree.Interval(long(addr), long(addr + size))
                addrs.add(i)
                raw_perms = p[parse_am37x_register_tables.TITable.TYPE].lower()
                perms = "readonly" if 'w' not in raw_perms else 'global'
                self._raw_subregions[name] = {
                    'addresses': [i.begin, i.end],
                    'include_children': False,
                    'type': perms,
                    }
                self.children_names.append("%s.%s" % (self.short_name, name))
            self.addresses = addrs
            f.close()
            all_resolved = True
        elif (type(self._raw_addresses) == list):
            if type(self._raw_addresses[0]) == list:  # its a list of lists of subregions
                for a in self._raw_addresses:
                    all_resolved = all_resolved and self._resolve_addr_region(a, all_regions,
                                                                              values)
            else:
                all_resolved = self._resolve_addr_region(self._raw_addresses, all_regions, values)
        else:
            all_resolved = self._resolve_special_addr_region(self._raw_addresses, all_regions,
                                                             values)
        self.addresses_resolved = all_resolved


class SubstagesFileParser():
    def __init__(self, stage, f, mmap_info):
        with open(f, 'r') as o:
            data = yaml.load(o, OrderedDictYAMLLoader)
            self.substages = {}
            self.mmap_info = mmap_info
            if data is None:
                return
            keys = list(data.iterkeys())
            for i in range(0, len(data)):
                n = keys[i]
                d = dict(data[n])
                prev = self.substages[i-1] if i > 0 else None
                self.substages[i] = SubstagesConfig(n, d, i, stage, prev, mmap_info)

    @classmethod
    def get_substage_fns(cls, f):
        with open(f, "r") as o:
            data = yaml.load(o, OrderedDictYAMLLoader)
            if data:
                return list(data.iterkeys())
            else:
                return []

    @classmethod
    def parse_file(cls, f):
        with open(f, "r") as o:
            data = yaml.load(o, OrderedDictYAMLLoader)
            return data
