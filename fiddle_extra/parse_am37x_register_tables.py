#!/usr/bin/env python2
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

import unicodedata
import os
import sys
import argparse
import re
import string
import csv
from pdfminer import pdfparser, pdfpage, pdfdocument, pdfdevice, pdfinterp, pdftypes, psparser, converter, layout


class TIColInfo():
    def __init__(self, name, regex, l, r, c, obj, typ):
        self.name = name
        self.regex = regex
        self.l = l
        self.r = r
        self.c = c
        self.obj = obj
        self.typ = typ


class TITable():
    NAME = 'name'
    WIDTH = 'width'
    RESET = 'reset'
    OFFSET = 'offset'
    ADDRESS = 'address'
    TYPE = 'typ'

    def __init__(self, var_rules={}, phys_addrs={},
                 force_phys_addrs=[],
                 name=u'Register Name', field_center_offset = {},
                 label_bottom_offset=0,
                 namere=None, addrre=None, offsetre=None,
                 resetre=None, widthre=None, typre=None,
                 var_sub_fn=None, default_width=32):
        self.name = name
        self.force_phys_addrs = force_phys_addrs
        self.typs = []
        self.default_width = default_width
        self.offsets = []
        self.phys_addrs = phys_addrs if phys_addrs else {u'Physical Address': ''}
        self.resets = []
        self.widths = []
        if addrre and isinstance(addrre, str):
            addrre = re.compile(addrre)
        if resetre and isinstance(resetre, str):
            resetre = re.compile(resetre)
        if offsetre and isinstance(offsetre, str):
            offsetre = re.compile(offsetre)
        if namere and isinstance(namere, str):
            namere = re.compile(namere)
        if typre and isinstance(typre, str):
            typre = re.compile(typre)
        if widthre and isinstance(widthre, str):
            widthre = re.compile(widthre)

        self.customnamere = namere if namere else False
        self.customoffsetre = offsetre if offsetre else False
        self.customaddrre = addrre
        self.noaddrs = [u'N/A', u'-']
        self._possible_varnames = ['i', 'j', 'k', 'l', 'm', 'n', 'x', 'y']
        self._names = {TITable.TYPE: [u'Type'],
                       TITable.NAME: [u'Register Name', u'Name', u'Register\nName', u'Register Name (j = 0', self.name],
                       TITable.WIDTH: [u'Register Width', u'Width', u'RegisterWidth',
                                       u'Width (Bits)', u'Register Width (Bits)',
                                       u'Width (bits)', u'Register Width (bits)'],
                       TITable.RESET: [u'Reset Type'],
                       TITable.OFFSET: [u'Offset', u'Address Offset'],
                       TITable.ADDRESS: [u'Physical Address', u'Physical', u'Base Address', u'Base']}
        self.col_info = {}
        self.var_sub_fn = var_sub_fn
        self._regexps = {TITable.TYPE: typre if typre else re.compile("^(R|W|RW|R/W|RW 1toClr|Reserved|R/OCO)$"),
                         TITable.NAME: namere if namere else re.compile("(^[A-Z][A-Z0-9_%s]+)$|^(Reserved for non-GP devices.)$|^RESERVED$" % ''.join(self._possible_varnames)),
                         TITable.WIDTH: widthre if widthre else re.compile("^[0-9]{1,2}$"),
                         TITable.RESET: resetre if resetre else re.compile("^([CW]{1})|(C \( refer to)$"),
                         TITable.OFFSET: offsetre if offsetre else re.compile("^0 ?x ?(?P<base>([0-9A-F]{4} ?[0-9A-F]{4})|([0-9A-F]{1,4}))$"),
                         TITable.ADDRESS: addrre if addrre else re.compile("^(0 ?x ?)?(?P<base>([0-9A-F]{4} ?[0-9A-F]{4,5})|-|N/A)$")}
        self.var_rules = var_rules
        self.var_names = []
        if len(var_rules) > 0:
            self._add_var_rules()
        self.field_center_offsets = field_center_offset
        self.label_bottom_offset = label_bottom_offset


    def default_sub_fn(self, aname, i, results):
        newresults = {}
        newresults = {f: [] for f in self._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: self._regexps[TITable.ADDRESS],
                   TITable.OFFSET: self._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base'] if offset else ""


        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in self._names.iterkeys():
                newresults[f].append(locals()[f])

        variablefield = False
        nonbaseaddr = re.sub(baseaddr, "", addrvalue)
        nonbaseoffset = re.sub(baseoffset, "", offset)

        nonbaseaddr = re.sub("(0x)+", "", nonbaseaddr)  # remove any 'x's
        nonbaseoffset = re.sub("(0x)+", "", nonbaseoffset)

        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16) if baseoffset else ''

        rows = []
        index = 0

        suffix = self.phys_addrs[aname] if self.phys_addrs[aname] else ""
        if not (aname == TITable.ADDRESS) and not suffix:
            suffix = aname
        if suffix == "Physical Address":
            suffix = ""
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes
        shortname = name
        #print "%s %s %s" % (name, suffix, TITable.ADDRESS)
        name = name + '_' + suffix if suffix else name
        #print name
        for val in [nonbaseaddr, nonbaseoffset, name]:
            if "+" in val or any(map(lambda x: x in val, self.var_names)):
                variablefield = True
        if variablefield:
            v = None
            for val in [nonbaseaddr, nonbaseoffset, name]:
                for var in self.var_names:
                    if var in val:
                        if (v is not None) and ((not v == var) and (v is not "+")):
                            raise Exception("we can only handle exactly 1 variable subst,"
                                            " found %s [%s]" %
                                            ({k: v[i] for (k, v) in results.iteritems()},
                                             self.var_names))
                        else:
                            v = var
                    elif v is None and "+" in val:
                        if v is None:
                            v = "+"
                if "+" == v:
                    v = None
                    if len(self.var_names) > 1:
                        for var in self.var_names:
                            if var in shortname:
                                if v is not None:
                                    raise Exception("Don't know what variable to substitute for"
                                                    " %s found (from %s)" %
                                                    ({k: v[i] for (k, v) in results.iteritems()},
                                                     self.var_names))
                                else:
                                    v = var
                    else:
                        v = self.var_names[0]
            offsets = self.var_rules[aname][v]

            for o in offsets:
                rowname = re.sub(v, str(o), name)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % (baseaddr + o)
                c[TITable.OFFSET] = "0x%x" % (baseoffset + o) if baseoffset else ""
                rows.append(c)
        else:
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = re.sub(" ", "", addrvalue)
            c[TITable.OFFSET] = re.sub(" ", "", offset)
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def _add_var_rules(self):
        map(self.var_names.extend, list(v.iterkeys() for v in self.var_rules.itervalues()))
        self.var_names = list(set(self.var_names))  # remove duplicates

        allvars = ''.join(self.var_names)
        i = "0x ?[0-9A-F]{0,4} ?([0-9A-F]{4})?|0x ?[0-9A-F]+"
        plus = "\s*\+|\s*\+\s*\(\s*([%s]\s*\*\s*(?P<mult1>%s)|((?P<mult0>%s)\s*\*\s*[%s])|[%s]\s*\*?)\s*\)|(\s*\+\s*\(\s*[%s]\s*\*)?|(\s*\+\s*\(\s*(%s)\s*\*?)" % (allvars, i, i, allvars, allvars, allvars, i)
        addrre = self.customaddrre if self.customaddrre else re.compile("^((0 ?x ?(?P<base>([0-9A-F]{4} ?[0-9A-F ]{4}))(%s)?)|-|N/A)$" % plus)
        offsetre = self.customoffsetre if self.customoffsetre else re.compile("^0 ?x ?(?P<base>([0-9A-F]{4} ?[0-9A-F]{4})|([0-9A-F]{1,4}))(%s)?$" % plus)
        namere = self._regexps[TITable.NAME] if self.customnamere else re.compile("(^[A-Z][A-Z0-9_%s]+?)$|^(Reserved for non-GP devices.)$|^RESERVED$" % allvars)
        self._regexps[TITable.OFFSET] = offsetre
        self._regexps[TITable.ADDRESS] = addrre
        self._regexps[TITable.NAME] = namere


    def is_column(self, obj):
        text = TIPDF.get_text(obj)
        text = unicode(re.sub("\n", " ", text)).strip()
        #print "is column? %s" % text
        for (t, vals) in self._names.iteritems():
            for v in vals:
                if v in text:
                    return t
        for k in self.phys_addrs.iterkeys():
            if unicode(k) == unicode(text):
                return TITable.ADDRESS
        return None

    def add_column(self, name, obj, typ=None):
        if typ is None:
            typ = self.is_column(obj)
        if typ is None:
            raise Exception("%s is not a column title" % obj)
        key = typ
        if typ == TITable.ADDRESS:
            text = name
            text = re.sub("Physical", "", text)
            text = re.sub("Address", "", text)
            text = re.sub("Base", "", text)
            text = text.strip()
            if text:
                if text not in self.phys_addrs:
                    self.phys_addrs[text] = ''
                key = text
                pa = u'Physical Address'
                if pa in self.phys_addrs:
                    # remove soon-to-be unused address column
                    del self.phys_addrs[pa]
                if pa in self.col_info:
                    del self.col_info[pa]
            else:
                nphys = len(self.phys_addrs)
                if name not in self.phys_addrs:
                    self.phys_addrs[name] = ''
                key = name
        else:
            if typ in [k for (k, v) in self.col_info.iteritems() if v.typ == typ]:
                return
        regex = self._regexps[typ]
        #print "adding col %s of type %s (regex: %s)" % (key, typ, regex.pattern)
        left = obj.bbox[0]
        right = obj.bbox[2]
        center = (left + right) / 2
        if key in self.field_center_offsets:
            center += self.field_center_offsets[key]
        info = TIColInfo(key, regex, left, right, center,  obj, typ)
        self.col_info[key] = info


class TIPDF():
    ntables = 0
    successful = 0

    @classmethod
    def resolve_dest(cls, dest):
        if isinstance(dest, str):
            dest = resolve1(doc.get_dest(dest))
        elif isinstance(dest, psparser.PSLiteral):
            dest = resolve1(doc.get_dest(dest.name))
        if isinstance(dest, dict):
            dest = dest['D']
        return dest

    @classmethod
    def normalize_text(cls, text):
        text = re.sub(u"\u2002", " ", text)
        text = re.sub(u"\u2013", "-", text)
        return text.encode("ascii", "replace").strip()

    @classmethod
    def get_text(cls, o):
        return cls.normalize_text(o.get_text())


    @classmethod
    def traverse(cls, t, prefix="."):
        try:
            for i in t:
                print "%s%s%s" % (prefix, i, prefix)
                if isinstance(i, layout.LTContainer):
                    cls.traverse(i, prefix + ".")
                else:
                    print i.__dict__
        except:
            pass

    @classmethod
    def lookup_font(cls, text):
        i = None
        for i in text:
            if isinstance(i, layout.LTChar):
                return i.fontname
            elif isinstance(i, layout.LTText):
                return cls.lookup_font(i)
        return None

    @classmethod
    def calculate_center(cls, obj):
        left = obj.bbox[0]
        right = obj.bbox[2]
        return (left + right) / 2

    @classmethod
    def get_text_obj(cls, obj, index, regexp, text):
        otext = cls.get_entry_text(obj)
        if otext == text:
            return obj
        else:
            if isinstance(obj, layout.LTTextBox):
                i = 0
                for l in obj:
                    ret = cls.get_text_obj(l, text)
                    if ret:
                        return ret
            return None


    @classmethod
    def _try_add(cls, t, obj, results, nrows, nameoffset):
        if obj.bbox[0] < ((t.col_info[TITable.NAME].l - nameoffset)- 0.5): # don't consider items that are past the left of the table
            return False

        text = cls.get_entry_text(obj)
        added = False
        center = cls.calculate_center(obj)
        closest_field = None
        min_diff = sys.maxint
        field_info = None
        for (field, info) in t.col_info.iteritems():
            if field == TITable.NAME:
                center -= nameoffset
            diff = abs(center - info.c)
            if diff < min_diff:
                min_diff = diff
                closest_field = field
                field_info = info

        #print "%s closest to %s (%s)" % (obj, closest_field, field_info.regex.pattern)

        addrfield = [j for j in t.col_info.itervalues() if j.typ == TITable.ADDRESS]
        if isinstance(obj, layout.LTText):
            text = cls.get_entry_text(obj)
            if field_info.regex.search(text):
                if len(results[closest_field]) >= nrows:
                    added = False
                else:
                    results[closest_field] += [obj]
                    added = True
            elif isinstance(obj, layout.LTTextLine) and \
                            ((closest_field == TITable.OFFSET) or \
                             (closest_field in [a.name for a in addrfield])):

                fields = [j for j in text.rsplit(")", 2) if len(j) > 0]
                if len(fields) == 2:
                    fields = [f+")" for f in fields]
                    off = fields[0].strip()
                    adr = fields[1].strip()
                    if adr[0] == '+':  # move + to end of off if @ start of adr
                        adr = adr[1:].strip()
                    if TITable.OFFSET in t.col_info:
                        col1 = t.col_info[TITable.OFFSET]
                        col2 = addrfield[0]
                    elif len(addrfield) == 2:
                        col1 = addrfield[0]
                        col2 = addrfield[1]
                    else:
                        return False

                    if col1.regex.match(off) \
                       and col2.regex.match(adr):
                        #print "splitting objects"
                        (oobj, aobj) = cls.split_text(obj, off, adr)
                        # TODO: split text into two obbjects
                        results[col1.name].append(oobj)
                        results[col2.name].append(aobj)
                        added = True
        return added
    @classmethod
    def strip_text_line(cls, line, text):
        linetext = cls.get_entry_text(line).strip()
        startindex = linetext.index(text)
        endindex = startindex + len(text)
        chars = filter(lambda x: isinstance(x, layout.LTAnno) or isinstance(x, layout.LTChar), line._objs)
        newline = chars[-1]
        line._objs = chars[startindex:endindex] + [newline]  # keep newline char
        return line

    @classmethod
    def split_text(cls, line, text1, text2):
        textbox = not isinstance(line, layout.LTTextLine)
        if textbox:
            box = line
            line = line._objs[0]
        second = object.__new__(line.__class__)
        second.__dict__ = dict(line.__dict__)
        (o1, o2) = (cls.strip_text_line(line, text1),
                    cls.strip_text_line(second, text2))
        if textbox:
            box2 = object.__new__(box.__class__)
            box2.__dict__ = dict(box.__dict__)
            box._objs = [o1]
            box2._objs = [o2]
            return (box, box2)
        else:
            return (o1, o2)


    @classmethod
    def try_add_field(cls, t, obj, results, nrows, nameoffset=0):
        if isinstance(obj, layout.LTTextLine):
            cls._try_add(t, obj, results, nrows, nameoffset)
        elif isinstance(obj, layout.LTTextBox):
            if not cls._try_add(t, obj, results, nrows, nameoffset): #only if add fails recurse
                for i in obj:
                    cls.try_add_field(t, i, results, nrows, nameoffset)



    @classmethod
    def is_name_header(cls, obj, name):
        if isinstance(obj, layout.LTText):
            text = cls.get_entry_text(obj)
            match = cls.search_text_box(obj, name)
            if match:
                return obj
        return None

    @classmethod
    def get_full_addr_col_label(cls, page, namecol, physcol, t):
        physcenter = cls.calculate_center(physcol)
        text = ""
        for l in page:
            if isinstance(l, layout.LTText):
                lcenter = cls.calculate_center(l)
                if cls.in_same_row(namecol, l, t) and (abs(lcenter - physcenter) <= 0.2):
                    text += cls.get_entry_text(l) + " "
        return text.strip()

    @classmethod
    def in_same_row(cls, o1, o2, t):
        top = o1.bbox[1]
        bottom = o1.bbox[3]

        ttop = o2.bbox[1]
        tbottom = o2.bbox[3]
        return (ttop >= top) and (tbottom <= (bottom + t.label_bottom_offset))

    @classmethod
    def is_not_in_table_bounds(cle, tablestart, tableend, o):
        return ((o.bbox[1] > tablestart) or (tableend and (o.bbox[3] < tableend)))

    @classmethod
    def vertical_offset(cls, o1, o2):
        return o1.bbox[1] - o2.bbox[1]

    @classmethod
    def find_table_columns(cls, page, table, tablestart, tableend, verbose, vr={}, pa={}, offset=0,
                           offsetre=None, resetre=None, widthre=None, field_center_offset={},
                           label_bottom_offset=0, force_phys_addrs=[],
                           default_width=32, name=u'Register Name',
                           namere=None, addrre=None, typre=None, var_sub_fn=None):
        namecol = None
        t = TITable(var_rules=vr, phys_addrs=pa,
                    namere=namere, name=name, force_phys_addrs=force_phys_addrs,
                    offsetre=offsetre, field_center_offset=field_center_offset,
                    widthre=widthre, default_width=default_width,
                    label_bottom_offset=label_bottom_offset,
                    addrre=addrre, typre=typre, var_sub_fn=var_sub_fn)
        for o in page:
            if cls.is_not_in_table_bounds(tablestart, tableend, o):
                continue
            for i in t._names[TITable.NAME]:
                c = cls.is_name_header(o, i)
                if c:
                    namecol = o
                    t.add_column(i, o, TITable.NAME)
                    t.name = i
            if namecol:
                break
        if namecol is None:
            raise Exception("No name column found in %s" % table)
        # now find table label row height by finding first rect below namecol label
        closest_rect = None
        for o in page:
            if cls.is_not_in_table_bounds(tablestart, tableend, o):
                continue
            if isinstance(o, layout.LTRect) and (abs(o.bbox[1] - o.bbox[3]) < 1.5):  # is a line
                # if left edge of line is not near left edge of name col_info
                if abs(namecol.bbox[0] - (o.bbox[0] + offset)) > 5:
                    continue
                odiff = cls.vertical_offset(namecol, o)
                if (odiff > 0) and (closest_rect is None):
                    closest_rect = o
                else:
                    cdiff = cls.vertical_offset(namecol, closest_rect)
                    if (odiff > 0) and (odiff < cdiff):
                        closest_rect = o
        if closest_rect is None:
            t = "No horizonal line found near '%s'" % namecol
            raise Exception(t)
        # pretend namecol bottom is at closest_rect
        namecol.bbox = (namecol.bbox[0], closest_rect.bbox[1],
                        namecol.bbox[2], namecol.bbox[3],)
        for o in page:
            if cls.is_not_in_table_bounds(tablestart, tableend, o):
                continue
            if not isinstance(o, layout.LTText):
                continue
            if cls.in_same_row(namecol, o, t):
                c = t.is_column(o)
                if c and c == TITable.ADDRESS:
                    text = cls.get_full_addr_col_label(page, namecol, o, t)
                    t.add_column(text, o, TITable.ADDRESS)
                elif c:
                    t.add_column(cls.get_entry_text(o), o, c)
        if t.force_phys_addrs:
            if not set(t.phys_addrs.iterkeys()) == set(t.force_phys_addrs):
                # figure split out column
                missing = []
                for k in t.force_phys_addrs:
                    if k not in t.phys_addrs:
                        missing.append(k)
                if len(missing) == 2:
                    for k in t.col_info:
                        addrs = k.split()
                        if set(addrs) == set(missing):
                            # split!
                            info = t.col_info[k]
                            (o1, o2) = cls.split_text(info.obj, addrs[0], addrs[1])
                            bbox = o1.bbox
                            (x1, y1, x2, y2) = o1.bbox
                            o1.bbox = (x1, y1, info.c, y2)
                            o2.bbox = (info.c, y1, x2, y2)
                            del t.col_info[k]
                            del t.phys_addrs[k]
                            t.add_column(addrs[0], o1, TITable.ADDRESS)
                            t.add_column(addrs[1], o2, TITable.ADDRESS)
                            break

        return t

    @classmethod
    def parse_register_table_from_page(cls, interp, dev, page, sectionname,
                                       table, aftertable,
                                       verbose=False, name_offset=0, skip=False,
                                       offsetre=None, resetre=None, widthre=None,
                                       namere=None, addrre=None, default_width=32,
                                       typre=None, var_sub_fn=None,
                                       label_bottom_offset=0, force_phys_addrs=[],
                                       name=u'Register Name', field_center_offset={},
                                       var_rules={}, phys_addrs={}):
        if skip:
            return {}

        tablestart = table.bbox[1]
        tableend = aftertable.bbox[1] if aftertable else None
        t = cls.find_table_columns(page, table, tablestart, tableend, verbose,
                                   vr=var_rules, pa=phys_addrs, typre=typre,
                                   field_center_offset=field_center_offset,
                                   label_bottom_offset=label_bottom_offset,
                                   force_phys_addrs=force_phys_addrs,
                                   var_sub_fn=var_sub_fn, offsetre=offsetre, name=name,
                                   resetre=resetre, widthre=widthre, default_width=default_width,
                                   offset=name_offset, namere=namere, addrre=addrre)

        results = {k: [] for k in list(t.col_info.iterkeys())}

        nrows = 0
        for o in page:
            if (o.bbox[3] >= tablestart) or (tableend and (o.bbox[1] < tableend)):
                continue
            nrows += cls.count_rows(t, o, name_offset)
        if verbose:
            print "counted %d rows" % nrows
        for o in page:
            if (o.bbox[3] >= tablestart) or (tableend and (o.bbox[1] < tableend)):
                continue
            cls.try_add_field(t, o, results, nrows, name_offset)
        counts = {k: len(v) for (k, v) in results.iteritems()}
        n = counts[TITable.NAME]
        for (k, l) in counts.iteritems():
            if not n == l:
                print "Parsing failed. Unequal counts for %s" % counts
                return {}
        #if verbose:
        #    print "results initially " % [(k, len(v)) for (k, v) in results.iteritems()]
        results = cls.sort_results(results)
        if verbose:
            print "results sorted  %s" % [(k, len(v)) for (k, v) in results.iteritems()]
        results = cls.filter_results(results, t, sectionname)
        if verbose:
            print "results filtered %s" % [(k, len(v)) for (k, v) in results.iteritems()]
        return results

    def usb_tll_fn(cls, aname, i, results, t):
        newresults = {}
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]
        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base'] if offset else ""

        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        variablefield = False

        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16)

        rows = []
        index = 0

        suffix = t.phys_addrs[aname]
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes
        name = name + '_' + suffix if suffix else name

        variablefield = any(map(lambda x: x in offset, t.var_names))

        exceptions = ["TLL_CHANNEL_CONF_i"]
        if variablefield:
            v = [x for x in t.var_names if x in offset][0]
            if name in exceptions:
                offsets = range(0, 2*0x4, 0x4)
            else:
                offsets = t.var_rules[aname][v]

            for o in offsets:
                rowname = re.sub(v, str(o), name)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % (baseaddr + o)
                c[TITable.OFFSET] = "0x%x" % (baseoffset + o) if baseoffset else ""
                rows.append(c)

        else:
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = re.sub(" ", "", addrvalue)
            c[TITable.OFFSET] = re.sub(" ", "", offset)
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def tpcc_var_sub(cls, aname, i, results, t):
        newresults = {}
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base'] if offset else ""

        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        variablefield = False

        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16)

        rows = []
        index = 0

        suffix = t.phys_addrs[aname]
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes

        variablefield = any(map(lambda x: x in name, t.var_names))
        name = name + '_' + suffix if suffix else name

        exceptions = ["TPCC_DRAEj", "TPCC_TRAEHj"]
        if variablefield:
            v = [x for x in t.var_names if x in offset][0]
            if v == 'j':
                if name in v:
                    offsets = range(0, 7*0x8, 0x8)
                else:
                    offsets = t.var_rules[aname][v]
            else:
                offsets = t.var_rules[aname][v]
            for o in offsets:
                rowname = re.sub(v, str(o), name)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % (baseaddr + o)
                c[TITable.OFFSET] = "0x%x" % (baseoffset + o) if baseoffset else ""
                rows.append(c)
        else:
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = re.sub(" ", "", addrvalue)
            c[TITable.OFFSET] = re.sub(" ", "", offset)
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def gpmc_var_sub(cls, aname, i, results, t):
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base'] if offset else ""

        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        variablefield = False

        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16)

        rows = []
        index = 0

        suffix = t.phys_addrs[aname]
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes
        name = re.sub(" where k = j -", "", name)
        variablefield = any(map(lambda x: x in name, t.var_names))
        name = name + '_' + suffix if suffix else name
        exceptions = ["GPMC_BCH_RESULT0_i", "GPMC_BCH_RESULT1_i", "GPMC_BCH_RESULT2_i",
                      "GPMC_BCH_RESULT3_i"]
        if variablefield:
            v = [x for x in t.var_names if x in name][0]
            if name in exceptions:
                    offsets = range(0x10, 10*0x10, 0x10)
            else:
                offsets = t.var_rules[aname][v]

            for o in offsets:
                rowname = re.sub(v, str(o), name)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % (baseaddr + o)
                c[TITable.OFFSET] = "0x%x" % (baseoffset + o) if baseoffset else ""
                rows.append(c)

        else:
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = re.sub(" ", "", addrvalue)
            c[TITable.OFFSET] = re.sub(" ", "", offset)
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def sdrc_var_sub(cls, aname, i, results, t):
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base'] if offset else ""


        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        variablefield = False

        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16)

        rows = []
        index = 0

        suffix = t.phys_addrs[aname]
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes

        variablefield = any(map(lambda x: x in name, t.var_names))
        name = name + '_' + suffix if suffix else name
        exceptions = ["SDRC_ACTIM_CTRLA_p", "SDRC_ACTIM_CTRLB_p"]

        if variablefield:
            v = [x for x in t.var_names if x in name][0]
            if name in exceptions:
                    offsets = [0, 0x28]
            else:
                offsets = t.var_rules[aname][v]

            for o in offsets:
                rowname = re.sub(v, str(o), name)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % (baseaddr + o)
                c[TITable.OFFSET] = "0x%x" % (baseoffset + o) if baseoffset else ""
                rows.append(c)

        else:
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = re.sub(" ", "", addrvalue)
            c[TITable.OFFSET] = re.sub(" ", "", offset)
            rows.append(c)

        for r in rows:
            add_row(**r)
        return newresults

    def isp_var_sub(cls, aname, i, results, t):
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]
        variablefields = [f for f in t._names.iterkeys() if f not in commonfields]
        resultvariablefields = [f for f in results.iterkeys() if f not in commonfields]
        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base'] if offset else ""

        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        variablefield = False

        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16)

        rows = []
        index = 0

        suffix = t.phys_addrs[aname]
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes

        variablefield = any(map(lambda x: x in name, t.var_names))

        if variablefield:
            v = 'x'
            xoffsets = t.var_rules[aname]['x']
            offsets = []
            if 'y' in name:
                yoffsets = t.var_rules[aname]['y']
                for x in xoffsets:
                    for y in yoffsets:
                        offsets.append((y, x + y))
            else:
                offsets = xoffsets

            for o in offsets:
                if isinstance(o, tuple):
                    y = o[0]
                    o = o[1]
                    rowname = re.sub('y', str(y), name)
                rowname = re.sub(v, str(o), name)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % (baseaddr + o)
                c[TITable.OFFSET] = "0x%x" % (baseoffset + o) if baseoffset else ""
                rows.append(c)

        else:
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = re.sub(" ", "", addrvalue)
            c[TITable.OFFSET] = re.sub(" ", "", offset)
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def dcvid_var_sub(cls, aname, i, results, t):
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        rows = []
        index = 0
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes
        if 'VID1' in t.name:
            n = 1
        else:
            n = 2

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}
        addrvalue = results[aname][i]
        offset = results[TITable.OFFSET][i]
        baseoffset = regexps[TITable.OFFSET].match(offset).groupdict()['base']
        baseaddr = regexps[aname].match(addrvalue).groupdict()['base']
        baseaddr = long(re.sub("\s", "", baseaddr), 16)
        baseoffset = long(re.sub("\s", "", baseoffset), 16)
        rg = None
        v = None

        def find_var(var):
            vals = [name, addrvalue, offset]
            return any(map(lambda x: var in x, vals))

        if find_var('i'):
            rg = range(0, 7*0x8, 0x8)
            v = 'i'
        elif find_var('j'):
            if n == 1:
                if name == u'DISPC_VIDn_FIR_COEFF_Vi':
                    rg = range(0, 1*0x4, 0x4)
                else:
                    rg = range(0, 1*0x8, 0x8)
            else:
                rg = range(0, 1*0x4, 0x4)
            v = 'j'

        elif find_var('l'):
            rg = range(0, 1*0x4, 0x4)
            v = 'l'

        if rg:
            for j in rg:
                offset = baseoffset + ((n - 1) * 0x90) + (j * 0x4)
                addr = baseaddr + (j * 0x4)
                rowname = re.sub(v, str(j), name)
                rowname = re.sub('n', str(n), rowname)
                c = dict(common)
                c[TITable.NAME] = rowname
                c[TITable.ADDRESS] = "0x%x" % addr
                c[TITable.OFFSET] = "0x%x" % offset
                rows.append(c)

        else:
            rowname = re.sub('n', str(n), name)
            c = dict(common)
            c[TITable.NAME] = rowname
            c[TITable.ADDRESS] = "0x%x" % baseaddr
            c[TITable.OFFSET] = "0x%x" % baseoffset
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def mem_wkup_sub(cls, aname, i, results, t):
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        rows = []
        index = 0
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes
        baseaddr = 0x48002600

        for off in range(0, 31*(0x9fc-0x600), 32):
            addr = baseaddr + off
            c = dict(common)
            c[TITable.NAME] = name
            c[TITable.ADDRESS] = "0x%x" % addr
            c[TITable.OFFSET] = "0x%x" % off
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    def camera_isp22_sub(cls, aname, i, results, t):
        newresults = {}
        newresults = {f: [] for f in t._names.iterkeys()}

        commonfields = [TITable.TYPE, TITable.RESET, TITable.WIDTH]

        regexps = {aname: t._regexps[TITable.ADDRESS],
                   TITable.OFFSET: t._regexps[TITable.OFFSET]}

        def add_row(address='',  offset='', typ='', name='', width='', reset=''):
            for f in t._names.iterkeys():
                newresults[f].append(locals()[f])

        rows = []
        index = 0
        common = {f: results[f][i] for f in commonfields}

        name = re.sub("\([d]+\)", "", results[TITable.NAME][i])  # remove any footnotes
        if i == 0:
            if '2A' in aname:
                baseaddr = 0x480BD9C0
            else:
                baseaddr = 0x480BDDC0
        else:
            if '2A' in aname:
                baseaddr = 0x480BD9C4
            else:
                baseaddr = 0x480BDDC4

        for off in range(0, 0x8*7, 0x8):
            addr = baseaddr + off
            c = dict(common)
            suffix = "CODEH" if i == 0 else "CODEV"
            c[TITable.NAME] = name + '_' + suffix
            c[TITable.ADDRESS] = "0x%x" % addr
            c[TITable.OFFSET] = "0x%x" % off
            rows.append(c)

        for r in rows:
            add_row(**r)

        return newresults

    @classmethod
    def count_rows(cls, t, o, offset=0):
        info = t.col_info[TITable.NAME]
        count = 0
        if isinstance(o, layout.LTTextBox):
            for i in o:
                count += cls.count_rows(t, i, offset)
            return count
        elif isinstance(o, layout.LTTextLine):
            text = cls.get_entry_text(o)
            if abs(info.l - (o.bbox[0] + offset)) < 0.2:
                if info.regex.match(text):
                    return 1
        return 0

    parse_exceptions = [
        ("iVLCD Register Mapping Summary", {
            'var_rules': {u'Physical Address':
                          {'i': range(0, 1*0x4, 0x4),
                           'j': range(0, 5*0x4, 0x4)}}}),
        ("ISP_CBUFF Register Summary", {
            'offsetre': "^(?P<base>(0x[0-9A-F]{4} [0-9A-F]{4}))(( \+ \(x \* 0x4\))( \+)?)?$",
            'var_sub_fn': isp_var_sub,
            'var_rules': {u'Physical Address':
                          {'x': range(0, 1*0x4, 0x4),
                           'y': range(0, 15*0x4, 0x4)}}}),
        ("ISP_CCP2 Register Summary",
         {'name_offset': (106.5 - 57),
          'var_rules': {u'Physical Address':
                        {'x': range(0, 0x30*3, 0x30)}}}),
        ("iME Register Mapping Summary",
         {'var_rules': {u'Physical Address':
                        {'i': range(0, 255*0x8, 0x8),
                         'j': range(0, 15*0x4, 0x4),
                         'k': range(0, 63*0x4, 0x4),
                         'l': range(0, 3*0x4, 0x4),
                         'm': range(0, 7*0x4, 0x4)}}}),
        ("ISP_HIST Register Summary",
         {'var_rules': {u'Physical Address':
                        {'n': range(0, 3*0x8, 0x8)}}}),
        ("iLF Register Mapping Summary",
         {'var_rules': {u'Physical Address':
                        {'i': range(0, 0x8*127, 0x8),
                         'j': range(0, 7*0x4, 0x4),
                         'k': range(0, 23*0x4, 0x4),
                         'l': range(0, 35*0x4, 0x4),
                         'm': range(0, 39*0x4, 0x4),
                         'n': range(0, 0x4*3, 0x4)}}}),
        ("RFBI Register Mapping Summary",
         {'var_rules':
          {u'Physical Address': {'i': range(0, 1*0x18, 0x18)}}}),
        ("SDRC Register Summary",
         {'var_sub_fn': sdrc_var_sub,
          'phys_addrs': {u'Physical Address': ''},
          'var_rules':
          {u'Physical Address':
           {'p': [0, 0x30]}}}),
        ("GPMC Registers Mapping Summary",
         {
             'namere': '^GPMC_[A-Z0-9a-z=()_ -]+$',
             'var_sub_fn': gpmc_var_sub,
             'var_rules': {
                u'Physical Address': {'i': range(0, 7*0x30, 0x30),
                                      'j': range(1, 10),
                                      'k': range(0, 0x4*7, 0x4)}}}),

        ("SDMA Register Summary",
         {'phys_addrs': {u'SDMA': ''},
          'var_rules': {u'SDMA':
                        {'i': range(0, 31*0x60, 0x60),
                         'j': range(0, 3*0x4, 0x4)}}}),
        ("MPU INTC Register Summary",
         {'phys_addrs': {u'MPU INTC': ''},
          'var_rules': {u'MPU INTC':
                        {'n': range(0, 2*0x20, 0x20),
                         'm': range(0, 95*0x4, 0x4)}}}),
        ("XMC Register Summary", {
            'typre': '^(RW|R|W|RW \(RO if i = 0...15\))$',
            'var_rules': {u'Physical Address':
                          {'i': range(0, 255*0x4, 0x4),
                           'j': range(0, 64*0x4, 0x4),
                           'k': range(0, 31*0x4, 0x4)}}}),
        ("VIDEOSYSC Register Mapping Summary", {
            'typre': '^(RW|R|W|w/1toSet)$'}),
        ("ISP_PREVIEW Register Summary", {
            'var_rules': {u'Physical Address':
                          {'x': range(0, 0x4*3, 0x4)}}}),
        ("Global_Reg_PRM Register Summary", {
            'offsetre': "^(?P<base>0 ?x[0-9A-F]{4} [0-9A-F]{4})$"}),
        ("ISP_CCDC Register Summary",
         {'var_rules': {u'Physical Address':
                        {'x': range(0, 0x4*7, 0x4)}}}),
        ("TPCC Register Summary", {
            'var_sub_fn': tpcc_var_sub,
            'var_rules': {u'Physical Address':
                          {'i': range(0, 63*0x4, 0x4),
                           'j': range(0, 7*0x4, 0x4),  # or 0x8
                           'k': range(0, 15*0x4, 0x4),
                           'l': range(0, 1*0x4, 0x4),
                           'm': range(0, 127*0x20, 0x20),
                           'n': range(0, 7*0x200, 0x200)}}}),
        ("PADCONFS Register Summary",
         {'namere': '^(CONTROL|RESERVED)[_A-Z0-9]*$'}),
        ("GENERAL_WKUP Register Summary",
         {'namere': '^(CONTROL|RESERVED)[_A-Z0-9]*$'}),
        ("GENERAL Register Summary",
         {'namere': '^(CONTROL|RESERVED)[_A-Z0-9]*$'}),
        ("PADCONFS_WKUP Register Summary",
         {'namere': '^(WKUP|RESERVED)[_A-Z0-9]*$'}),
        ("Video Encoder Register Mapping Summary",
         {"namere": "^VENC_[A-Z0-9_]+$"}),
        ("DSI Protocol Engine Register Mapping Summary",
         {'namere': "^DSI_[A-Z0-9n_]+$",
          'var_rules':
          {u'Physical Address':
           {'n': range(0, 3*0x20, 0x20)}}}),

        ("DSI PLL Controller Register Mapping Summary",
         {'namere': "^DSI_[A-Z0-9n_]+$",
          'var_rules': {u'Physical Address':
                        {'n': range(0, 3*0x20, 0x20)}}}),
        ('CAMERA_ISP _CSIPHY',
         {'phys_addrs': {
             'PHY2 L3': 'PHY2',
             'PHY1 L3': 'PHY1'
         }}),
        ('CAMERA_ISP_CSI2_REGS1 Register Summary', {'namere': "^CSI2_[A-Z_0-9x]+$",
                                                    'var_rules': {u'2A_REGS1 L3':
                                                                  {'x': range(0, 7*0x20, 0x20)},
                                                                  u'2C_REGS1 L3':
                                                                  {'x': range(0, 7*0x20, 0x20)}},
                                                    'phys_addrs': {u'2A_REGS1 L3': u'2A',
                                                                   u'2C_REGS1 L3': u'2C'}}),
        ('Display Controller Register Mapping Summary', {
                                                         'var_rules': {u'Physical Address':
                                                                       {'m': range(0, 1*0x4, 0x4),
                                                                        'j': range(0, 1*0x4, 0x4),
                                                                        'k': range(0, 2*0x4,
                                                                                   0x4)}}}),
        ("L4 AP Register Summary",
         {'addrre': '((?P<base>0x[0-9A-F]{4} [0-9A-F] ?[0-9A-F]{3})(\s*\+\s*\(\s*0x[0-9A-F]{2}\s*\[ijk]*\s*\))?)|(N/A)',
          'var_rules':  {u"EMU_AP": {'i': range(0, 0x8*2, 0x8),
                                     'k': range(0, 0x8*5, 0x8),
                                     'l': range(0, 0x8*25, 0x8)},
                         u'CORE_AP': {'i': range(0, 0x8*5, 0x8),
                                      'k': range(0, 0x8*7, 0x8),
                                      'l': range(0, 0x8*99, 0x8)},
                         u'PER_AP': {'i': range(0, 0x8*4, 0x8),
                                     'k': range(0, 0x8*7, 0x8),
                                     'l': range(0, 0x8*42, 0x8)},
                         u'WKUP_AP': {'i': range(0, 0x8*1, 0x8),
                                      'l': range(0, 0x8*18, 0x8)}}}),
        ("TPTC0 and TPTC1 Register Summary", {
            'namere': "^TPTCj_[A-Z0-9i_]+$",
            'var_rules':  {u"TPTC0":
                           {'i': range(0, 3*0x40, 0x40)},
                           u'TPTC1':
                           {'i': range(0, 1*0x40, 0x40)}},
            'phys_addrs': {u"TPTC0": u"0",
                           u"TPTC1": u"1"}}),
        ("IC Register Summary", {
            'var_rules':  {u"Physical Address":
                           {'i': range(0, 3*0x4, 0x4),
                            'j': range(0, 3*0x4, 0x4)}}}),
        ("EHCI Registers Mapping Summary",
         {'var_rules': {u"Physical Address":
                        {'l': range(0, 2*0x4, 0x4)}}}),

        ("USBTLL Registers Mapping Summary",
         {'var_sub_fn': usb_tll_fn,
          'typre': '^RW|R|W|Reserved$',
          'var_rules':  {u"Physical Address":
                         {'i': range(0, 2*0x100, 0x100)}}}),
        ('Protection Mechanism Common Register Summary',
         {'namere': "^L3_PM_[A-Z0-9ik_() 12]+$",
          'var_rules':
          {'PM_MAD2D': {'i': range(0, 7*0x20, 0x20),
                        'k': range(1*0x20, 8*0x20, 0x20)},
           'PM_IVA2.2': {'i': range(0, 3*0x20, 0x20),
                         'k': range(1*0x20, 4*0x20, 0x20)},
           'PM_OCM_RAM': {'i': range(0, 7*0x20, 0x20),
                          'k': range(1*0x20, 8*0x20, 0x20)},
           'PM_OCM_ROM': {'i': range(0, 1*0x20, 0x20),
                          'k': [0x20]},
           'PM_RT': {'i': [0, 0x20],
                     'k': [0x20]},
           'PM_GPMC': {'i': range(0, 7*0x20, 0x20),
                       'k': range(1*0x20, 8*0x20, 0x20)}}}),
        ("McSPI Register Summary",
         {'default_width': 32,
          'name': u'Register',
          'namere': "^MCSPI_[A-Z_0-9x]+$",
          'phys_addrs': {u'MCSPI1 Instance': u'1',
                         u'MCSPI2 Instance': u'2',
                         u'MCSPI3 Instance': u'3',
                         u'MCSPI4 Instance': u'4'},
          'var_rules': {u'MCSPI1 Instance':
                        {'x': range(0, 0x14*3, 0x14)},
                        u'MCSPI2 Instance':
                        {'x': range(0, 0x14*1, 0x14)},
                        u'MCSPI3 Instance':
                        {'x': range(0, 0x14*1, 0x14)},
                        u'MCSPI4 Instance':
                        {'x': range(0, 0*0x14, 0x14)}}}),

        ('MLB Register Summary',
         {'var_rules': {u'Physical Address':
                        {'m': range(0, 0x4*1, 0x4),
                         'u': range(0, 0x4*1, 0x4)}}}),
        ("Display Controller VID1 Register Mapping",
         {'var_sub_fn': dcvid_var_sub,
          'name': u'Register Name (n=1 for VID1)',
          'namere': '^DISPC_[A-Z0-9_nijl]+$',
          'addrre': '^(?P<base>0x[0-9A-F]{4} [0-9A-F]{4})(\s*\+\s*\(\s*[nijl](\s*\*\s*0x[0-9A-F]{2,3}\)?)?)?$',
          'offsetre': '^(?P<base>0x[0-9A-F]{1,4})\s*\+\s*\(\(n-1\)\s*\*\s*0x[0-9A-F]{2}\)(\s*\+(\s\(\s*[ijl]\s\*\s0x[0-90-F]{2})?)?$'}),
        ("Display Controller VID2 Register Mapping",
         {'var_sub_fn': dcvid_var_sub,
          'name': u'Register Name (n=2 for VID2)',
          'namere': '^DISPC_[A-Z0-9_nijl]+$',
          'addrre': '^(?P<base>0x[0-9A-F]{4} [0-9A-F]{4})(\s*\+\s*\(\s*[nijl](\s*\*\s*0x[0-9A-F]{2,3}\)?)?)?$',
          'offsetre': '^(?P<base>0x[0-9A-F]{1,4})\s*\+\s*\(\(n-1\)\s*\*\s*0x[0-9A-F]{2}\)(\s*\+(\s\(\s*[ijl]\s\*\s0x[0-90-F]{2})?)?$'}),
        ("GPTIMER9 to GPTIMER11 Register Summary",
         {'phys_addrs': {u'(GPTIMER9)': 'GPTIMER9',
                         u'(GPTIMER10)': 'GPTIMER10',
                         u'(GPTIMER11)': 'GPTIMER11'},
          'field_center_offset': {TITable.OFFSET: -122.738}}),
        ("UART/IrDA/CIR Register Summary Part 1",
         {"force_phys_addrs": ["UART1", "UART2", "UART3"]}),

        ("32-kHz Sync Timer",
         {'namere': "^REG_[A-Z0-9n_]+$"}),
        ("SGX Registers Mapping Summary",
         {'namere': "^OCP_[A-Z0-9n_]+$"}),
        ("SMS Register Summary",
         {'namere': "^SMS_[A-Z0-9ijkmn_]+$",
          'var_rules':
          {u'Physical Address':
           {
            'i': range(0, 7*0x20, 0x20),
            'k': range(0, 6*0x20, 0x20),
            'm': range(0, 2*0x4, 0x4),
            'j': range(0, 8),
            'n': range(0, 10*0x10, 0x10)
           }}}),
        ("MEM_WKUP Register Summary",
         {'var_sub_fn': mem_wkup_sub,
          'namere': '^CONTROL_SAVE_REST$',
          'addrre': '^0x4800 2600 - 0x4800$',
          'offsetre': '^0x0600 - 0x09FC'}),
        ('CAMERA_ISP_CSI2_REGS2 Registers Mapping Summary', {'namere': "^CSI2_[A-Z_0-9x]+$",
                                                             'var_sub_fn': camera_isp22_sub,
                                                             'offsetre': "^0x8\)$",
                                                             'addrre': "^0x8\)$",
                                                             'phys_addrs': {u'2A_REGS2 L3': u'2A2',
                                                                            u'2C_REGS2 L3': u'2C2'}}),
        ('Display Controller Register Mapping Summary',
         {
          'var_rules':  {u"Physical Address":
                         {'m': range(0, 1*0x4, 0x4),
                          'k': range(0, 2*0x4, 0x4),
                          'j': range(0, 1*0x4, 0x4)}}}),

        ("MMC/SD/SDIO Register Summary", {
            'label_bottom_offset': 15,
            'phys_addrs': {'MMCHS1': '1',
                           'MMCHS2': '2',
                           'MMCHS3': '3'}}),

        ]

    @classmethod
    def get_entry_text(cls, obj):
        t = cls.get_text(obj)
        return  re.sub("\(\d+\)", "", t).strip() # remove footnote

    @classmethod
    def search_text_box(cls, box, text):
        if isinstance(box, layout.LTText):
            if cls.get_text(box).strip() == cls.normalize_text(text).strip():
                return box
        if isinstance(box, layout.LTContainer):
            for l in box:
                if isinstance(l, layout.LTChar):
                    continue
                elif isinstance(l, layout.LTText):
                    s = cls.get_text(l).strip()
                    if s == text:
                        return l
                    else:
                        return cls.search_text_box(l, text)
                elif isinstance(l, layout.LTContainer):
                    return cls.search_text_box(l, text)
        return None

    @classmethod
    def found_table(cls, box, text):
        text = cls.normalize_text(text)
        if isinstance(box, layout.LTText):
            if cls.get_text(box).strip().endswith(text):
                return box
        if isinstance(box, layout.LTContainer):
            for l in box:
                if isinstance(l, layout.LTChar):
                    continue
                elif isinstance(l, layout.LTText):
                    s = cls.get_text(l).strip()
                    if s == text:
                        return l
                    else:
                        return cls.found_table(l, text)
                elif isinstance(l, layout.LTContainer):
                    return cls.found_table(l, text)
        return None

    @classmethod
    def sort_results(cls, results):
        newresults = {}
        for (k, v) in results.iteritems():

            newresults[k] = [cls.get_entry_text(i) for i in sorted(v,
                                                                   reverse=True,
                                                                   key=lambda o: o.bbox[1])]
        return newresults

    @classmethod
    def filter_results(cls, results, t,  name):
        newresults = {k: [] for k in t._names.iterkeys()}
        nrows = len(results[TITable.NAME])
        nonaddrs = [TITable.NAME, TITable.TYPE, TITable.WIDTH, TITable.OFFSET, TITable.RESET]
        for i in nonaddrs:
            if i not in results.iterkeys():
                if i == TITable.WIDTH and t.default_width:
                    results[i] = nrows * str(t.default_width)
                results[i] = nrows * ['']

        addrfields = t.phys_addrs
        varnames = t.var_names
        for i in addrfields:
            if len(results[i]) == 0:
                del results[i]

        for (a, v) in addrfields.iteritems():
            for i in range(0, nrows):
                try:
                    addr = results[a][i]
                except IndexError:
                    print "Failed to filter table %s" % name
                    return {}
                if addr in t.noaddrs:
                    continue
                if t.var_sub_fn:
                    rs = t.var_sub_fn(cls, a, i, results, t)
                else:
                    rs = t.default_sub_fn(a, i, results)
                for (k, q) in rs.iteritems():
                    newresults[k] += q

        return newresults

    @classmethod
    def parse_register_table(cls, interp, dev, pages, pageno, tablename, output, verbose):
        end = 0
        alt = None
        args = {}
        results = {}

        for (n, exception) in cls.parse_exceptions:
            if n == tablename:
                args = exception
                break
        if not args: # try for less exact match
            for (n, exception) in cls.parse_exceptions:
                if n in tablename:
                    args = exception
                    break
        # check to see if table is continued onto next page
        more = True
        while more:
            more_results = {}
            page = pages[pageno]
            interp.process_page(page)
            l = dev.get_result()
            if isinstance(l, layout.LTContainer):
                table = None
                for o in l:
                    if isinstance(o, layout.LTText) and cls.found_table(o, tablename):
                        table = o
                        break
                if table is None:
                    break
                tableend = None
                for o in sorted(l._objs, reverse=True, key=lambda o: o.bbox[1]):
                    if isinstance(o, layout.LTText):
                        t = cls.get_text(o).strip()
                        if (o.bbox[3] < table.bbox[3]) and \
                           ((t.startswith(u"Table")
                             and (not t.endswith(tablename))) or
                            (t.startswith(u"Section"))):
                            if tableend:
                                if tableend.bbox[3] < o.bbox[3]:
                                    tableend = o
                            else:
                                tableend = o

                if table is None:
                    more = False
                    break

                if args:
                    more_results = cls.parse_register_table_from_page(interp, dev, l,
                                                                      tablename,
                                                                      table, tableend,
                                                                      verbose, **args)
                else:
                    more_results = cls.parse_register_table_from_page(interp, dev, l,
                                                                      tablename,
                                                                      table, tableend,
                                                                      verbose, namere=None,
                                                                      field_center_offset={},
                                                                      label_bottom_offset=0,
                                                                      name=u'Register Name',
                                                                      widthre=None, skip=False,
                                                                      offsetre=None,resetre=None,
                                                                      typre=None,
                                                                      default_width=32,
                                                                      addrre=None,
                                                                      var_sub_fn=None,
                                                                      force_phys_addrs=[],
                                                                      phys_addrs={}, var_rules={})

            if len(more_results) == 0:
                more = False
            for (k, v) in more_results.iteritems():
                if k in results:
                    results[k] = results[k] + v
                else:
                    results[k] = v
            if ("(continued)" not in tablename) and more:
                tablename = tablename + " (continued)"
            pageno += 1
        if verbose:
            print [(k, len(v)) for (k, v) in results.iteritems()]
        return results




    @classmethod
    def process_table_index(cls, parser, document, rsrcmgr, params, device, interp,
                            pages, page, pageno, output, verbose, tables):
        interp.process_page(page)
        l = device.get_result()
        index = 0
        for o in sorted(l._objs, reverse=True, key=lambda o: o.bbox[1]):
            if isinstance(o, layout.LTText):
                if cls.get_text(o).strip() == u"List of Tables":
                    font = cls.lookup_font(o)
                    if font == 'Helvetica-Oblique':
                        res = cls.iterate_table_list(parser, document, device, interp,
                                                     pages, l, pageno, output, verbose, index, tables)
                        break
            index += 1


    @classmethod
    def iterate_table_list(cls, parser, document, device, interp,
                           pages, page, pageno, output, verbose, index, tables):
        done = False
        while not done:
            objs = page._objs
            objs.sort(reverse=True, key=lambda o: o.bbox[1])
            for i in range(index, len(page._objs)):
                o = objs[i]

                if isinstance(o, layout.LTText):
                    if u"Register Call Summary for Register DAPC_EPM2..." in cls.get_text(o):
                        done = True
                    else:
                        cls.iter_text_lines(interp, device, pages,
                                            o, output, verbose, tables)
                if done:
                    break

            if not done:
                pageno = pageno + 1
                index = 0
                interp.process_page(pages[pageno])
                page = device.get_result()
        print "sucessfully parsed %s of %s tables (ish)" % (TIPDF.successful, TIPDF.ntables)

    @classmethod
    def is_reg_table_label(cls, text):
        s = ["Register Summary", "Registers Mapping Summary", "Register Mapping Summary"]
        if ".." in text:
            return any(map(lambda x: re.search("%s\s*..+" % x, text), s))
        else:
            return any(map(lambda x: text.endswith(x), s))

    @classmethod
    def iter_text_lines(cls, interp, dev, pages, box, output, verbose, tables):
        res = None

        objs = box._objs
        objs.sort(reverse=True, key=lambda o: o.bbox[1])

        titles = []
        alltext = ""
        for l in objs:
            if isinstance(l, layout.LTText):
                text = cls.get_text(l)
                alltext += "%s\n" % text

        splittext = re.split("(\d+-\d+.\s[A-Za-z0-9 _-]+.+ ?\d+)\s*", alltext)
        for text in [f for f in splittext if cls.is_reg_table_label(f)]:
            text = re.sub("\n", " ", text)
            ts = filter(lambda x: len(x) > 0, text.split(".."))
            name = ts[0].strip()
            title = "Table " + name
            pageno = long(re.sub("[ .]*", "", ts[1].strip())) - 1
            if tables:
                matches = filter(lambda t: t in name, tables)
                if not matches:
                    continue
            if verbose:
                print "-----------------------"
                print "Parsing '%s' '%d'" % (title, pageno)
            TIPDF.ntables += 1
            res = cls.parse_register_table(interp, dev, pages,
                                           pageno, title, output, verbose)
            if res:
                TIPDF.successful += 1
                cls.table_to_csv(title, res, output, verbose)

        return res

    @classmethod
    def process_pdf(cls, pdf, output, verbose=False, tables=None):
        parser = pdfparser.PDFParser(pdf)
        document = pdfdocument.PDFDocument(parser)
        rsrcmgr = pdfinterp.PDFResourceManager(caching=True)

        params = layout.LAParams(line_margin=0.4, word_margin=0.1, char_margin=2,
                                 line_overlap=0.4, boxes_flow=0.5)
        device = converter.PDFPageAggregator(rsrcmgr, laparams=params)

        interpreter = pdfinterp.PDFPageInterpreter(rsrcmgr, device)
        outlines = document.get_outlines()
        registers = {}
        pages = dict((pageno, page) for (pageno, page)
                     in enumerate(pdfpage.PDFPage.create_pages(document)))
        for xref in document.xrefs:
            for oid in xref.get_objids():
                obj = document.getobj(oid)
                if type(obj) == dict:
                    if"Title" in obj.iterkeys() and "List of Tables" in obj['Title']:
                        pageoid = obj['A'].resolve()['D'][0].objid
                        (pageno, page) = [(pn, p) for (pn, p) in pages.iteritems()
                                          if p.pageid == pageoid][0]
                        cls.process_table_index(parser, document, rsrcmgr, params, device,
                                                interpreter, pages, page, pageno, output,
                                                verbose, tables)
                        return

    csv_field_order = [TITable.NAME, TITable.TYPE, TITable.RESET,
                       TITable.WIDTH, TITable.OFFSET, TITable.ADDRESS, "table"]

    @classmethod
    def table_to_csv(cls, table, results, output, verbose):
        writer = csv.DictWriter(output, fieldnames=TIPDF.csv_field_order)
        if verbose:
            print "Saving %s" % table
        if verbose and not output == sys.stdout:
            printer = csv.DictWriter(sys.stdout, fieldnames=TIPDF.csv_field_order)
        else:
            printer = None
        nregs = len(results[TITable.NAME])
        for i in range(0, nregs):
            row = {k: v[i] for (k, v) in results.iteritems()}
            row['table'] = table
            writer.writerow(row)
            if printer:
                printer.writerow(row)


def parsecsv(f):
    csvfile = open(f, 'r')
    fields = TIPDF.csv_field_order
    return (csvfile, csv.DictReader(csvfile, fields))


def checkcsv(f):
    (fd, reader) = parsecsv(f)
    addrdict = {}

    CORE_TA_DUPS = [
        "L4_TA_COMPONENT_L",
        "L4_TA_COMPONENT_H",
        "L4_TA_CORE_L",
        "L4_TA_CORE_H",
        "L4_TA_AGENT_CONTROL_L",
        "L4_TA_AGENT_CONTROL_H",
        "L4_TA_AGENT_STATUS_L",
        "L4_TA_AGENT_STATUS_H"]
    core_ta_addr_pairs = [("CORE_TA_USB_TLL", "CORE_TA_USB_HS_TLL"),
                          ("CORE_TA_USB_HS_HOST", "CORE_TA_USB_HS_Host"),
                          ("CORE_TA_MCBSP1", "CORE_TA_MCBSP5"),
                          ("CORE_TA_MCSPI1", "CORE_TA_MCBSP5"),
                          ("CORE_TA_MCBSP5", "CORE_TA_MCSPI1"),
                          ("CORE_TA_MCSPI1", "CORE_TA_MCSPI5"),
                          ("CORE_TA_GPTIMER11", "CORE_TA_MCSPI5"),
                          ("CORE_TA_MCBSP1", "CORE_TA_MMAILBOX"),
                          ("CORE_TA_MCBSP5", "CORE_TA_MMAILBOX")]

    known_dups = []
    for l in CORE_TA_DUPS:
        for p in core_ta_addr_pairs:
            known_dups.append(set([l+"_"+p[0], l+"_"+p[1]]))

    def mapreg(l):
        return map(lambda x: x + "_REG", l)

    UART_ADDRS = ["UART1", "UART2", "UART3", "UART4"]
    UART_DUPS = [["DLL_REG", "RHR_REG", "THR_REG"],
                 ["DLH_REG", "IER_REG"],
                 ["IIR_REG", "FCR_REG", "EFR_REG"],
                 ["XON1_ADDR1_REG", "MCR_REG"],
                 ["LSR_REG", "XON2_ADDR2_REG"],
                 ["TCR_REG", "XOFF1_REG", "MSR_REG"],
                 ["SPR_REG", "TLR_REG", "XOFF2_REG"],
                 mapreg(["SFLSR", "TXFLL"]),
                 mapreg(["RESUME", "TXFLH"]),
                 mapreg(["SFREGL", "RXFLL"]),
                 mapreg(["SFREGH", "RXFLH"]),
                 mapreg(["UASR", "BLR"])]
    for addr in UART_ADDRS:
        for r in UART_DUPS:
            dupset = set()
            for i in r:
                dupset.add("%s_%s" % (i, addr))
            known_dups.append(dupset)

        other_dups = [set(["TPCC_QDMAQNUM", "TPCC_QUETCMAP"]),
                      set(["TPCC_DRAEH4", "TPCC_DRAE8"]),
                      set(["TPCC_DRAEH0", "TPCC_DRAE4"]),
                      set(["TPCC_DRAEH20", "TPCC_DRAE24"]),
                      set(["TPCC_DRAEH12", "TPCC_DRAE16"]),
                      set(["INSNREG05_ULPI", "INSNREG05_UTMI"]),
                      set(["TPCC_DRAEH16", "TPCC_DRAE20"]),
                      set(["L4_AP_COMPONENT_L_WKUP_AP", "L$_AP_COMPONENT_H_WKUP_AP"]),
        ]
    known_dups += other_dups
    print known_dups

    for entry in reader:
        addr = entry[TITable.ADDRESS]
        if addr in addrdict:
            addrdict[addr].append(entry)
        else:
            addrdict[addr] = [entry]

    for (a, vals) in addrdict.iteritems():
        if len(vals) > 1:
            names = set([v['name'] for v in vals])
            if not any(map(lambda x: names <= x, known_dups)):
                print "duplicates in  %s -- %s" % (a, vals)
    fd.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser("ti pdf documentation parser")
    cmds = parser.add_mutually_exclusive_group()
    cmds.add_argument('-p', '--parsepdf', action="store_true")
    cmds.add_argument('-c', '--check', action="store", default=None)
    parser.add_argument('-i', '--pdf', action='store', type=argparse.FileType('rb'),
                        help='pdf to parse')
    parser.add_argument('-o', '--output', action='store', type=argparse.FileType('w'),
                        help='file to store results, stdout is default', default=sys.stdout)
    parser.add_argument('-t', '--table', action='append', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='increate verbosity')

    args = parser.parse_args()
    if not args.check:
        TIPDF.process_pdf(args.pdf, args.output, args.verbose,
                          [TIPDF.normalize_text(t).strip() for t in args.table]
                          if args.table else None)
        args.output.close()
    else:
        checkcsv(args.check)


def parse(pdf, output, verbose=False):
    out = open(output, "w")
    p = open(pdf, "rb")
    TIPDF.process_pdf(p, out, verbose)
    if out.tell() < 1:
        out.close()
        return False
    out.close()
    return True
