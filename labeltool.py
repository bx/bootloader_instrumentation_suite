#!/usr/bin/python2
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

# inserted in Makefile.build
# labeltool := __file__/labeltool.py
# cs_list = "cs_files"
# $(obj)/%.o: $(src)/%.c $(recordmcount_source) FORCE
# 	$(call cmd,force_checksrc)
# 	$(call if_changed_rule,cc_o_c)
# 	 $(labeltool) -s $(prefix) -c $(src)/$*.c -p ${PWD} -o ${cs_list}

# $(obj)/%.o: $(src)/%.S FORCE
# 	$(call if_changed_dep,as_o_S)
# 	@{$(labeltool) -s $(prefix) -S $(src)/$*.S -p ${PWD} -o ${cs_list}}

import fnmatch
import argparse
import sys
import re
import testsuite_utils as utils
import os
from sortedcontainers import SortedList
from config import Main
label_classes = {}


class LabelRegistrar(type):
    def __new__(cls, clsname, bases, attrs):
        newcls = type.__new__(cls, clsname, bases, attrs)
        global label_classes
        # register subclasses of Label
        if (clsname is not "Label") and (clsname not in label_classes.keys()):
            label_classes[clsname] = newcls
        return newcls


class FileLabels():
    def __init__(self, filename, path):
        self.filename = filename
        self.path = path
        self.current_labels = SortedList(key=self._labelsortkey)
        self.updated_labels = SortedList(key=self._labelsortkey)
        self.get_labels_from_file()

        for l in self.current_labels:
            if not ((l.filename == self.filename) and (l.path == self.path)):
                raise Exception("Found label with incorrect filename/path")

    def get_labels_from_file(self):
        self.updated_labels = SortedList(key=self._labelsortkey)
        self.current_labels = SortedList(key=self._labelsortkey)
        self.current_labels.update(
            SrcLabelTool._get_labels(self.filename, self.path, "", "", True, None)
        )
        self.updated_labels.update(self.current_labels)

    def insert_label(self, label):
        if not ((label.filename == self.filename) and (label.path == self.path)):
            raise Exception("Trying to insert label with incorrect filename/path")

        if label in self.current_labels:
            return
        # update the lineno in the following labels
        if label in self.updated_labels:
            self.updated_labels.remove(label)
            self.updated_labels.add(label)
        i = self.updated_labels.bisect(label)
        for l in self.updated_labels[i:]:
            l.lineno += 1
        self.updated_labels.add(label)

    def remove_label(self, label):
        i = self.updated_labels.bisect(label)
        # update the lineno in the following labels
        for l in self.updated_labels[i:]:
            l.lineno -= 1
        self.updated_labels.remove(label)

    def insert_label_list(self, labels):
        sortedlabels = SortedList(key=self._revlabelsortkey)
        sortedlabels.update(labels)
        for i in sortedlabels:
            self.insert_label(i)

    def _labelsortkey(self, l):
        return l.lineno

    def _revlabelsortkey(self, l):
        return -l.lineno

    def update_file(self):
        fullpath = os.path.join(self.path, self.filename)
        f = open(fullpath, "r")
        lines = f.readlines()
        f.close()
        nolabels = [l for l in lines if not SrcLabelTool.is_any_label(l)]
        for l in self.updated_labels:
            nolabels.insert(l.lineno-1, l.filerepr())

        # rewrite file
        f = open(fullpath, "w")
        for line in nolabels:
            f.write(line)
        f.close()
        self.get_labels_from_file()


class Label():
    reqs = {}
    __metaclass__ = LabelRegistrar

    def __init__(self, filename, lineno, isasm, name, stage, value, raw, path):
        self.filename = filename
        self.lineno = lineno
        self.isasm = isasm
        self.stagename = stage
        self.value = value
        self.name = name
        self.raw = raw
        self.path = path
        self.reference_lineno = SrcLabelTool.get_next_non_label(self.lineno,
                                                                os.path.join(self.path,
                                                                             self.filename))
        self.reference_line = self._get_reference_line()

    def _get_reference_line(self):
        return utils.line2src("%s:%d" % (os.path.join(self.path, self.filename),
                                         self.reference_lineno))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        return (hash(self.filename) ^ hash(self.reference_lineno) ^
                hash(self.stagename) ^ hash(self.value) ^
                hash(self.path) ^ hash(self.__class__) ^ hash(self.reference_line))

    @classmethod
    def parse_label(cls, line):
        labelre = re.compile(cls.labelformat)
        matches = labelre.match(line)
        if matches:
            stage = matches.group(2)
            value = matches.group(3)
            name = matches.group(1)
            raw = matches.group(0)
            return (name, value, stage, raw)
        else:
            return (None, None, None, None)

    @classmethod
    def format_label(cls, ltype, values):
        if len(values) == 0:
            raise Exception("There should be at least 1 value per label type")
        s = "#define ___%s_([0-9a-zA-Z_]+)_(spl|main)_(" % ltype
        cls.ltype = ltype
        ltype = ltype
        cls.values = values
        for v in values:
            s = s + "%s|" % v
        s = s[:-1]  # cut final |
        s = s + ")"
        return s

    @classmethod
    def set_requirements(cls, reqs):
        cls.reqs = reqs

    @classmethod
    def check_requirements(cls, labellist):
        for l in labellist:
            if l in cls.reqs.keys():
                found = False
                for required_value in cls.reqs[l]:
                    if required_value in labellist:
                        found = True
                if not found:
                    return False
        return True

    def filerepr(self):
        return "#define ___%s_%s_%s_%s\n" % (self.ltype, self.name, self.stagename, self.value)

    def __repr__(self):
        return "%s:%d %s(%s) in %s" % \
            (self.filename, self.lineno, self.name, self.value, self.stagename)


class PhaseLabel(Label):
    begin = "BEGIN"
    end = "END"
    values = [begin, end]
    labelformat = Label.format_label("PHASE", values)
    labelrequirements = {
        begin: end,
    }
    Label.set_requirements(labelrequirements)


class StageinfoLabel(Label):
    values = ["EXIT"]
    labelformat = Label.format_label("STAGEINFO", values)
    labelrequirements = {
    }
    Label.set_requirements(labelrequirements)


class LongwriteLabel(Label):
    bk = "BREAK"
    write = "WRITE"
    ct = "CONT"
    labelrequirements = {
        bk: [ct],
    }
    values = [bk, write, ct]
    labelformat = Label.format_label("LONGWRITE", values)
    ltype = "LONGWRITE"
    Label.set_requirements(labelrequirements)


class RelocLabel(Label):
    [b, r, d, s, e] = ["BEGIN", "READY", "DST", "CPYSTART", "CPYEND"]
    values = [b, r, d, s, e]
    labelrequirements = {
        b: [r],
    }
    labelformat = Label.format_label("RELOC", values)
    ltype = "RELOC"
    Label.set_requirements(labelrequirements)


class SkipLabel(Label):
    [n, s, e, f] = ["NEXT", "START", "END", "FUNC"]
    values = [n, s, e, f]
    labelrequirements = {
        s: [e],
    }
    labelformat = Label.format_label("SKIP", values)
    ltype = "SKIP"
    Label.set_requirements(labelrequirements)


class RegOpLabel(Label):
    values = ["WRITE", "ADDRESS", "STATIC_WRITE"]
    labelformat = Label.format_label("REG", values)
    ltype = "REG"
    labelrequirements = {
    }
    Label.set_requirements(labelrequirements)


class FramaCLabel(Label):
    values = ["ENTRYPOINT", "SAMPLE_ENTRYPOINT", "PATCH",
              "ADDR_PATCH", "INTERVAL_PATCH", "SUBPATCH"]
    labelformat = Label.format_label("FRAMAC", values)
    ltype = "FRAMAC"
    labelrequirements = {
    }
    Label.set_requirements(labelrequirements)

    def is_patch_value(self):
        return (self.value == "PATCH") or (self.value == "ADDR_PATCH") \
            or (self.value == "SUBPATCH")


class SrcLabelTool():
    def __init__(self, srcfile, isasm, stage, path=""):
        self.srcfile = srcfile
        self.isasm = isasm
        self.stagename = stage
        if len(path) < 1:
            self.path = Main.get_bootloader_root()
        else:
            self.path = path
        self.lineno = -1

    @classmethod
    def label_search(cls, label=None, root=""):
        labels = []
        if len(root) == 0:
            root = Main.get_bootloader_root()
        for (dirpath, dirs, files) in os.walk(root):
            for filename in fnmatch.filter(files, "*.[chsS]"):
                fullpath = os.path.join(dirpath, filename)
                filepath = fullpath[len(root)+1:]
                if os.path.isfile(fullpath):  # just in case
                    filelabels = cls._get_labels(filepath, root, name="",
                                                 stage="", checkreqs=False, ltype=label)
                if len(filelabels) > 0:
                    labels.extend(filelabels)
        return labels

    @classmethod
    def get_next_non_label(cls, lineno, srcfile):
        with open(srcfile, 'r') as src:
            lines = src.readlines()[lineno:]
            i = lineno
            for l in lines:
                i = i + 1
                if (len(l.strip()) > 0) and not cls.is_any_label(l):
                    return i

    @classmethod
    def get_prev_non_label(cls, lineno, srcfile):
        with open(srcfile, 'r') as src:
            lines = src.readlines()[:(lineno-1)][::-1]
            i = lineno
            for l in lines:
                i = i - 1
                if (len(l.strip()) > 1) and not cls.is_any_label(l):
                    return i

    @classmethod
    def lineno_is_a_label(cls, lineno, srcfile):
        with open(srcfile, 'r') as src:
            return Label.is_any_label(src.readlines()[lineno])

    def get_labels(self, labelcls, name="", stage="", checkreqs=False, alltypes=False):
        if alltypes:
            ltype = None
        else:
            ltype = labelcls
        return SrcLabelTool._get_labels(self.srcfile, self.path, name, stage, checkreqs, ltype)

    @classmethod
    def _get_labels(cls, srcfile, path, name,
                    stage, checkreqs=False, ltype=None):
        resultclass = ltype
        with open(os.path.join(path, srcfile), 'r') as src:
            labels = []
            alllabels = []
            i = 0
            isasm = False
            if srcfile[-3:] == ".S":
                isasm = True
            for l in src.readlines():
                i = i + 1
                resultclass = None
                if ltype is not None:
                    resultclass = SrcLabelTool.is_a_label(ltype, l)
                else:
                    resultclass = cls.is_any_label(l)
                if resultclass is not None:
                    (lname, lvalue, lstage, raw) = resultclass.parse_label(l)
                    newlabel = resultclass(srcfile, i, isasm, lname, lstage, lvalue, raw, path)
                    alllabels.append(newlabel)
                    append = True
                    if len(name) > 0 and (not name == newlabel.name):
                        append = False
                    if (len(stage) > 0) and (not stage == newlabel.stagename):
                        append = False
                    if append:
                        labels.append(newlabel)
        if checkreqs and ltype:
            if not ltype.check_requirements(alllabels):
                raise Exception("Labels don't meet requirements in %s (%s)" %
                                (path, str([str(l) for l in alllabels])))
        return labels

    @classmethod
    def is_a_label(cls, labelcls, line):
        labelre = re.compile(labelcls.labelformat)
        matches = labelre.match(line)
        if matches is not None:
            return labelcls
        else:
            return None

    @classmethod
    def is_any_label(cls, line):
        global label_classes
        for c in label_classes.itervalues():
            labelre = re.compile(c.labelformat)
            matches = labelre.match(line)
            if matches:
                return c
        return None

    def new_label(self, labelclass, name, value, raw):
        return labelclass(self.srcfile, self.lineno, self.isasm, name,
                          self.stagename, raw, self.path)

    def search_file(self):
        self.lineno = 0
        global label_classes
        labels = {}
        for label_name in label_classes.iterkeys():
            labels[label_name] = []
        with open(os.path.join(self.path, self.srcfile), 'r') as f:
            for line in f.readlines():
                self.lineno += 1

                for (label_name, label_class) in label_classes.iteritems():
                    (name, value, stage, raw) = label_class.parse_label(line)
                    if name and (stage == self.stagename):
                        label_list = labels[label_name]
                        label_list.append(self.new_label(label_class, name, value, raw))
                        labels[label_name] = label_list
                        continue
        return labels

    def get_labels_of_type(self, clsname):
        if self.labels == {}:
            self.search_file()
        return self.labels[clsname]

    def get_phase_labels(self):
        return self.get_labels_of_type(PhaseLabel)

    def get_longwrite_labels(self):
        return self.get_labels_of_type(LongwriteLabel)


all_labels_root = ""
all_labels = {}


def get_all_labels(root):
    global all_labels
    global all_labels_root
    if not all_labels_root == root:
        all_labels_root = root
        labels = SrcLabelTool.label_search(None, root)
        for l in labels:
            name = l.__class__
            if name in all_labels.keys():
                all_labels[name].append(l)
            else:
                all_labels[name] = [l]
    return all_labels


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sourcegroup = parser.add_mutually_exclusive_group(required=True)
    sourcegroup.add_argument('-S', '--Ssrc', action="store",
                             help='name of assembly file to process')
    sourcegroup.add_argument('-c', '--csrc', action="store",
                             help='name of c source file to process')

    parser.add_argument('-o', '--phaseoutputfile', type=argparse.FileType('a'), default=sys.stdout)
    parser.add_argument('-l', '--longwriteoutputfile', type=argparse.FileType('a'),
                        default=sys.stdout)
    parser.add_argument('-L', '--printlongwrites', action="store_true", default=False,
                        help='print longwrite labels')
    parser.add_argument('-P', '--printphases', action="store_false", default=True,
                        help='print phase labels')
    parser.add_argument('-s', '--stage', action="store", choices=['spl', '.'],
                        default='spl')
    parser.add_argument('-p', '--srcpath', action="store", default=Main.get_bootloader_root())
    sourcegroup.add_argument('--summarize', action="store", default="all",
                             help="print out information on label type for source tree")
    args = parser.parse_args()

    if len(args.summarize) > 0:
        label = args.summarize
        if (not (label == "all")) and (label not in label_classes.keys()):
            print "label (%s) is not a valid label" % label
            sys.exit(1)
        label_class = None
        if not label == "all":
            label_class = label_classes[label]
        labels = SrcLabelTool.label_search(label_class, args.srcpath)
        label_by_file = {}
        for label in labels:
            if label.filename not in label_by_file.keys():
                label_by_file[label.filename] = []
            label_by_file[label.filename].append(label)

        for (k, v) in label_by_file.iteritems():
            print "--v---%s--v---" % k
            v.sort(key=lambda l: l.lineno)
            for label in v:
                print label
        sys.exit(0)
    if args.stage == ".":
        args.stage = "main"

    asm = False
    srcfile = ""
    if args.Ssrc:
        asm = True
        srcfile = args.Ssrc
    else:
        srcfile = args.csrc

    s = SrcLabelTool(srcfile, asm, args.stage, args.srcpath)

    if args.printphases:
        labels = s.get_phase_labels()

        for l in labels:
            args.phaseoutputfile.write(str(l))
            args.phaseoutputfile.write("\n")

    if args.printlongwrites:
        labels = s.get_longwrite_labels()

        for l in labels:
            args.longwriteoutputfile.write(str(l))
            args.longwriteoutputfile.write("\n")

    args.longwriteoutputfile.close()
    args.phaseoutputfile.close()
