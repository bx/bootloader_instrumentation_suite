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

import random
import argparse
import string
import os
import sys
import re
import functools
import shutil
import glob
import atexit
#path = os.path.dirname(os.path.realpath(__file__))
#sys.path.append(os.path.join(path, ".."))
#sys.path.append(path)
#version = os.path.join(path, ".python-version")
#if os.path.exists(version):
#    with open(version, 'r') as pv:
#        penv = pv.read().strip()
#        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
patches = {}

from doit.action import CmdAction
from config import Main
import labeltool
import database
import doit_manager
import db_info
import pure_utils
import tempfile

cc = None
elf = None


class PreprocessorDirective():
    ppdformat = re.compile("# ([0-9]+) \"([a-zA-Z0-9_\/\-\.]+)\"(?:([1-4\s]*))$")

    @classmethod
    def _match(cls, line):
        line = line.rstrip()
        return cls.ppdformat.match(line)

    @classmethod
    def is_preprocessor_directive(cls, line):
        return cls._match(line) is not None

    def _relative_path(self, path):
        return re.sub(r'^./', '', path)

    def _process_line(self, line):
        match = PreprocessorDirective._match(line)
        self.lineno = int(match.group(1))
        self.path = self._relative_path(match.group(2))
        self.flags = []
        try:
            flags = match.group(3).strip().split()
        except IndexError:
            flags = []
        if len(flags) > 0:
            self.flags = [int(f) for f in flags]

    def __init__(self, line, ilineno=-1):
        if not PreprocessorDirective.is_preprocessor_directive(line):
            raise Exception("'%s' is not a preprossor directive" % line)
        self._process_line(line)
        self.s = line.rstrip()
        self.pp_lineno = ilineno

    def __repr__(self):
        return self.s


class PreprocessedFileProcessor():
    def __init__(self, preprocessed_file, stage):
        self.stage = stage
        global cc
        global elf
        self.cc = cc
        self.elf = elf
        self.path = preprocessed_file
        self.included_files = set()
        self.directives = []
        self._data_loc = -1
        self._get_preprocessing_directives()

    def get_related_preprocessing_directives(self, label):
        return [d for d in self.directives if label.filename == d.path]

    def _get_preprocessing_directives(self):
        ppf = open(self.path, "r")
        lineno = 0
        for l in ppf.readlines():
            lineno += 1
            if PreprocessorDirective.is_preprocessor_directive(l):
                d = PreprocessorDirective(l, lineno)
                self.directives.append(d)
                self.included_files.add(d.path)
        ppf.close()

    def get_closest_directive(self, cfilename, clineno):
        closest_directive = None

        filtered_directives = [dt for dt in self.directives
                               if (dt.path == cfilename) and (dt.lineno <= clineno) and
                               (3 not in dt.flags)]

        last = filtered_directives[-1]
        # find first occurance of directives matching last directive's lineno
        for d in filtered_directives:
            if d.lineno >= last.lineno:
                closest_directive = d
        return closest_directive

    def _get_label_reference_lineno(self, l):
        return 0

    def match_paren(self, line, index):
        orig = line
        line = line[index:]
        last_index = 0
        if line[0] != "(":  # find opening paren
            last_index = line.index("(")
            line = line[last_index:]

        level = 0
        for c in line:
            if c == "(":
                level += 1
            elif c == ")":
                level -= 1
                if (level == 0) and (last_index > 0):
                    return last_index
            last_index += 1
        raise Exception("no matching paren %s" % orig)

    def typeof_patch(self, line, i=0):
        if "(typeof" in line or ("( typeof" in line):
            a = re.match("\s*char\s+__([a-zA-Z0-9_-]+)\[([\w\s()>+*~/&-]+)\];", line)
            if a:
                name = a.group(1)
                l = "char __%s[%s];" % (name, a.group(2))
                n = "; ([\s\w]+)\s+\*%s" % name
                a = re.search(n, line)
                if a:
                    l = "%s %s *%s = __%s;\n" % (l, a.group(1), name, name)
                    return l
        return line

    def global_patch(self, line):
        line = self.typeof_patch(line)
        return self.gd_patch(line)

    def _do_fix_file(self, fixinfo, outpath):
        outf = open(outpath, "w")
        inf = open(self.path, "r")
        fixinfo.sort(key=lambda (lineno, fixfunction, label):
                     lineno)
        curlineno = 0
        for l in inf.readlines():
            curlineno += 1
            if len(fixinfo) > 0:
                (fixline, fixfun, label) = fixinfo[0]
                if fixline == curlineno:
                    l = fixfun(l, label)
                    l = self.global_patch(l)
                    fixinfo.pop(0)
            l = self.global_patch(l)
            outf.write(l)
        inf.close()
        outf.close()

    def void_int_patch(self, line, label):
        out = re.sub("void", "int", line, count=1)
        return out

    def i2cadapstart_patch(self, line, label):
        return ' extern struct i2c_adapter _u_boot_list_2_i2c_2_omap24_0; struct i2c_adapter *i2c_adap_p = &_u_boot_list_2_i2c_2_omap24_0; index=0; return i2c_adap_p;\n'

    def i2cadapmax_patch(self, line, label):
        line = line.strip()
        # if max is declared as an int, keep the declaration
        i = line.find("int")
        dec = ""
        if (i > -1) and (i < line.find("max")):
            dec = "int"
        return ' %s max = 2;\n' % dec

    def i2cinitbus_patch(self, line, label):
        return ' if (bus_no >= 2)\n'

    def _no_patch(self, line, label):
        return line

    def val_patch(self, line, label):
        return "  val = 0xF0000000 &  0x40200800;\n"

    def malloc_zero_patch(self, line, label):
        pat = "[-a-zA-Z0-9_\s()]+"
        args = re.compile("\s*do { size_t mzsz = \((%s)\);" % (pat))
        res = args.match(line)
        if not res:
            return line
        new = "memset(mem, 0, %s);\n" % (res.group(1))
        return new

    def cpuid_patch(self, line, label):
        return "\tcpuid = 0x3;\n"

    def addr_patch(self, line, label):
        cchars = "[a-zA-Z0-9_\-\* ]+"
        tn = "(%s)%s\s*(?:=[\s\S]+)?;" % (cchars, label.name)
        try:
            last = line.index("=")
        except:
            last = line.index(";")

        value = pure_utils.get_symbol_location(self.elf, label.name, self.stage)
        l = "%s = 0x%x;\n" % (line[:last], value)
        return l

    def gd_patch(self, line):
        # addr of gd should be the top of .data section, so lookup where this section is
        line = line.strip()
        global patches
        if self._data_loc == -1:
            (self._data_loc, end) = pure_utils.get_section_location(self.elf, ".data")
        if ("frama_c_tweaks" not in self.path) and \
           (re.match('register volatile gd_t \*gd asm \("r9"\);', line) is not None):
            n = patches.get("gd", 0)
            patches["gd"] = n + 1
            return "gd_t *gd; //@ volatile gd reads read_gd writes write_gd;\n"
        elif ("frama_c_tweaks" in self.path) and \
             (re.match('register volatile gd_t \*gd asm \("r9"\);', line) is not None):
            n = patches.get("gd", 0)
            patches["gd"] = n + 1
            return "gd_t *gd = 0x%x; //@ volatile gd reads read_gd writes write_gd;\n" % \
                self._data_loc
        else:
            return line+"\n"

    def noreturn_patch(self, line, label):
        return re.sub("return", "", line)

    def interval_patch(self, line, label):
        return "val = get_base;\n"

    def re_patch(self, line, label):
        return re.sub(label.name, "", line)

    def delete_line(self, line, label):
        return ";\n"

    def returnzero_patch(self, line, label):
        return "return 0;\n"

    def memalign_patch(self, line, label):
        return "return malloc(bytes);\n"

    def chunksz_patch(self, line, lab):
        return "csz = sz+sizeof(size_t);\n"

    def sdr_cs_offset_patch(self, line, label):
        return "return 0;\n"

    def patch(self, labels, outfile):
        # write patch to outfile
        fixinfo = []
        for l in labels:
            # get line number in c file label is referring to
            clineno = l.lineno + 1

            # get coressponding directive in preprocessed file
            d = self.get_closest_directive(l.filename, clineno)

            # calculate line number offset

            pplineno = (clineno - d.lineno) + d.pp_lineno + 1
            # check if the code corresponding to that directive is included in the .i file
            # (it may have been #ifdef'd out) -- if there is a directive relating to the same
            # c file with a clineno > label.lineno but it is located before the caluclated pplineno
            related_directives = [dt for dt in self.directives
                                  if (dt.path == l.filename) and
                                  (dt.lineno > clineno) and
                                  (dt.pp_lineno <= pplineno)]
            if len(related_directives) > 0:
                # then don't lookup fixfn, nothingto fix
                print "cline line %d not included in %s, skipping patching label" \
                    % (clineno, l.filename)
                continue
            name_to_patch_functions = {
                "sdr_cs_offset": self.sdr_cs_offset_patch,
                "i2c_adap_start": self.i2cadapstart_patch,
                "i2c_init_bus": self.i2cinitbus_patch,
                "i2c_adap_max": self.i2cadapmax_patch,
                "cpuid": self.cpuid_patch,
                "delete_line": self.delete_line,
                "noreturn": self.noreturn_patch,
                "return_zero": self.returnzero_patch,
                "val": self.val_patch,
                "void_to_int": self.void_int_patch,
            }
            fixfn = self._no_patch
            if l.value == "ADDR_PATCH":
                fixfn = self.addr_patch
            if l.value == "INTERVAL_PATCH":
                fixfn = self.interval_patch
            if l.value == "SUBPATCH":
                fixfn = self.re_patch
            elif l.name.lower() in name_to_patch_functions.keys():
                global patches
                n = patches.get(l.name.lower(), 0)
                patches[l.name.lower()] = n + 1
                fixfn = name_to_patch_functions[l.name.lower()]
            fixinfo.append((pplineno, fixfn, l))
        self._do_fix_file(fixinfo, outfile)


class PreprocessedFiles():
    # collect *.i files in u-boot
    # for each *.i, execute frama-c

    # the ordering of these are important, if there are multiple
    # definitions of the same function it will use the first
    # regardless of any "weak" lables

    files = ["frama_c_tweaks.i", "boot.i", "serial_ns16550.i", "omap24xx_i2c.i",
             "ns16550.i", "omap_hsmmc.i", "beagle.i", "omap_gpio.i",
             "boot-common.i",
             "spl_fat.i",  # comment this file out to speed things up for testing
             "mmc.i",  # this one as well
             "twl4030.i", "crc32.i",
             "syslib.i", "sys_info.i",
             "mem-common.i", "board_init.i",
             # "am35x.i", "omap2430.i", some extern structs for the spl are defined here, but are not used by the spl
             "board.i",
             "clock.i", "spl_id_nand.i", "timer.i",
             "sdrc.i", "spl.i", "fat_write.i", "i2c_core.i",
             "spl_mmc.i",  "utils.i", "part_dos.i",
             "part_efi.i",
             "part.i", "dlmalloc.i", "vsprintf.i", "stdio.i",
             "string.i",  "ctype.i", "malloc_simple.i",
             "env_common.i", "serial.i", "div64.i",
             "panic.i", "hang.i",
             "console.i"]
    quick_files = ["frama_c_tweaks.i", "boot.i", "serial_ns16550.i", "omap24xx_i2c.i",
                   "ns16550.i", "omap_hsmmc.i", "beagle.i", "omap_gpio.i",
                   "boot-common.i",
                   "spl_fat.i",  # comment this file out to speed things up for testing
                   "mmc.i",  # this one as well
                   "twl4030.i", "crc32.i",
                   "mem-common.i", "board_init.i",
                   "clock.i", "spl_id_nand.i", "timer.i",
                   "sdrc.i", "spl.i", "fat_write.i", "i2c_core.i",
                   "spl_mmc.i",  "utils.i", "part_dos.i",
                   "part.i", "dlmalloc.i", "vsprintf.i", "stdio.i",
                   "string.i",  "ctype.i", "malloc_simple.i",
                   "env_common.i", "serial.i", "div64.i",
                   "console.i"]

    @classmethod
    def instances(cls, stage, root=Main.get_target_cfg().software_cfg.root, quick=False):
        files = cls.files
        fs = map(lambda s: os.path.join(root, s), files)
        fs = map(functools.partial(PreprocessedFileInstance, stage=stage), fs)
        return fs


class FramaCDstPluginManager():
    def __init__(self, stage, labels=None, execute=False, quick=False, more=False, verbose=False,
                 patchdest=Main.get_target_cfg().software_cfg.root,
                 patch_symlink='', backupdir='',
                 calltracefile=None, tee=None):
        self.frama_c = "frama-c"
        self.quick = quick
        self.execute = execute
        self.stage = stage
        self.verbose = verbose
        self.patchdest = patchdest
        if len(patch_symlink) == 0:
            patch_symlink = tempfile.mkdtemp()
            os.system("rm -r %s" % patch_symlink)
            if self.execute:
                atexit.register(lambda: os.system("rm %s" % patch_symlink))
        self.shortdest = patch_symlink
        self.backupdir = backupdir
        self.tee = tee
        self.path = os.path.dirname(os.path.realpath(__file__))
        verbosen = 3 if verbose else 3
#                            "-slevel-function printf:0  "\
#                            "-slevel-function puts:0 "\
#                            "-val-use-spec do_fat_read_at "\

        self.frama_c_args = " -load-script %s -machdep arm " \
                            "-load-script %s " \
                            "-load-script %s " \
                            "-no-initialized-padding-locals " \
                            "-absolute-valid-range 0x10000000-0xffffffff "\
                            "-val-builtin malloc:Frama_C_malloc_fresh,free:Frama_C_free "\
                            "-val-initialization-padding-globals=no  "\
                            "-constfold "\
                            "-kernel-verbose %d -value-verbose %d  "\
                            "-big-ints-hex 0  "\
                            "-slevel 1 "\
                            "-val -then -dst -then -call" % (os.path.join(self.path,
                                                                          "machdep_arm.ml"),
                                                             os.path.join(self.path,
                                                                          "dest_analysis.ml"),
                                                             os.path.join(self.path,
                                                                          "call_analysis.ml"),
                                                             verbosen, verbosen)
        if not self.quick:
            self.frama_c_args = "%s -slevel-function memset:1048576 " \
                                "-slevel-function malloc:2000  "\
                                "-slevel-function calloc:2000 " % self.frama_c_args
        if calltracefile:
            self.frama_c_args += " -call-output %s " % calltracefile
        self.frama_c_main_arg = " -main"
        self.more = more
        if more:
            self.frama_c_args += " -dst-more"
        self.results = {}
        if labels is None:
            self.labels = [l for l in Main.get_config('labels')[labeltool.FramaCLabel]
                           if (l.stagename == self.stage.stagename)]
        else:
            self.labels = [l for l in labels[labeltool.FramaCLabel]
                           if l.stagename == self.stage.stagename]
        self.entrypoints = []
        self.preprocessed_files = []

    def import_results_from_file(self, path):
        f = open(path, 'r')
        self.process_framac_results(f.readlines())
        f.close()

    def process_framac_results(self, lines):
        for line in lines:
            if database.WriteDstResult.is_dst_result(line):
                if self.verbose:
                    print line
                d = database.WriteDstResult.from_line(line, self.stage)
                vals = list(d.values)
                if d.key() in self.results:
                    self.results[d.key()].add_value(vals.pop())
                else:
                    self.results[d.key()] = d

    def get_cmd_results(self, cmd):
        print "running cmd %s" % cmd

        self.process_framac_results(Main.shell.run_multiline_cmd(cmd, teefile=self.tee))
        print "frama c result %s" % Main.shell.get_last_cmd_return_value()

    def execute_frama_c(self, main):
        if not os.path.islink(self.shortdest):
        #    print self.shortdest
        #    print self.patchdest
            os.symlink(self.patchdest, self.shortdest)
        if len(self.backupdir) > 0:
            if not os.path.isdir(self.backupdir):
                os.mkdirs(self.backupdir)

            [shutil.copyfile(f.pp_path,
                             os.path.join(self.backupdir,
                                          os.path.basename(f.pp_path)))
             for f in self.preprocessed_files]

        cmd = "%s %s %s %s %s" % (self.frama_c, self.paths(),
                                  self.frama_c_main_arg, main, self.frama_c_args)
        if self.execute:
            if self.verbose:
                print cmd
            self.get_cmd_results(cmd)
        else:
            print cmd
            print "\n"

    def _get_file_labels(self, f):
        labels = []
        for l in self.labels:
            if l.filename == f:
                labels.append(l)
        return labels

    def process_preprocessed_file(self, f):
        patch_labels = []
        included_files = f.processor.included_files
        for i in included_files:
            # get labels for this file
            labels = self._get_file_labels(i)
            entryvalue = "ENTRYPOINT"
            for l in labels:
                if l.value == entryvalue:
                    if l not in self.entrypoints:
                        self.entrypoints.append(l)
                elif l.is_patch_value():
                    patch_labels.append(l)
        outfile = "%s-%s.i" % (f.pp_path[:-2], "patched")
        f.patch(patch_labels, outfile)
        f.pp_path = outfile
        self.preprocessed_files.append(f)

    def update_db(self):
        if self.results:
            db_info.create(self.stage, "tracedb")
            results = [r for r in self.results.itervalues()]
            print "have %d results" % len(results)
            print "adding dst entries"
            for r in results:
                db_info.get(self.stage).add_range_dsts_entry(r)
            print '-----------'
            # db_info.get(self.stage).print_range_dsts_info()
            db_info.get(self.stage).consolidate_trace_write_table()
            db_info.get(self.stage).flush_tracedb()

    def print_results(self):
        print self.results

    def entrypoint_label_to_function_name(self, l):
        full_path = os.path.join(l.path, l.filename)
        # get lineno label is referring to
        lineno = labeltool.SrcLabelTool.get_next_non_label(l.lineno, full_path)

        # read line from file
        cmd = "sed '%dq;d' %s" % (lineno, full_path)

        line = Main.shell.run_cmd(cmd)
        fnre = re.compile("\s+([a-zA-Z\-_0-9]+)\(")
        res = fnre.search(line)
        if res is not None:
            return res.group(1)
        raise Exception("cannot determine entrypoint from label %s" % (l, line))

    def process_entrypoints(self):
        for e in self.entrypoints:
            # invoke frama_c pluging with -main set to entrypoint
            main_name = self.entrypoint_label_to_function_name(e)
            self.execute_frama_c(main_name)

    def paths(self):
        return " ".join([re.sub(self.patchdest,
                                self.shortdest, p.pp_path) for p in self.preprocessed_files])

    def process_dsts(self, files):
        for i in files:
            self.process_preprocessed_file(i)
        self.process_entrypoints()


class PreprocessedFileInstance():

    def _assert_exists(self, path):
        if not os.path.exists(path):
            raise Exception("file %s does not exist" % path)

    def __init__(self, path, stage):
        self._assert_exists(path)
        self.pp_path = path
        self.c_file = PreprocessedFileInstance.c_file_lookup(self.pp_path)
        self.processor = PreprocessedFileProcessor(self.pp_path, stage)

    @classmethod
    def c_file_lookup(cls, base_file):
        f = open(base_file, "r")
        l = f.readline()
        # should be on first line
        pd = PreprocessorDirective(l, 1)
        f.close()
        return pd.path

    def patch(self, patch_labels, outname):
        self.base_file = outname
        self.processor.patch(patch_labels, outname)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("FramaC analysis")
    parser.add_argument('-s', '--stage', action='store',
                        default='spl')
    parser.add_argument('-T', '--test_id', action='store')
    parser.add_argument('-I', '--instance_id', action='store')
    parser.add_argument('-k', '--keep_temp', action='store_true')
    parser.add_argument('-P', '--policy_id', action='store')
    parser.add_argument('-e', '--execute', action='store_true',
                        default=False, help="Execute frama c & collect"
                        " results (Default is to just print commands)")
    parser.add_argument('-q', '--quick', action='store_true',
                        default=False, help="Quick mode for testing,"
                        " don't run full analysis.")
    parser.add_argument('-m', '--more', action='store_true',
                        default=False, help="Tell frama c analysis to print more")
    parser.add_argument('-u', '--update', action='store_true',
                        default=False, help="Update static analysis database"
                        " for given stage (will set execute to true if it is also true)")
    parser.add_argument('-c', '--calltracefile', action='store', default=None)
    parser.add_argument('-b', '--patchbkup', action='store', default='')
    parser.add_argument('-t', '--tee', action='store', default='')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-i', '--input', action='store', default="",
                        help="Instead of running frama_c populate static analysis"
                        " database directly from this file (which should contain frama_c "
                        "dst plugin output)")
    parser.add_argument('-S', '--standalone', action='store_true', default=False,
                        help="Don't pull configuration data from instrumentation suite")

    args = parser.parse_args()

    s = Main.stage_from_name(args.stage)
    if s is None:
        raise Exception("no such stage named %s" % args.stage)
    if not args.standalone:
        d = doit_manager.TaskManager([], [], False, [args.stage],
                                     {args.stage: args.policy_id},
                                     False, {}, args.test_id, False, [],
                                     hook=True, rm_dir=not args.keep_temp)
        labels = Main.get_config("labels")
        l = labels
        root = Main.get_config("temp_target_src_dir")
        builder = d.build([Main.get_target_cfg().software], False)[0]
        origdir = os.getcwd()
        os.chdir(root)

        for t in builder.tasks:
            for action in t.list_tasks()['actions']:
                if isinstance(action, CmdAction):
                    do = action.expand_action()
                    os.system(do)
        os.chdir(origdir)
        elf = Main.get_config("stage_elf", s)

    else:
        root = Main.get_target_cfg().software.root
        labels = labeltool.get_all_labels(root)
        s.post_build_setup()
        elf = s.elf

    if args.update:
        args.execute = True

    if args.patchbkup and not os.path.isdir(args.patchbkup):
        os.makedirs(args.patchbkup)

    fc = FramaCDstPluginManager(s, labels=labels, execute=args.execute,
                                quick=args.quick, more=args.more,
                                verbose=args.verbose,
                                patchdest=root,
                                backupdir=args.patchbkup,
                                calltracefile=args.calltracefile, tee=args.tee)
    if len(args.input) > 0:
        fc.import_results_from_file(args.input)
        fc.update_db()
    else:
        files = PreprocessedFiles.instances(s, root, args.quick)
        fc.process_dsts(files)
        #for p in sorted(list(patches.keys())):
        #    print "%s: %s" % (p, patches[p])
        if args.update or args.execute:
            if args.update:
                fc.update_db()
            else:
                fc.print_results()
