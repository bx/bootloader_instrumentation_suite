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
path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(path, ".."))
sys.path.append(path)
version = os.path.join(path, ".python-version")
if os.path.exists(version):
    with open(version, 'r') as pv:
        penv = pv.read().strip()
        sys.path.append(os.path.join(os.path.expanduser("~"), ".pyenv/versions", penv, "lib/python2.7/site-packages"))
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
        if i > 10:
            raise Exception("too much recursion %s, %d times" % (line, i))
        if "(typeof" in line or ("( typeof" in line):
            if "(typeof" in line:
                index = line.index("(typeof")
            else:
                index = line.index("( typeof")
            lastindex = self.match_paren(line, index)
            out = line[:index] + line[(index+lastindex+1):]
            global patches
            n = patches.get("typeof", 0)
            patches["typeof"] = n + 1
            return self.typeof_patch(out, i+1)
        else:
            return line

    def writel_patch(self, line, label):
        stripline = line.strip()
        whitespace = line[0:len(stripline)]
        chars = "[a-zA-Z0-9 \*_\-&\.<>\?,\(\)\/\%\+~\^\[\]\|]+"
        restr = "^writel\(\s*(%s)\s*,\s*(%s)\s*\);" % (chars, chars)
        res = re.compile(restr).match(stripline)
        dst = res.group(2)
        val = res.group(1)
        new = "%s *(%s) = %s\n" % (whitespace, dst, val)
        return new

    def global_patch(self, line):
        line = self.typeof_patch(line)
        return self.gd_patch(line)

    def _do_fix_file(self, fixinfo, outpath):
        outf = open(outpath, "w")
        inf = open(self.path, "r")
        fixinfo.sort(key=lambda (lineno, fixfunction, label):
                     lineno)
        # print fixinfo
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

    def cast_ulong_patch(self, line, label):
        return "uint us = (ulong) s;\n"

    def compare_s_patch(self, line, label):
        return "if ((us & (sizeof(*sl) - 1)) == 0) {\n"

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

    def unalignedle32_patch(self, line, label):
        return re.sub("get_unaligned_le32", "", line)

    def alignbuffer_patch(self, line, label):
        namechars = "[\(\)_\->a-zA-Z0-9 \*]+"
        exp = "char __([a-zA-Z0-9\-_]+)\[%s\(([a-zA-Z\->_0-9]+)\) " \
              "\* sizeof\(([\(\)_\->a-zA-Z0-9 \*]+)\)\) - 1" \
              % (namechars)
        # (group(1)) * sizeof(group(3)) + 63 (over estimate)
        bufferre = re.compile(exp)
        line = line.strip()
        res = bufferre.match(line)
        new_line = "%s %s[(%s * sizeof(%s)) + 63];\n" % (res.group(3),
                                                         res.group(1),
                                                         res.group(2),
                                                         res.group(3))
        return new_line

    def alignbuffer_malloc_patch(self, line, label):
        namechars = "[\(\)_\->a-zA-Z0-9 \*]+"
        exp = "char __([a-zA-Z0-9\-_]+)\[%s\(([a-zA-Z\->_0-9]+)\) \* " \
              "sizeof\(([\(\)_\->a-zA-Z0-9 \*]+)\)\) - 1" \
              % (namechars)
        bufferre = re.compile(exp)
        line = line.strip()
        res = bufferre.match(line)
        if not res:
            return line
        new_line = "%s %s[(%s * sizeof(%s)) + 63]  __attribute__((aligned(8)));\n" % \
                   (res.group(3), res.group(1),  res.group(2), res.group(3))
        return new_line

    def gpio_bank_patch(self,line, label):
        return "static const struct gpio_bank gpio_bank_am33xx[] __attribute__((aligned(8)))= {\n"

    def align_decl_patch(self, line, label):
        start = line.index(";")
        return line[:start] + " __attribute__((aligned(8)))" + line[start:]

    def buffer_cast_patch(self, line, label):
        return 'printf("FAT: Misaligned buffer address (%p)\\n", (void *) buffer);\n'

    def assume_aligned_patch(self, line, label):
        eq = line.index("=")
        col = line.index(";")
        line = line[:eq] + "= __builtin_assume_aligned(" + line[eq+1:col] + ", 8);\n"
        return line

    def alignbufferdos_patch(self, line, label):
        namechars = "[\(\)_\->a-zA-Z0-9 \*]+"
        exp = "char __([a-zA-Z0-9\-_]+)\[%s\(([a-zA-Z\->_0-9]+)\) \* " \
              "sizeof\(([\(\)_\->a-zA-Z0-9 \*]+)\)\) - 1" \
              % (namechars)
        # (group(1)) * sizeof(group(3)) + 63 (over estimate)
        bufferre = re.compile(exp)
        line = line.strip()
        res = bufferre.match(line)
        if not res:
            return line + "\n"
        new_line = "%s %s[(512 * sizeof(%s)) + 63];\n" % (res.group(3), res.group(1), res.group(3))
        return new_line

    def addr_patch(self, line, label):
        cchars = "[a-zA-Z0-9_\-\* ]+"
        tn = "(%s)%s\s*(?:=[\s\S]+)?;" % (cchars, label.name)
        try:
            last = line.index("=")
        except:
            last = line.index(";")

        value = pure_utils.get_symbol_location(self.cc, self.elf, label.name, self.stage)
        l = "%s = 0x%x;\n" % (line[:last], value)
        return l

    def put_dec_trunc_patch(self, line, label):
        numre = "\s*put_dec_trunc\(([-_a-zA-Z0-9]+),"
        equalre = "([-_a-zA-Z0-9]+)\s*=\s*put_dec_trunc\("
        res = re.compile(numre).search(line).group(1)
        if re.compile("\s*return").match(line):
            return "return %s;\n" % res
        else:
            lval = re.compile(equalre).search(line).group(1)
            return "%s = %s;\n" % (lval, res)

    def serial_putc(self, line, label):
        return line

    def empty_block(self, line, label):
        return "1;\n"

    def number_patch(self, line, label):
        numre = "\s*number\(([-_a-zA-Z0-9]+),"
        equalre = "([-_a-zA-Z0-9]+)\s*=\s*number\("
        res = re.compile(numre).search(line).group(1)
        if re.compile("\s*return").match(line):
            return "return %s;\n" % res
        else:
            lval = re.compile(equalre).search(line).group(1)
            return "%s = %s;\n" % (lval, res)

    def gd_pointer(self, line, label):
        return line

    def gd_patch(self, line):
        # addr of gd should be the top of .data section, so lookup where this section is
        line = line.strip()
        global patches
        if self._data_loc == -1:
            (self._data_loc, end) = pure_utils.get_section_location(self.cc, self.elf, ".data")
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

    def usbmaxp_patch(self, line, label):
        # print line
        # print label
        return "\treturn &epd->wMaxPacketSize;\n"

    def noreturn_patch(self, line, label):
        return re.sub("return", "", line)

    def gd_to_gdptr(self, line, label):
        return re.sub("gd->", "gd_ptr->", line)

    def be32_patch(self, line, label):
        i = line.index(":")
        line = line[i:]
        n = "(__be32)("
        i = line.index(n)
        line = line[i+len(n):]
        line = re.sub("\)", "", line)
        line = line.strip()
        return "if(!(%s))\n" % line

    def capacity_patch(self, line, label):
        return "capacity = 8388608;\n"

    def interval_patch(self, line, label):

        return ";\n"

    def re_patch(self, line, label):
        return re.sub(label.name, "", line)

    def bootdevice_patch(self, line, label):
        return "\treturn 0x6;\n"

    def delete_line(self, line, label):
        return ";\n"

    def delete_line_all(self, line, label):
        return "\n"

    def i2cfunc_patch(self, line, label):
        fns = {
            "init": ("omap24_i2c_init", "static void omap24_i2c_init("
                     "struct i2c_adapter *adap, int speed, int slaveadd)"),
            "probe": ("omap24_i2c_probe", "static int omap24_i2c_probe("
                      "struct i2c_adapter *adap, uchar chip)"),
            "read": ("omap24_i2c_read", "static int omap24_i2c_read("
                     "struct i2c_adapter *adap, uchar chip, uint addr, "
                     "int alen, uchar *buffer, int len)"),
            "write": ("omap24_i2c_write", "static int omap24_i2c_write("
                      "struct i2c_adapter *adap, uchar chip, uint addr, "
                      "int alen, uchar *buffer, int len)"),
            "set_bus_speed": ("omap24_i2c_setspeed", "static uint omap24_i2c_setspeed("
                              "struct i2c_adapter *adap, uint speed)"),
        }
        repl = ""
        orig = ""
        prot = ""
        for n in fns.iterkeys():
            if n in line:
                (repl, prot) = fns[n]
                orig = n
                break
            line = line.replace(orig, repl)
            line = line.replace("adap->", "", 1)
            line = line.replace("i2c_get_adapter(gd->cur_i2c_bus)->", "", 1)
        if line.strip().find("return") == 0:
            line = "{%s; %s;};\n" % (prot, line.strip())
        else:
            line = "({%s; %s;});\n" % (prot, line.strip())
        return line

    def mmcops_patch(self, line, label):
        fns = {
            "send_cmd": ("omap_hsmmc_send_cmd", "static int omap_hsmmc_send_cmd("
                         "struct mmc *mmc, struct mmc_cmd *cmd, struct mmc_data *data)"),
            "set_ios": ("omap_hsmmc_set_ios", "static void omap_hsmmc_set_ios(struct mmc *mmc)"),
            "init": ("omap_hsmmc_init_setup", "static int omap_hsmmc_init_setup(struct mmc *mmc)"),
            "getcd": ("omap_hsmmc_getcd", "static int omap_hsmmc_getcd(struct mmc *mmc)"),
            "getwp": ("omap_hsmmc_getwp", "static int omap_hsmmc_getwp(struct mmc *mmc)"),
        }
        repl = ""
        orig = ""
        prot = ""
        for n in fns.iterkeys():
            if n in line:
                (repl, prot) = fns[n]
                orig = n
                break
            line = line.replace(orig, repl)
            line = line.replace("mmc->cfg->ops->", "")
        return line

    def blkops_patch(self, line, label):
        fns = {
            "block_read": ("mmc_bread", "static ulong mmc_bread(int dev_num, "
                           "lbaint_t start, lbaint_t blkcnt, void *dst)"),
            "block_write": ("mmc_bwrite", "static inline __attribute__((always_inline)) "
                            "__attribute__((no_instrument_function)) "
                            "ulong mmc_bwrite(int dev_num, lbaint_t start, "
                            "lbaint_t blkcnt, const void *src)"),
            "block_erase": ("mmc_berase", "static inline "
                            "__attribute__((always_inline)) "
                            "__attribute__((no_instrument_function)) unsigned long "
                            "mmc_berase(int dev_num, lbaint_t start, lbaint_t blkcnt"),
        }
        repl = ""
        orig = ""
        prot = ""
        for n in fns.iterkeys():
            if n in line:
                (repl, prot) = fns[n]
                orig = n
                break
            line = line.replace(orig, repl)
            line = line.replace("mmc->block_dev.", "")
        return line

    def serial_patch(self, line, label):
        fns = {
            "start": ("eserial3_init", "static int serial3_init(void)"),
            "setbrg": ("eserial3_setbrg", "static void eserial3_setbrg(void)"),
            "getc": ("eserial3_getc", "int eserial3_getc(void)"),
            "tstc": ("eserial3_tstc", "int eserial3_tstc(void)"),
            "puts": ("eserial3_puts", "static void eserial3_puts(const char *s)"),
            "putc": ("eserial3_putc", "static void eserial3_putc(const char c)"),
        }
        repl = ""
        orig = ""
        prot = ""
        for n in fns.iterkeys():
            if n in line:
                (repl, prot) = fns[n]
                orig = n
                break
            line = line.replace(orig, repl)
            line = line.replace("get_current()->", "")
            line = line.replace("dev->", "")
        return line

    def mmcdevice_patch(self, line, label):
        # mmc struct pulled off linked list is consided
        # to be misaligned due to the pointer arithmatic
        # used in calculting the begging on the mmc struct
        # with respect to the position of its list_head link
        # field
        return line
        return "\treturn globalbxmmc;\n"

    def usebootparams_patch(self, line, label):
        line = "u32 boot_params = 0x4020E024;\n"
        return line

    def mmc_stat_read_patch(self, line, label):
        return "mmc_stat = 1;\n"

    def createmmc_patch(self, line, label):
        return line
        return "*globalmmcbxp = mmc;\n"

    def dosextended_patch(self, line, label):
        return "\t\t if (0) {\n"

    def mmmc_patch(self, line, label):
        return line
        return "\t m = *globalmmcbxp;\n"

    def returnzero_patch(self, line, label):
        return "return 0;\n"

    def returnone_patch(self, line, label):
        return "return 1;\n"

    def createmmccheck_patch(self, line, label):
        return line
        return "if (*globalmmcbxp) {return *globalmmcbxp;}\n"

    def declaremmc_patch(self, line, label):
        return line
        return "struct mmc *globalbxmmc, **globalmmcbxp = &globalbxmmc;\n"

    def blksz_patch(self, line, label):
        return "mmc->block_dev.blksz = 512;\n"

    def list_entry_patch(self, line, label):
        return ");});\n"

    def containerof_patch(self, line, label):
        typere = re.compile(
            "const typeof\( \((\([a-zA-Z \_0-9\-]+ \*\))0\)\-\>[a-zA-Z\_0-9\-]+ \)"
        )
        typename = typere.search(line)
        return line

    def mmc_initialize_patch(self, line, label):
        return "int initialized = 0;\n"

    def ext_csd_u8_patch(self, line, label):
        q = line.index("=")
        line = line[0:q] + " = (u8) " + line[q + 1:]
        return line

    def list_for_each_patch(self, line, label):
        return "if(1) { entry = (&mmc_devices)->next;\n"

    def memalign_patch(self, line, label):
        return "return malloc(bytes);\n"

    def chunksz_patch(self, line, lab):
        return "csz = sz+sizeof(size_t);\n"

    def tolower_patch(self, line, label):
        return "((char) *str) = (char) (('A' <= (*str)) && ((*str) <= 'Z') " \
            "? (char) ((char) *str + ' ') : (char) *str);\n"

    def memalign_return_patch(self, line, label):
        return "return m;\n"

    def le64u64_patch(self, line, label):
        return re.sub("\(\s*__le64\s*\)\s*\(\s*__u64\s*\)", "", line)

    def le32u32_patch(self, line, label):
        return re.sub("\(\s*__le32\s*\)\s*\(\s*__u32\s*\)", "", line)

    def u64le64_patch(self, line, label):
        return re.sub("\(\s*__u64\s*\)\s*\(\s*__le64\s*\)", "", line)

    def u32le32_patch(self, line, label):
        return re.sub("\(\s*__u32\s*\)\s*\(\s*__le32\s*\)", "", line)

    def func_patch(self, line, label):
        return re.sub("__func__", "__func__", line)

    def va_patch(self, line, label):
        return "extern void __builtin_va_start(__builtin_va_list);\n"

    def idx_patch(self, line, label):
        equals = line.index("=")
        return "l_name[*((u8 *) idx)] =" + line[equals:]

    def pte_patch(self, line, label):
        equals = line.index("=")
        return "pte = ( gpt_entry *)" + line[equals+1:]

    def min_patch(self, line, label):
        return "actsize = filesize <= (loff_t) bytesperclust "\
            "? filesize : (loff_t) bytesperclust;\n"

    def memcmp_patch(self, line, label):
        return "if ((res = (*su1 == *su2)) !=0) \n"

    def strcmp_patch(self, line, label):
        return "if (((__res = (*cs == *ct++)) != 0) || !*cs++)\n"

    def mmcscr_patch(self, line, label):
        rescr = re.compile("mmc->scr\[([0-9]+)\] =")
        res = rescr.search(line)
        return "mmc->scr[%s] = scr[%s];\n" % (res.group(1), res.group(1))

    def gpio_patch(self, line, label):
        return "return &omap_gpio_bank[gpio];\n"

    def revision_patch(self, line, label):
        return "revision = 2;\n"

    def sdr_cs_offset_patch(self, line, label):
        return "return 0;\n"

    def part_patch(self, line, label):
        return "part = 1;\n"

    def mangle_name(self, line, label):
        t = line.find(" ")
        i = line.find("(")
        return ("%s mangledname_ignore%s" %
                (line[0:t], ''.join(random.choice(string.ascii_uppercase)
                                    for _ in range(3)))) + line[i:]

    def mmcread_patch(self, line, label):
        return "*output_buf = o;\n"

    def mmcvolatile_patch(self, line, label):
        return "volatile char o;\n"

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
                #"align_buffer": self.alignbuffer_malloc_patch,  # self.alignbuffer_patch,
                # "align_buffer_dos": self.alignbufferdos_patch,
                #"align_decl": self.align_decl_patch,
                "chunksize": self.chunksz_patch,
                "cpuid": self.cpuid_patch,
                "delete_line": self.delete_line,
                "i2c_adap_max": self.i2cadapmax_patch,
                "i2c_adap_start": self.i2cadapstart_patch,
                "i2c_init_bus": self.i2cinitbus_patch,
                "malloc_zero": self.malloc_zero_patch,
                "memalign": self.memalign_patch,
                "noreturn": self.noreturn_patch,
                "return_zero": self.returnzero_patch,
                "sdr_cs_offset": self.sdr_cs_offset_patch,
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
    def instances(cls, stage, root=Main.get_bootloader_root(), quick=False):
        # if quick:
        #    files = cls.quick_files
        #else:
        files = cls.files
        fs = map(lambda s: os.path.join(root, s), files)
        fs = map(functools.partial(PreprocessedFileInstance, stage=stage), fs)
        return fs


class FramaCDstPluginManager():
    def __init__(self, stage, labels=None, execute=False, quick=False, more=False, verbose=False,
                 patchdest=Main.get_bootloader_root(),
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
        self.frama_c_args = " -load-script %s -machdep arm " \
                            " -load-script %s " \
                            " -load-script %s " \
                            " -val-use-spec do_fat_read_at -no-results-function printf " \
                            "-no-results-function get_timer_masked " \
                            "-no-results-function get_timer " \
                            "-no-results-function serial_printf "\
                            "-no-results-function fprintf "\
                            "-no-results-function fputs -no-results-function fputc"\
                            " -slevel 100 -slevel-function printf:0  -slevel-function puts:0 "\
                            " -va -val-initialization-padding-globals=no  -constfold "\
                            " -kernel-verbose %d -value-verbose %d  -big-ints-hex 0  "\
                            "-unsafe-arrays "\
                            " -val-builtin malloc:Frama_C_alloc_size,free:Frama_C_free "\
                            " -absolute-valid-range 0x40000000-0xffffffff "\
                            "-no-results-function pointer -no-results-function vsprintf"\
                            " -val -then -dst -then -call" % (os.path.join(self.path,
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
        self.frama_c_main_arg = "-main"
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
            print self.shortdest
            print self.patchdest
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
    cc = Main.cc
    if not args.standalone:
        d = doit_manager.TaskManager(False, False, [args.stage],
                                     {args.stage: args.policy_id},
                                     False, {}, args.test_id, False, [],
                                     hook=True)
        labels = Main.get_config("labels")
        root = Main.get_config("source_tree_copy")
        builder = d.build([Main.get_bootloader_cfg().software], False)[0]
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
        root = Main.get_bootloader_root()
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
        for p in sorted(list(patches.keys())):
            print "%s: %s" % (p, patches[p])
        if args.update or args.execute:
            if args.update:
                fc.update_db()
            else:
                fc.print_results()
