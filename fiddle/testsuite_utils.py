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

from config import Main
import re
import os
import pure_utils
import r2_keeper as r2
import json

def addr2functionname(addr, stage, debug=False):
    elf = stage.elf
    old = r2.gets(elf, "s")
    r2.get(elf, "s 0x%x" % addr)    
    s = r2.get(elf, "afi")
    r2.get(elf, "s %s" % old)    
    def getname(i):
        name = i["name"]
        if i.name.startswith("sym."):
            name = name[4:]
    #print "addr2fn %x " % (addr)            
    for i in s:
        if len(i) > 1:
            print s
            print "%x addr func" % addr
            raise Exception
        name = getname(i)
        
        return name
    return ""

def get_symbol_location(name, stage, debug=False):
    elf = stage.elf
    return pure_utils.get_symbol_location(elf, name, debug)    

def addr2line(addr, stage, debug=False):
    fn = addr2functionname(addr, stage)
    addr = get_symbol_location(fn, stage)
    elf = stage.elf
    #print "addr2line 0x%x" % addr
    old = r2.gets(elf, "s")                
    r2.get(elf, "s 0x%x" % addr)    
    s = r2.gets(elf, "CL")
    r2.get(elf, "s %s" % old)    
    res = s.split()
    d = r2.gets(elf, "pwd")
    if debug and res:
        print "addr2line %s%s:%s" % (d, res[1][2:], res[3])
    if res:
        return "%s%s:%s" % (d, res[1][2:], res[3])
    else:
        return ""

def line2addrs(line, stage):
    output = infoline(line, stage)
    startat = output[0]
    assembly = False
    isataddr = None
    restart = None
    reend = None
    if ("but contains no code." in startat) and (".S\" is at address" in startat):
        if (".S\" is at address" in startat):  # is assembly
            assembly = True
        isataddr = re.compile("is at address (0x[0-9a-fA-F]{0,8})")

    else:
        restart = re.compile("starts at address (0x[0-9a-fA-F]{0,8})")
        reend = re.compile("and ends at (0x[0-9a-fA-F]{0,8})")

    if isataddr:
        if assembly:
            startaddr = int((isataddr.search(startat)).group(1), 0)
            return (startaddr, startaddr+4)
        else:
            return (-1, -1)
    else:
        startaddr = int((restart.search(startat)).group(1), 0)
        endaddr = int((reend.search(startat)).group(1), 0)
        return (startaddr, endaddr)


def line2src(line):
    try:
        [path, lineno] = line.split(':')
    except ValueError:
        return ""
    cmd = "sed -n '%s,%sp' %s 2>/dev/null" % (lineno, lineno, path)
    try:
        output = Main.shell.run_cmd(cmd)
        return output
    except:
        return ''


def addr2disasmobjdump(addr, sz, stage, thumb=True, debug=False):
    old = r2.gets(stage.elf, "s")
    r2.get(stage.elf, "s 0x%x" % addr)
    if thumb:
        r2.get(stage.elf, "e asm.bits=16" )
        r2.gets(stage.elf, "ahb 16")        
    else:
        r2.get(stage.elf, "e asm.bits=32" )
        r2.gets(stage.elf, "ahb 32")        
    
    i = r2.get(stage.elf, "pdj 1")[0]
    i = r2.get(stage.elf, "pdj 1")[0]    
    if "disasm" in i or "invalid" in i["type"] or "invalid" in i["disasm"]:
        return (None, None, None)    
    fn = addr2functionname(addr, stage, debug)
    return (i['bytes'], i['disasm'], fn)



def get_c_function_names(stage):
    cc = Main.cc
    elf = stage.elf
    cmd = '%sreadelf -W -s %s | grep FUNC 2>/dev/null' % (cc, elf)
    output = Main.shell.run_multiline_cmd(cmd)

    results = []
    for l in output:
        cols = l.split()
        if len(cols) > 7:
            addr = cols[1]
            name = cols[7]     
            results.append((name, int(addr, 16)))        

    return results


def get_section_headers(stage):
    elf = stage.elf
    return pure_utils.get_section_headers(elf)


def get_section_location(name, stage):
    elf = stage.elf
    return pure_utils.get_section_location(elf,name)


def get_symbol_location_start_end(name, stage, debug=False):
    elf = stage.elf
    s = r2.get(elf, "isj")    
    for i in s:
        if i["name"] == name:
            addr = i["vaddr"]
            if debug:
                print i            
            return (addr, addr + i["size"])
    return (-1, -1)


def get_line_addr(line, start, stage, debug=False, srcdir=None):
    cc = Main.cc
    elf = stage.elf
    if srcdir:
        srcdir = "--cd=%s " % (srcdir)
    cmd = "%sgdb %s -ex 'info line %s' --batch --nh --nx  %s 2>/dev/null" % (cc,
                                                                             srcdir,
                                                                             line, elf)
    if debug:
        print cmd
    output = Main.shell.run_multiline_cmd(cmd)
    if debug:
        print output
    output = output[0]

    assembly = False
    if ("but contains no code." in output) and (".S\" is at address" in output):
        if (".S\" is at address" in output):  # is assembly
            assembly = True
        readdr = re.compile("is at address (0x[0-9a-fA-F]{0,8})")
    elif start:
        readdr = re.compile("starts at address (0x[0-9a-fA-F]{0,8})")
    else:
        readdr = re.compile("and ends at (0x[0-9a-fA-F]{0,8})")
    if not readdr:
        return -1
    addrg = readdr.search(output)
    if not addrg:
        return -1
    res = int(addrg.group(1), 0)
    if assembly and (not start):
        res += 1   # give something larger for end endress for non-includive range
    return res


def symbol_relocation_file(name, offset, stage, path=None, debug=False):
    if path is None:
        path = tempfile.NamedTemporaryFile("rw").name
    elf = stage.elf
    srcdir = Main.raw.runtime.temp_target_src_dir
    cc = Main.cc
    cmd = "%sobjcopy  --extract-symbol -w -N \!%s "\
          "--change-addresses=0x%x %s %s 2>/dev/null" % (cc,
                                                         name,
                                                         offset,
                                                         elf,
                                                         path)
    if debug:
        print cmd
    output = Main.shell.run_cmd(cmd)
    if debug:
        print output
    return path
