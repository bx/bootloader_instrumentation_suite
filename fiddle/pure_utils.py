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

import hashlib
import run_cmd
import re
import r2_keeper as r2
shell = run_cmd.Cmd()


def file_md5(filename):
    m = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            m.update(block)
    return m.hexdigest()


def get_entrypoint(elf):
    try:
        return r2.entrypoint(elf)
    except KeyError:
        r2.gets(elf, "s")
    return r2.entrypoint(elf)


def get_c_function_names(elf, cc="/usr/bin/"):
    cmd = '%sreadelf -W -s %s | grep FUNC 2>/dev/null' % (cc, elf)
    output = shell.run_multiline_cmd(cmd)

    results = []
    for l in output:
        cols = l.split()
        if len(cols) > 7:
            addr = cols[1]
            name = cols[7]
            results.append((name, long(addr, 16)))

    return results


def get_image_size(image):
    cmd = "/usr/bin/wc -c %s" % (image)
    output = shell.run_cmd(cmd)
    output = output.split()
    if len(output) == 2:
        return long(output[0], 0)
    else:
        return -1


def get_min_max_pcs(elf):
    headers = get_section_headers(elf)
    lo = float('inf')
    hi = 0
    for h in headers:
        if (h['size'] > 0) and (h['flags'][-1] == 'x'):  # if memory mapped
            hstart = h['address']
            hstop = hstart+h['size']
            if hstart < lo:
                lo = hstart
            if hstop > hi:
                hi = hstop
    return (lo, hi)

def get_section_headers(elf):
    ds = r2.get(elf, "iSj")
    index = 0
    headers = []
    if len(ds) > 0:
        # flags key differs between r2 versions
        if "flags" in ds[0]:
            flags = "flags"
        else:
            flags = "perm"
    for d in ds:
        h = {
            "number": index,
            "name": d["name"],
            "address": d["vaddr"],
            "offset": d["paddr"],
            "size": d['vsize'],
            "filesize": d['size'],
            "flags": d[flags]
        }
        headers.append(h)
        index += 1
    return headers


def get_section_location(elf, name):
    start = 0
    end = 0

    headers = get_section_headers(elf)
    for h in headers:
        if h['name'] == name:
            start = h['address']
            end = start+h['size']
            return (start, end)
    return (-1, -1)


def get_symbol_location(elf, name, debug=False):
    s = r2.get(elf, "isj")
    name = u"%s" % name # convert to unicode
    for i in s:
        if i["name"] == name:
            if debug:
                print i
            return i["vaddr"]
    return -1


def addr2functionname(addr, elf, debug=False):
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


def addr2line(addr, elf, debug=False, fn=None):
    if fn is None:
        fn = addr2functionname(addr, elf, debug)
    addr = get_symbol_location(elf, fn, debug)
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
