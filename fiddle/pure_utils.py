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
    return r2.entrypoint(elf)

def get_image_size(image):
    cmd = "/usr/bin/wc -c %s" % (image)
    output = shell.run_cmd(cmd)
    output = output.split()
    if len(output) == 2:
        return int(output[0], 0)
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
    for d in ds:
        h = {
            "number": index,
            "name": d["name"],
            "address": d["vaddr"],
            "offset": d["paddr"],
            "size": d['vsize'],
            "filesize": d['size'], 
            "flags": d['flags']
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
    for i in s:
        if i["name"] == name:
            if debug:
                print i
            return i["vaddr"]
    return -1
