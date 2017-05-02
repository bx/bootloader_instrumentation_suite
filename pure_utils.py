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
shell = run_cmd.Cmd()


def file_md5(filename):
    m = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            m.update(block)
    return m.hexdigest()


def get_entrypoint(cc, elf):
    cmd = "%sreadelf -W -h %s" % (cc, elf)
    output = shell.run_multiline_cmd(cmd)
    ere = re.compile("Entry point address:[\s]+(0x[a-fA-F0-9]{1,16})")
    for l in output:
        matches = ere.search(l)
        if matches:
            return int(matches.group(1), 0)


def get_image_size(image):
    cmd = "/usr/bin/wc -c %s" % (image)
    output = shell.run_cmd(cmd)
    output = output.split()
    if len(output) == 2:
        return int(output[0], 0)
    else:
        return -1


def get_program_headers(cc, elf):
    cmd = "%sreadelf -W -l %s" % (cc, elf)
    output = shell.run_multiline_cmd(cmd)
    numre = "0x[0-9a-fA-F]{1,16}"
    phre = re.compile("([\w]+)[\s]+(%s)[\s]+(%s)[\s]+(%s)[\s]+(%s)[\s]+"
                      "(%s)[\s]+([RWE ]{3})[\s]+(%s)" %
                      (numre, numre, numre, numre, numre, numre))
    headers = []
    for l in output:
        matches = phre.search(l)
        if matches:
            h = {
                "type": matches.group(1),
                "offset": int(matches.group(2), 0),
                "virtaddr": int(matches.group(3), 0),
                "physaddr": int(matches.group(4), 0),
                "filesz": int(matches.group(5), 0),
                "memsz": int(matches.group(6), 0),
                "flags": matches.group(7),
                "align": int(matches.group(8), 0),
            }
            headers.append(h)
    return headers


def get_min_max_pcs(cc, elf):
    headers = get_program_headers(cc, elf)
    lo = float('inf')
    hi = 0
    for h in headers:
        if (h['memsz'] > 0) and (h['type'] == 'LOAD'):  # if memory mapped
            hstart = h['virtaddr']
            hstop = hstart+h['memsz']
            if ("E" in h['flags']):  # if executable
                if hstart < lo:
                    lo = hstart
                if hstop > hi:
                    hi = hstop
    return (lo, hi)
