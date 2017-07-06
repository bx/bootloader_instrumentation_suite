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


def addr2line(addr, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = '%saddr2line -e %s 0x%x 2>/dev/null' % (cc, elf, addr)
    ret = Main.shell.run_cmd(cmd)
    return ret.split()[0]  # sometimes there is extra junk after the line number (like below)


def infoline(line, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = '%sgdb -ex "info line %s" --batch --nh --nx %s 2>/dev/null' % (cc, line, elf)
    output = Main.shell.run_cmd(cmd).split("\n")
    return output


def line2addrs(line, stage):
    output = infoline(line, stage)
    startat = output[0]
    # print output
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


def gdblist(line, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = '%sgdb -ex "l %s" --batch --nh --nx %s 2>/dev/null' % (cc, line, elf)
    return Main.shell.run_cmd(cmd)


def addr2functionname(addr, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = '%sgdb -ex "x/i 0x%x" --batch --nh --nx %s 2>/dev/null' % (cc, addr, elf)
    output = Main.shell.run_cmd(cmd)
    output = output.split('\n')[0].strip()
    output = output.split(':')[0]
    if output.lower() == '0x%x:':
        return ''  # not located in a function
    else:
        rgx = re.compile(r'<([A-Za-z0-9_]+)(\+\d+){0,1}>')
        res = re.search(rgx, output)
        if res is None:
            return ''
        else:
            return res.group(1)


def line2src(line):
    [path, lineno] = line.split(':')
    cmd = "sed -n '%s,%sp' %s 2>/dev/null" % (lineno, lineno, path)
    try:
        output = Main.shell.run_cmd(cmd)
        return output
    except:
        return ''


def disasmrange(start, end, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = "%sobjdump -D -w --start-address=0x%x --stop-address=0x%x %s 2>/dev/null" \
          % (cc, start, end, elf)
    return Main.shell.run_cmd(cmd)


def addr2disasmobjdump(addr, sz, stage, thumb=True, debug=False):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = "%sobjdump -D -w --start-address=0x%x --stop-address=0x%x -j .text %s 2>/dev/null" \
          % (cc, addr, addr+sz, elf)
    if debug:
        print cmd
    output = Main.shell.run_cmd(cmd).split("\n")
    if len(output) < 2:
        return (None, None, None, None)
    if debug:
        print output
    addrre = re.compile("%x" % addr)
    output = [l for l in output if addrre.match(l)]

    name = output[0].strip()
    disasm = output[1].strip()
    func = ""
    rgx = re.compile(r'<([A-Za-z0-9_]+)(\+0x[a-fA-F0-9]+){0,2}>:')
    res = re.search(rgx, name)
    if res is None:
        func = ''
    else:
        func = res.group(1)

    disasm = disasm.split('\t')

    # convert to a hex string and then decode it to it is an array of bytes
    value = (''. join(disasm[1].split())).decode('hex')

    instr = ' '.join(disasm[2:])
    if (not thumb) or (len(value) == 2):
        value = value[::-1]
    else:
        sv = value[:2][::-1]
        ev = value[2:][::-1]
        value = sv+ev

    return (value, instr, func)


def addr2funcnameobjdump(addr, stage, debug=False):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = "%sobjdump -D -w --start-address=0x%x --stop-address=0x%x %s 2>/dev/null" \
          % (cc, addr, addr + 4, elf)
    if debug:
        print cmd
    output = Main.shell.run_cmd(cmd).split("\n")
    if debug:
        print output
    addrre = re.compile("%x" % addr)
    output = [l for l in output if addrre.match(l)]
    if debug:
        print output
    name = output[0].strip()
    func = ""
    if debug:
        print name
    rgx = re.compile(r'%x <([A-Za-z0-9_]+)(\+0x[0-9a-fA-F]+){0,1}>:' % addr)
    res = re.search(rgx, name)
    if res is None:
        func = ''
    else:
        func = res.group(1)
    return func


def addr2disasm(addr, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = '%sgdb -ex "disassemble/r 0x%x,+1" --batch --nh --nx %s 2>/dev/null' % (cc, addr, elf)
    # print cmd
    output = Main.shell.run_cmd(cmd)
    voutput = output.split('\n')[1].strip()  # get line with disassembly
    voutput = voutput.split('\t')
    # try:
    # convert to a hex string and then decode it to it is an array of bytes
    value = (''.join(voutput[1].split())).decode('hex')
    # except Exception:

    instr = ' '.join(voutput[2:])

    # get function name if possible
    foutput = output.split(':')[0]
    if foutput.lower() == '0x%x:':
        func = ''  # not located in a function
    else:
        rgx = re.compile(r'<([A-Za-z0-9_]+)(\+\d+){0,1}>')
        res = re.search(rgx, foutput)
        if res is None:
            func = ''
        else:
            func = res.group(1)
    return (value, instr, func)


def get_c_function_names(stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = '%sreadelf -W -s %s 2>/dev/null' % (cc, elf)
    output = Main.shell.run_multiline_cmd(cmd)
    regexp = re.compile("\s+\d+:\s+(?P<addr>[a-fA-f0-9]{8})\s+\w*\s+(?P<t>[A-Z]+)\s+\w*\s+\w*\s+\w*\s+(?P<name>[\w_\-\.]+)\s*$")
    results = []
    for l in output:
        m = regexp.search(l)
        if m is not None:
            (addr, name, t) = (m.groupdict()['addr'], m.groupdict()['name'], m.groupdict()['t'])
            if t == "FUNC":
                results.append((name, int(addr, 16)))
    return results


def get_section_headers(stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    return pure_utils.get_section_headers(cc, elf)


def get_section_location(name, stage):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    return pure_utils.get_section_location(cc, elf, name)


def get_symbol_location(name, stage, debug=False, nm=False):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    return pure_utils.get_symbol_location(cc, elf, name, debug, nm)


def get_symbol_location_start_end(name, stage, debug=False):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    start = get_symbol_location(name, stage, debug)
    if start >= 0:
        cmd = '%sreadelf -W -s %s | grep %s 2>/dev/null' % (cc, elf, name)
        if debug:
            print cmd
        output = Main.shell.run_cmd(cmd)
        if debug:
            print output
        size = int(output.split()[2])
        return (start, start + size)
    else:
        return (0, 0)


def get_line_addr(line, start, stage, debug=False):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = "%sgdb -ex 'dir %s' -ex 'info line %s' --batch --nh --nx  %s 2>/dev/null" % (cc,
                                                                                       Main.get_bootloader_root(),
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


def get_line_addr2(line, stage, debug=False):
    cc = Main.cc
    elf = Main.get_config("stage_elf", stage)
    cmd = "%sgdb -ex 'dir %s' -ex 'info line %s' --batch --nh --nx  %s 2>/dev/null" % (cc,
                                                                                       Main.get_bootloader_root(),
                                                                                       line, elf)
    if debug:
        print cmd
    output = Main.shell.run_multiline_cmd(cmd)
    if debug:
        print output
    output = output[0]

    assembly = False
    if ("but contains no code." in output) and (".S\" is at address" in output):
        readdr = re.compile("is at address (0x[0-9a-fA-F]{0,8})")
    else:
        readdr = re.compile("starts at address (0x[0-9a-fA-F]{0,8})")
    if not readdr:
        return -1
    addrg = readdr.search(output)
    if not addrg:
        return -1
    res = int(addrg.group(1), 0)
    return res


def symbol_relocation_file(name, offset, stage, path=None, debug=False):
    if path is None:
        path = tempfile.NamedTemporaryFile("rw").name
    elf = Main.get_config("stage_elf", stage)
    cc = Main.cc
    cmd = "%sobjcopy  --extract-symbol -w -N \!%s --change-addresses=0x%x %s %s 2>/dev/null" % (cc,
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
