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

import re


class QemuParsedObject():
    def __init__(self, time, pid, size, dest, pc, lr, cpsr):
        #  pid, size, dest, pc, lr, cpsr
        if type(time) == str:
            self.time = float(time)
            self.pid = int(pid)
            self.size = int(size, 16)
            self.pc = int(pc, 16)
            self.lr = int(lr, 16)
            self.dest = int(dest, 16)
            self.cpsr = int(cpsr, 16)
        else:
            self.time = time
            self.pid = pid
            self.size = size
            self.pc = pc
            self.lr = lr
            self.dest = dest
            self.cpsr = cpsr

    def __repr__(self):
        return "time=%.3f pid=%i size=%d dest=0x%x pc=0x%x lr=0x%x, cpsr=0x%x" \
            % (self.time, self.pid, self.size, self.dest, self.pc, self.lr, self.cpsr)


class QemuSimpleParse():
    @staticmethod
    def toobject(line):
        rgx = re.compile(r'my_cpu_write ([0-9]+\.{0,1}[0-9]{0,3}) pid=([0-9]+) \
        size=(0x[0-9a-fA-F]+) addr=(0x[0-9a-fA-F]{0,8}) pc=(0x[0-9a-fA-F]{0,8}) \
        lr=(0x[0-9a-fA-F]{0,8}) cpsr=(0x[0-9a-fA-F]{0,8})')
        res = re.match(rgx, line)
        if res is None:
            print "this line doesn't parse properly: %s" % line
        res = res.groups()
        return QemuParsedObject(*res)

    @staticmethod
    def tostring(line):
        QemuSimpleParse.objtostring(QemuSimpleParse.toobject(line))
