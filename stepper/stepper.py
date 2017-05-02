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

"""
SYNOPSIS

    stepper.py [-h,--help] [-v,--verbose]

DESCRIPTION

    TODO This describes how to use this script. This docstring
    will be printed by the script if there is an error or
    if the user requests help (-h or --help).

EXAMPLES

    TODO: Show some examples of how to use this script.

EXIT STATUS

    TODO: List exit codes

AUTHOR

    TODO: Name <name@example.org>

LICENSE

    The MIT License (MIT)

    Copyright (c) 2017 Rebecca ".bx" Shapiro

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

"""

import sys
import argparse
import logging
import time
# import string
import socket
# import sys
import os
import re
path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(path, ".."))
from config import Main
import doit_manager
import db_info
import signal
import staticanalysis

class OpenOcdRpcClient():
    COMMAND_TOKEN = '\x1a'

    def __init__(self, log="openocd.out"):
        self.tcl_server = "127.0.0.1"
        self.tcl_port = 6666
        self.buffer_size = 4096
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.tcl_server, self.tcl_port))
        self.send("init")
        # self.send("tcl_notifications on")
        self.send("debug_level 0")
        self.log = log
        self.send('log_output %s' % log)

    def __exit__(self, type, value, traceback):
        try:
            self.send("exit")
        finally:
            self.sock.close()

    def send(self, cmd):
	"""
        Send a command string to TCL RPC. Return the result that was
        read.
        """
        data = (cmd + OpenOcdRpcClient.COMMAND_TOKEN).encode("utf-8")

        self.sock.send(data)
        return self._recv()

    def recv(self):
        packet = self._recv()

        # Strip trailing CR-LF.
        packet = packet[:-2]

        return packet

    def _recv(self):
        """
        Read from the stream until the token ('\x1a') was received.
        """
        data = bytes()

        while True:
            chunk = self.sock.recv(self.buffer_size)
            data += chunk

            if bytes(OpenOcdRpcClient.COMMAND_TOKEN) in chunk:
                break
        data = data.decode("utf-8").strip()
        # Strip trailing '\x1a'.
        data = data[:-1]

        return data


class OpenOcd():
    def __init__(self, ocdinit=None, noinit=False, log="openocd.log"):
        self.ocd = OpenOcdRpcClient(log)
        self.ocdinit = ocdinit
        self.noinit = noinit
        if (not noinit) and self.ocdinit:
            for l in self.ocdinit.readlines():
                self.ocd.send(l)

    def read_addr(self, address):
        raw = self.ocd.send("ocd_mdw 0x%x" % address).split(": ")
        return None if (len(raw) < 2) else raw[1].encode("hex")

    def read_instr(self, address, thumb=None):
        if thumb is None:
            core = self.ocd.send("ocd_arm core_state")
            core = (core.split(": ")[1])[:-1]  # strip off command suffix too
            if core == "Thumb":
                core_state = 'thumb'
            else:
                core_state = ''
        else:
            core_state = 'thumb' if thumb else ''
        cmd = "ocd_arm disassemble 0x%x 1 %s" % (address, core_state)
        instr = self.ocd.send(cmd)
        instr = instr[:-1].encode("utf-8")
        instr = instr.split()
        instr = [i for i in instr if not i == u'']
        try:
            instr_value = instr[1][2:].decode('hex')
        except ValueError:
            print instr
            return (None, None, None)
        instr_dis = ' '.join(instr[2:]).strip()
        return (core_state, instr_value, instr_dis)

    def read_mem(self, wordLen, address, n):
        self.ocd.send("array unset output")  # better to clear the array before
        self.ocd.send("mem2array output %d 0x%x %d" % (wordLen, address, n))

        output = self.ocd.send("ocd_echo $output").split(" ")

        return [int(output[2*i+1]) for i in range(len(output)//2)]

    def write_var(self, address, value):
        assert value is not None
        self.ocd.send("mww 0x%x 0x%x" % (address, value))

    def show(self, *args):
        print str(*args) + "\n\n"

    def read_reg(self, reg):
        raw = self.ocd.send("ocd_reg %s" % reg).split(": ")  # force?
        return None if (len(raw) < 2) else int(raw[1], 0)


class OpenOcdStepper():
    def __init__(self, client,
                 stage,
                 test_id, instance_id, policy_id, verbose=False):
        self.ia = staticanalysis.InstructionAnalyzer()
        self.stage = stage
        self.verbose = verbose
        self.ocd = client
        self.stepno = 0
        self.test_id = test_id
        self.instance_id = instance_id
        self.policy_id = policy_id
        self.do_it = doit_manager.TaskManager(False, False, [self.stage.stagename],
                                              {self.stage.stagename: policy_id},
                                              False, False, self.instance_id,
                                              False, [], self.test_id)

        self.exitpc = self.stage.exitpc
        self.minpc = self.stage.minpc
        self.maxpc = self.stage.maxpc

        self.pc = self.ocd.read_reg("pc")
        signal.signal(signal.SIGINT, self.int_signal)
        if not self.ocd.noinit:
            while not ((self.pc == 0x40200800) or (self.pc == 0x40200860)):
                print "pc=%x" % self.pc
                self.ocd.ocd.send("step")
                self.pc = self.ocd.read_reg("pc")
            print "found entrypoint pc=%x" % self.pc

    def execute_rom(self, until, verbose=False, thumb=False):
        start = self.pc
        print "resuming at %x (until %x)" % (start, until)
        #if thumb:
        #    self.ocd.ocd.send("bp 0x%x 1 hw" % (until))
        #else:
        self.ocd.ocd.send("bp 0x%x 1 hw" % (until))
        self.ocd.ocd.send("resume")
        self.ocd.ocd.send("wait_halt 100000")
        self.ocd.ocd.send("rbp 0x%x" % until)
        self.pc = until

    def finish(self):
        print "finishing databse processing"
        db_info.close()

    def int_signal(self, signal, frame):
        print "received int signal at %x" % self.pc
        self.finish()

    def calculate_write_dest(self, pc, val, core, writeregs):
        regnames = {
            'sp': 'sp_svc',
            'lr': 'lr_svc',
            'sb': 'r9',
            'sl': 'r10',
            'fp': 'r11',
        }
        regs = [r for r in writeregs if r]
        ins = self.ia.disasm(val, core, pc)
        regexp = re.compile("^\([0-9]+\) ([0-9a-zA-Z_]+) \(/32\): (0x[0-9a-fA-F]{0,8})+")
        regexp2 = re.compile("^\([0-9]+\) ([0-9a-zA-Z_]+) \(/32\)")
        if self.ia.is_instr_memstore(ins):
            regvalues = []
            ocd_regs = self.ocd.ocd.send("ocd_reg").split('\n')
            for r in regs:
                if r in regnames.keys():
                    r = regnames[r]
                for ocdr in ocd_regs:
                    ocdr = ocdr.encode('ascii').strip()
                    results = regexp.search(ocdr)
                    results2 = regexp2.search(ocdr)
                    if results and results.group(1) == r:
                        regvalues.append(int(results.group(2), 0))
                    elif results2 and results2.group(1) == r:
                        # print "reg not on list"
                        regvalues.append(self.ocd.read_reg(r))
                    if results and results.group(1) == 'lr_svc':
                        self.lr = int(results.group(2), 0)
                    if results and results.group(1) == 'cpsr':
                        self.cpsr = int(results.group(2), 0)

            if self.ia.store_will_happen(ins, regvalues):
                return self.ia.calculate_store_offset(ins, regvalues)
            else:
                return 0
        else:
            return 0

    def skip_to(self, addr):
        self.ocd.ocd.send("bp 0x%x 4 hw" % addr)
        self.ocd.ocd.send("resume")
        self.ocd.ocd.send("wait_halt 200000")
        self.ocd.ocd.send("rbp 0x%x" % addr)

    def go_until(self, addr):
        print "running until %x" % addr
        self.broken = False
        self.lr = 0
        self.pc = self.ocd.read_reg("pc")
        while not (self.pc == addr):
            if self.verbose:
                print "pc=%x" % self.pc
            success = self.step()
            if not success:
                print "Cannot step : ( starting at pc=%x step=%d" % (self.pc, self.stepno)
                if self.broken:
                    print "resetting jtag wasnt enough"
                    return
                else:
                    self.broken = True
                    print "Attempting to reset jtag"
                    self.ocd.ocd.send("debug_level 3")
                    self.ocd.ocd.send("jtag init")
                    self.ocd.ocd.send("halt")
                    self.ocd.ocd.send("wait_halt 10000")
                    self.ocd.ocd.send("step")
                    self.ocd.ocd.send("debug_level 0")
                    continue
            else:
                self.broken = False

                if db_info.get(self.stage).is_smc(self.pc):
                    print "SKIPPING ROM"
                    self.execute_rom(self.pc + 4, False)
                res = db_info.get(self.stage).skip_info(self.pc)
                if len(res) > 0:
                    row = res.pop()
                    self.execute_rom(row['resumepc'], thumb=row['thumb'])

                res = db_info.get(self.stage).stepper_write_info(self.pc)
                if len(res) > 0:
                    row = res.pop()
                else:
                    row = None
                srcres = db_info.get(self.stage).src_write_info(self.pc)
                if len(srcres) > 0:
                    srcrow = srcres.pop()
                else:
                    srcrow = None
                if row:  # if this instruction is a write instruction
                    size = 0
                    dest = None
                    val = srcrow['ivalue'].ljust(srcrow['ilength'], '\0')
                    core = row['thumb']
                    size = row['writesize']
                    dest = self.calculate_write_dest(self.pc, val, core,
                                                     [row['reg0'], row['reg1'],
                                                      row['reg2'], row['reg3']])
                    db_info.get(self.stage).add_trace_write_entry(
                        time.time(), 0, size, dest, self.pc,
                        self.lr, self.cpsr, self.stepno)

                if (self.stepno % 1000) == 0:
                    print "stepno=%d pc=0x%x" % (self.stepno, self.pc)
        print "DONE! at %x (%x)" % (self.pc, addr)
        self.finish()

    def get_maskisr(self):
        masked = self.ocd.ocd.send("ocd_cortex_a maskisr")
        masked = masked.encode("utf-8").split()
        if masked[-1] == 'off':
            return False
        else:
            return True

    def set_maskisr(self, state):
        if state:
            state = 'on'
        else:
            state = 'off'
            self.ocd.ocd.send("ocd_cortex_a maskisr %s" % state)

    def get_instr(self, thumb=None):
        return self.ocd.read_instr(self.pc, thumb)

    def step(self):
        self.stepno += 1
        res = self.ocd.ocd.send("ocd_step")
        rows = res.encode("utf-8").split("\n")
        halted = rows[0].strip()[-6:]
        self.ocd.ocd.send("wait_halt 10000")
        if not halted == 'halted':
            print "not halted"
            print rows
            return False
        pc = rows[2].strip().split()[-1]
        self.pc = int(pc, 0)
        CPSR_THUMB = 0x20
        self.thumb = True if \
            (int(rows[2].strip().split()[-3], 0) & CPSR_THUMB) == CPSR_THUMB \
            else False
        return True


def main():
    """main"""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    # verbositygroup = parser.add_mutually_exclusive_group()
    # verbositygroup.add_argument('-v', '--verbose', help='Verbose logging', action='store_const',
    #                             const=logging.INFO, dest='loglevel')
    # verbositygroup.add_argument('-d', '--debug', help='Debugging logging', action='store_const',
    #                             const=logging.DEBUG, dest='loglevel')
    # verbositygroup.add_argument('-q', '--quiet', help='Minimal logging', action='store_const',
    #                             const=logging.CRITICAL, dest='loglevel')
    parser.add_argument('-n', '--noinit', help='do not run initialization', action='store_const',
                        const=True, default=False)

    parser.add_argument('-l', '--logfile', help='Path to file in which "\
    "to write openocd logging information',
                        action="store",
                        default="openocd.out")
    parser.add_argument('-i', '--openocdinit',
                        help='Path to file to read openocd commands "\
                        "froms to run when first launched',
                        type=argparse.FileType('r'))
    parser.add_argument('-s', '--startat', help='Start trace at this address', action='store',
                        default="0x40200800")
    parser.add_argument('-e', '--endat', help='End trace at this address', action='store',
                        default="0x80100000")
    parser.add_argument('-D', '--writedest', help='Get extra write destination information',
                        action='store_true', default=False)
    parser.add_argument('-t', '--test_id', action="store", default='')
    parser.add_argument('-I', '--instance_id', action="store", default='')
    parser.add_argument('-p', '--policy_id', action="store", default='')
    parser.add_argument('-v', '--verbose', action="store_true", default=False)
    parser.add_argument('-b', '--stage', action="store", default='spl')
    args = parser.parse_args()

    o = OpenOcd(args.openocdinit, args.noinit, args.logfile)
    stage = Main.stage_from_name(args.stage)
    print args
    stepper = OpenOcdStepper(o,
                             stage,
                             args.test_id,
                             args.instance_id,
                             args.policy_id,
                             args.verbose)
    if args.startat:
        print "startat %x" % (int(args.startat, 0))
        time.sleep(1)
        stepper.skip_to(int(args.startat, 0))
    stepper.go_until(int(args.endat, 0))


if __name__ == '__main__':
    main()
    sys.exit(0)
