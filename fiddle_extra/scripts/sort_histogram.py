#!/usr/bin/env python2

import argparse
import os
import re
self_path = __file__

if __name__ == "__main__":
    parser = argparse.ArgumentParser("histogram")
    parser.add_argument('-i', '--input',
                        default=os.path.join(os.path.abspath(os.path.dirname(self_path)),
                                             "..", "..", "..",
                                             "bootloader_test_data3/bbxm.u-boot.bbxm"
                                             "_verified_defconfig.refsheadsorig.956bc"
                                             "003f0b4ad2b283ed319e686d9aa5861341b.dba2"
                                             "3fb68c1005c5b8bbc0be304d3b33/trace_data/"
                                             "00000001/consolidate_writes/spl-write_range_info.txt"))
    parser.add_argument('-n', '--head',
                        action="store", default=0, type=int)
    args = parser.parse_args()
    print args.input
    entries = []
    hex = "[a-fA-F0-9]"
    addrre = re.compile("pc=(%s*)/\[(%s*)\]" % (hex, hex))
    destre = re.compile("\[(%s*)-(%s*)\]" % (hex, hex))

    class entry():
        def __init__(self, l):
            line = l.split()

            r = addrre.match(line[0])
            self.pc = r.group(1)
            self.va = r.group(2)
            self.fn = line[1][1:-1]
            self.lr = line[2][3:]
            self.lr_funnc = line[3][1:-1]

            r = destre.match(line[4])
            self.dest_lo = r.group(1)
            self.dest_hi = r.group(2)

            self.numbytes = long(line[5][1:-1])
            self.repeat = long(line[6])
            rest = (" ".join(line[8:])).split("--")
            self.asm = rest[1].strip()
            self.source = rest[2].strip()

        def __str__(self):
            if self.va == self.pc:
                addrs = "pc=0x%s" % self.pc
            else:
                addrs = "va:0x%s/pc:0x%s" % (self.va, self.pc)
            return "[repeat:%s] %s @ %s wrote %s bytes to 0x%s [%s]" % (self.repeat,
                                                                        self.fn,
                                                                        addrs,
                                                                        self.numbytes,
                                                                        self.dest_lo,
                                                                        self.asm)

    with open(args.input) as f:
        for l in f.readlines():
            entries.append(entry(l))

    sort = sorted(entries, cmp=lambda x, y: y.numbytes - x.numbytes)
    count = len(sort) if args.head < 1 else args.head
    for i in range(count):
        e = sort[i]
        print e
