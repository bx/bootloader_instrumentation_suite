#!/usr/bin/env python
import fiddle.staticanalysis
import fiddle.r2_keeper as r2

import sys
from fiddle.staticanalysis import LongWriteInfo

class LongWriteInfoOld():

    #@classmethod
    #def from_start_end(cls, elf, start, end, thumb):
    #    # get basic block
    #    return cls(elf, branch_ins["offset"], thumb)

    def __init__(self, elf, start, end, thumb):
        self.valid = True
        self.start_ins = None
        self.start_ins_addr = None
        self.write_ins = None
        self.write_ins_addr = None
        self.finish_ins = None
        self.finish_ins_addr = None
        self.start = start
        self.end = end
        self.elf = elf
        self.thumb = thumb
        self.valid = False
        self.branch_ins_addr = None
        self.branch_ins = None

        # grab basic blocks surrounding this region
        r2.gets(elf, "s 0x%x" % self.start)
        if self.thumb: # force r2 to use the correct instruction size. sigh.
            r2.gets(elf, "ahb 16")
            r2.gets(elf, "e asm.bits=16")
        else:
            r2.gets(elf, "ahb 32")
            r2.gets(elf, "e asm.bits=32")
        self.bbs = r2.get(elf,"pdbj")
        next = self.bbs[-1]["offset"] + self.bbs[-1]["size"]
        while next < end:
            r2.get(elf, "s 0x%x" % next)
            self.bbs.extend(r2.get(elf, "pdbj"))
            next = self.bbs[-1]["offset"] + self.bbs[-1]["size"]
        # grab one more basic block
        r2.get(elf, "s 0x%x" % next)
        #print r2.gets(elf, "pdb")
        self.bbs.extend(r2.get(elf, "pdbj"))

        # lookup write instruction
        nwrites = 0
        for i in self.bbs:
            mne = i["opcode"].split()[0]

            if fiddle.staticanalysis.InstructionAnalyzer._is_mne_memstore(mne):
                nwrites += 1
                if (self.start <= i["offset"]) and (i["offset"] < self.end):
                    if self.write_ins is not None:
                        # if there are two write instruction in basic block, don't know what to do
                        self.valid = False
                        break
                    else:
                        self.write_ins = i
                        self.valid = True
                        self.write_ins_addr = self.write_ins["offset"]
        if nwrites > 1:
            print "Warning: %s write ins in these blocks" % nwrites
        if not self.valid:
            return

        # look for branch after write to find loop
        branch = None
        unconditional = False
        for b in self.bbs:
            if b["offset"] < start:
            #    if "xrefs" in b.keys() and not self.branch_ins_addr:
            #        self.branch_ins_addr = b["xrefs"][0]["addr"]
                continue
            if b["type"] == u"cjmp" or b["type"] == u"jmp":
                if b["type"] == "jmp":
                    dst = b["jump"]
                    r2.gets(elf, "s 0x%x" % dst)
                    branch = r2.get(elf, "pdj 1")[0]
                    self.finish_ins_addr = branch["offset"] + branch["size"]
                else:
                    branch = b
                    jump = branch["jump"]
                    if jump not in [ii["offset"] for ii in self.bbs]:
                        self.finish_ins_addr = jump
                        #if not self.branch_ins_addr:
                        #    self.start_ins_addr = self.finish_ins_addr
                    else:
                        self.finish_ins_addr = branch["offset"] + branch["size"]
                        #if not self.branch_ins_addr:
                        #    self.write_ins_addr


        r2.gets(elf, "s 0x%x" % self.finish_ins_addr)
        self.finish_ins = r2.get(elf, "pdj 1")[0]
        #r2.gets(elf, "s 0x%x" % self.branch_ins_addr)
        #self.branch_ins = r2.get(elf, "pdj 1")[0]
        #if not self.start_ins_addr:
        #    self.start_ins_addr = self.branch_ins["jump"]
        self.start_ins_addr = self.write_ins_addr
        self.start_ins = self.write_ins
        #r2.get(elf, "s 0x%x" % self.start_ins_addr)
        #self.start_ins = r2.get(elf, "pdj 1")[0]

        #r2.gets(elf, "s 0x%x" % addr)
        #self.bbs = r2.get(elf,"pdbj")



        # if self.branch_ins["jump"] < self.branch_ins["offset"]:
        #     # if this branches backwards, then the copying is finished once the next instruction is executed
        #     if self.branch_ins["type"] == "cjmp":  # if conditional jump
        #         self.valid = True
        #         self.finish_ins_addr = self.branch_ins["offset"] + self.branch_ins["size"]
        #     else:
        #         self.finish_ins_addr = None

        # else:
        #     # otherwise destination of branch indicates test to determine if it is finished with loop
        #     if self.branch_ins["type"] == "jmp":  # if not conditional jump
        #         dst = self.branch_ins["jump"]
        #         r2.gets(elf, "s 0x%x" % dst)
        #         bb = r2.get(elf, "pdbj")
        #         r2.gets(elf, "pdb")
        #         for i in bb:
        #             if i["type"] == "cjmp":
        #                 jump = i["jump"]
        #                 offset = i["offset"]
        #                 self.branch_ins = i
        #                 self.valid = True
        #                 if jump not in [ii["offset"] for ii in self.bbs]:
        #                     # if does not jump back into loop
        #                     self.finish_ins_addr = jump
        #                 else:
        #                     # where it goes if it fails is the next instruction
        #                     self.finish_ins_addr = offset + i["size"]
        #                 break
        #             elif i["type"] == "jmp":
        #                 break



    def __repr__(self):
        if not self.valid:
            return "<invalid longwrite @ 0x%x>" % self.start_ins_addr
        else:
            return "<longwrite [start=0x%x,write=0x%x,done=0x%x]>" % (self.start_ins_addr, self.write_ins_addr, self.finish_ins_addr)

#    def __repr__(self):
#        return str(self)

def longwrite_info(elf, addr, thumb):
    l = LongWriteInfo(elf, start, end, thumb)
    return l

def analyze(elf):
    r2.get(elf, "aas")
    tsts = [(0x40208b6e, True),
             (0x402025c0, False), # bss
             (0x40208b24, True), # memset
            # (0x40208b30, True), # memset, just 8 bits at most
             (0x40208b50, True), # memcpy
            (0x40206de0, True)] # mmc_read_data

    #for i in tsts:
    #    l = longwrite_info(elf, i[0], i[1])
    #    print l

    tsts = [(0x40208b1e, 0x40208b20, True), # memset
            (0x40208b50, 0x40208b54, True), # memcpy
            (0x40206dd6, 0x40206dde, True), # mmc_read_data
            (0x402025c4, 0x402025c8, False) # clearbss
    ] # mmc_read_data
    for i in tsts:
        l = LongWriteInfo(elf, *i)
        print l



def run():
    if len(sys.argv) < 2:
        exit(0)
    elf = sys.argv[1]
    analyze(elf)

if __name__ == "__main__":
    run()


#     / (fcn) sym._main_finish 56
# |   sym._main_finish ();
# |           ; CALL XREF from 0x40201436 (sym.board_init_f)
# |           0x402025a4      610400fa       blx sym.spl_relocate_stack_gd
# |           0x402025a8      000050e3       cmp r0, 0
# |           0x402025ac      00d0a011       movne sp, r0
#             ;-- $d:
# |       ,=< 0x402025b0      ffffffea       b sym.clear_bss
#         |   ;-- clear_bss:
# |       |   ; CALL XREF from 0x402008ac (loc._d_21)
# |       `-> 0x402025b4      24009fe5       ldr r0, [0x402025e0]        ; [0x402025e0:4]=0x80000000 obj.__bss_start
# |           0x402025b8      24109fe5       ldr r1, [0x402025e4]        ; [0x402025e4:4]=0x80030144 obj.__bss_end
# |           0x402025bc      0020a0e3       mov r2, 0
#             ;-- clbss_l:
# |       .-> 0x402025c0      010050e1       cmp r0, r1
# |       :   0x402025c4      00208035       strlo r2, [r0]
# |       :   0x402025c8      04008032       addlo r0, r0, 4
# |       `=< 0x402025cc      fbffff3a       blo loc.clbss_l
# |           0x402025d0      0900a0e1       mov r0, sb
# |           0x402025d4      2c1099e5       ldr r1, [sb, 0x2c]
# \           0x402025d8      08f09fe5       ldr pc, [0x402025e8]        ; [0x402025e8:4]=0x40203685


# / (fcn) sym.memcpy 60
# |   sym.memcpy ();
# |           ; XREFS: CALL 0x40204ad2  CALL 0x40204b04  CALL 0x402061b4
# |           ; XREFS: CALL 0x40207a02  CALL 0x40207a7c  CALL 0x40207bc2
# |           ; XREFS: CALL 0x40207bf8  CALL 0x40207c2a  CALL 0x40207dc4
# |           ; XREFS: CALL 0x40208110  CALL 0x402081b4  CALL 0x402081d2
# |           ; XREFS: CALL 0x4020827e  CALL 0x402084ea  CALL 0x40208bee
# |           ; XREFS: CALL 0x40208bf8
# |           0x40208b3c      8842           cmp r0, r1
# |       ,=< 0x40208b3e      1ad0           beq 0x40208b76
# |       |   0x40208b40      10b4           push {r4}
# |       |   0x40208b42      40ea0103       orr.w r3, r0, r1
# |       |   0x40208b46      13f0030f       tst.w r3, 3                 ; 3
# |      ,==< 0x40208b4a      07d0           beq 0x40208b5c
# |      ||   0x40208b4c      0346           mov r3, r0
# |     ,===< 0x40208b4e      0ee0           b 0x40208b6e
# |    .----> 0x40208b50      0c68           ldr r4, [r1]
# |    :|||   0x40208b52      1c60           str r4, [r3]
# |    :|||   0x40208b54      043a           subs r2, 4
# |    :|||   0x40208b56      0431           adds r1, 4
# |    :|||   0x40208b58      0433           adds r3, 4
# |   ,=====< 0x40208b5a      00e0           b 0x40208b5e
# |   |:|`--> 0x40208b5c      0346           mov r3, r0
# |   |:| |   ; CODE XREF from 0x40208b5a (sym.memcpy)
# |   `-----> 0x40208b5e      032a           cmp r2, 3                   ; 3
# |    `====< 0x40208b60      f6d8           bhi 0x40208b50
# |     |,==< 0x40208b62      04e0           b 0x40208b6e
# |    .----> 0x40208b64      0a78           ldrb r2, [r1]
# |    :|||   0x40208b66      1a70           strb r2, [r3]
# |    :|||   0x40208b68      2246           mov r2, r4
# |    :|||   0x40208b6a      0131           adds r1, 1
# |    :|||   0x40208b6c      0133           adds r3, 1
# |    :|||   ; CODE XREF from 0x40208b4e (sym.memcpy)
# |    :|||   ; CODE XREF from 0x40208b62 (sym.memcpy)
# |    :``--> 0x40208b6e      541e           subs r4, r2, 1
# |    :  |   0x40208b70      002a           cmp r2, 0
# |    `====< 0x40208b72      f7d1           bne 0x40208b64
# |       |   0x40208b74      10bc           pop {r4}
# \       `-> 0x40208b76      7047           bx lr
# [0x40208b3c]>
