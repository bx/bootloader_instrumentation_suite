from capstone import *
from capstone.arm import *
import re

# analyze instruction to figure out what
# registers we need to calculate write destination
# and also calculate destination for us given reg values
class InstructionAnalyzer():
    WORD_SIZE = 4
    writemnere = re.compile("(push)|(stm)|(str)|(stl)|(stc)")

    def __init__(self):
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.thumb.detail = True
        # self.thumb.skipdata = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.arm.detail = True
        # self.arm.skipdata = True
        self.cache = {}

    def disasm(self, value, thumb, pc, cache=False):
        offset = pc
        ins = None
        if cache and pc in self.cache.iterkeys():
            return self.cache[pc]
        if thumb:
            ins = self.thumb.disasm(value, offset, count=1)
        else:
            ins = self.arm.disasm(value, offset, count=1)
        try:
            i = next(ins)
        except StopIteration as i:
            print "-%x %s '%s'-" % (pc, thumb, value.encode('hex'))
            raise i

        if cache:
            self.cache[pc] = i
        return i

    def is_instr_memstore(self, ins):
        return self.is_mne_memstore(ins.mnemonic)

    def get_flag_value(self, flag, cpsr):
        flags = {'n': (1 << 31), 'z': (1 << 30), 'c': (1 << 29), 'v': (1 << 28), 'q': (1 << 27)}
        return True if ((cpsr & flags[flag]) == flags[flag]) else False

    # inclase there is a conditional store check
    def store_will_happen(self, ins, regs):
        if self.has_condition_suffix(ins):
            cc = ins.cc
            cpsr = regs[-1]
            if cc == 0:
                # eq
                return self.get_flag_value('z', cpsr) is True
            elif cc == 1:
                # not equal, ne
                return self.get_flag_value('z', cpsr) is False
            elif cc == 2:
                # carry set, hs
                return self.get_flag_value('c', cpsr) is True
            elif cc == 3:
                # lo, cary clear
                return self.get_flag_value('c', cpsr) is False
            elif cc == 4:
                # mi,
                return self.get_flag_value('n', cpsr) is True
            elif cc == 5:
                # pl
                return self.get_flag_value('n', cpsr) is False
            elif cc == 6:
                # vs
                return self.get_flag_value('v', cpsr) is True
            elif cc == 7:
                return self.get_flag_value('v', cpsr) is False
                # vc
            elif cc == 8:
                # hi
                return (self.get_flag_value('c', cpsr) is True) \
                    and (self.get_flag_value('z', cpsr) is False)
            elif cc == 9:
                # ls
                return (self.get_flag_value('c', cpsr) is False) \
                    or (self.get_flag_value('z', cpsr) is True)
            elif cc == 10:
                # ge
                return (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr))
            elif cc == 11:
                # lt
                return not (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr))
            elif cc == 12:
                # gt
                return (self.get_flag_value('z', cpsr) is False) \
                    and (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr))
            elif cc == 13:
                # le
                return (self.get_flag_value('z', cpsr) is True) \
                    or (not (self.get_flag_value('n', cpsr) == self.get_flag_value('v', cpsr)))
            else:
                return True
        else:
            return True

    def is_thumb(self, cpsr):
        CPSR_THUMB = 0x20
        return True if (cpsr & CPSR_THUMB) == CPSR_THUMB else False  # if cpsr bit 5 is set

    def calculate_store_offset(self, ins, regs):
        if self.has_condition_suffix(ins):
            # strip off cpsr
            regs = regs[:-1]
        operands = ins.operands
        lshift = 0
        disp = 0
        for i in operands:
            if i.type == ARM_OP_MEM:
                lshift = i.mem.lshift
                disp = i.mem.disp
        if lshift > 0:
            regs[1] = (regs[1] << lshift) % (0xFFFFFFFF)

        return (sum(regs) + disp) % (0xFFFFFFFF)

    @classmethod
    def has_condition_suffix(cls, ins):
        # strip off '.w' designator if it is there, it just means
        # its a 32-bit Thumb instruction
        return ins.cc not in [ARM_CC_AL, ARM_CC_INVALID]

    @classmethod
    def calculate_store_size(cls, ins):
        mne = ins.mnemonic.encode("ascii")
        if mne.startswith('push') or mne.startswith('stl'):
            (read, write) = ins.regs_access()
            # cannot push sp value, so if it is in this list don't
            # include it in the count
            if 12 in read:
                read.remove(12)
            return -1*len(read)*InstructionAnalyzer.WORD_SIZE
        elif mne.startswith('stm'):  # stm gets converted to push, but just in case
            (read, write) = ins.regs_access()
            return (len(read) - 1)*InstructionAnalyzer.WORD_SIZE
        elif mne.startswith('str'):
            # strip off '.w' designator if it is there, it just means
            # its a 32-bit Thumb instruction
            if mne[-1] == 'w':
                mne = mne[:-1]
                if mne[-1] == '.':
                    mne = mne[:-1]

            # strip of any condition suffixes
            if cls.has_condition_suffix(ins):
                # remove last 2 chars
                mne = mne[:-2]

            # remove a final t if it is there
            if mne[-1] == 't':
                mne = mne[:-1]
            # now check to see how many bytes the instruction operates on
            if mne == 'str':
                return InstructionAnalyzer.WORD_SIZE
            elif mne[-1] == 'b':
                return 1
            elif mne[-1] == 'h':
                return InstructionAnalyzer.WORD_SIZE/2
            elif mne[-1] == 'd':
                return InstructionAnalyzer.WORD_SIZE*2
            else: # strex
                return InstructionAnalyzer.WORD_SIZE
        elif mne.startswith('stc'):
            if 'L' in mne:
                return InstructionAnalyzer.WORD_SIZE*8
            else:
                return InstructionAnalyzer.WORD_SIZE
        else:
            print "Do not know how to handle instruction mnemonic %s at %x (%x)" \
                % (ins.mnemonic, ins.address, 0)
            return -1
    @classmethod
    def needed_regs(cls, ins):
        regs = []
        if ins.id == 0:
            print "NO DATA!"
            return []
        if ins.mnemonic.startswith("push"):
            regs = ['sp']
        elif ins.mnemonic.startswith("stl") or ins.mnemonic.startswith("stm"):
            # stl is actually treated by capstone as push instruction
            # but we will check just in case
            # similar to push, first operand only
            regs = [ins.reg_name(ins.operands[0].reg).encode('ascii')]
        elif ins.mnemonic.startswith("str") or ins.mnemonic.startswith("stc"):
            readops = []
            for i in ins.operands:
                if i.type == ARM_OP_MEM:
                    if len(readops) > 0:
                        print "multiple mem operators? We can't handle this!"
                        return []
                    if i.mem.base != 0:
                        readops.append(ins.reg_name(i.mem.base).encode('ascii'))
                    if i.mem.index != 0:
                        readops.append(ins.reg_name(i.mem.index).encode('ascii'))
            regs = readops
        if cls.has_condition_suffix(ins):
            regs.append('cpsr')
        return regs

    @classmethod
    def _is_mne_memstore(cls, mne):
        return InstructionAnalyzer.writemnere.match(mne) is not None

    def is_mne_memstore(self, mne):
        return self._is_mne_memstore(mne)
