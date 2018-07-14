# from https://gist.github.com/moyix/669344f534c83e0704e0
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *


class UnicornCPU(object):
    def __init__(self, arch):
        # Prevent infinite recursion
        super(UnicornCPU, self).__setattr__('arch', arch)

    def get_reg_name_val(self, name):
        name = name.upper()
        reg_name = 'UC_' + self.arch + '_REG_' + name
        try:
            reg_name_val = globals()[reg_name]
        except KeyError:
            raise AttributeError(reg_name)
        return reg_name_val

c = UnicornCPU("ARM")

def reg_val_of(cpu, name):
    c = UnicornCPU(cpu)
    return c.get_reg_name_val(name)

def reg_val(name):
    global c
    return c.get_reg_name_val(name)
