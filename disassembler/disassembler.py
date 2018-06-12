#!/usr/bin/python
# import disassemble engine
from capstone import *


class DisassemblerEngine(object):
    BASE_ADDR = 0

    def __init__(self, mode=32):
        if mode == 32:
            cur_mode = CS_MODE_32
        elif mode == 16:
            cur_mode = CS_MODE_16
        elif mode == 64:
            cur_mode = CS_MODE_64
        else:
            raise Exception('Unspecified mode for the Disassembler Engine')

        self.capmd = Cs(CS_ARCH_X86, cur_mode)

    def get_disas_single(self, data, offs=0, addr=BASE_ADDR):
        for (address, size, mnemonic, op_str) in self.capmd.disasm_lite(data[offs:], self.BASE_ADDR):
            return (addr, size, mnemonic, op_str)

    def disas_single(self, data, offs=0):
        for (address, size, mnemonic, op_str) in self.capmd.disasm_lite(data[offs:], self.BASE_ADDR):
            print("  0x%-4x:\t%s\t%s" % (address, mnemonic, op_str))
            break

    def get_disas_n(self, data, n, offs=0):
        return self.capmd.disasm_lite(data[offs:], self.BASE_ADDR, count=n)

    def disas_n(self, data, n, offs=0):
        for (address, size, mnemonic, op_str) in self.capmd.disasm_lite(data[offs:], self.BASE_ADDR, count=n):
            print("  0x%-4x:\t%s\t%s" % (address, mnemonic, op_str))
            break

    def disas_all(self, data, offs=0):
        for (address, size, mnemonic, op_str) in self.capmd.disasm_lite(data[offs:], self.BASE_ADDR):
            print("  0x%-4x:\t%s\t%s" % (address, mnemonic, op_str))

    def get_disas_all(self, data, offs=0):
        for (address, size, mnemonic, op_str) in self.capmd.disasm_lite(data[offs:], self.BASE_ADDR):
            yield (address, size, mnemonic, op_str)
