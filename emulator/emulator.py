#!/usr/bin/python

from __future__ import print_function
# import emu engine and disassembler
from unicorn import *
from unicorn.x86_const import *
from disassembler.disassembler import *
# import tools
from utils.utils import *
# other imports
import sys
import binascii
import struct

# globals for the hooks
write_bound_high = None
write_bound_low = None


def print_registers(uc):
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)
    ebp = uc.reg_read(UC_X86_REG_EBP)

    print('[!] Registers:')
    print('\teip: %x, esp: %x, ebp: %x' % (eip, esp, ebp))


def mem_reader(uc, addr, size):
    tmp = uc.mem_read(addr, size)

    print('\t\t', end='')
    for i in tmp:
        print("%.2x " % i, end=''),


def hook_intr(uc, intno, user_data):
    if intno == 0x3:
        return False
    else:
        return True


def hook_mem_invalid(uc, access, address, size, value, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)

    if access == UC_MEM_WRITE:
        print("\tinvalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" %
              (address, eip, size, value))
    if access == UC_MEM_READ:
        print("\tinvalid READ of 0x%x at 0x%X, data size = %u" %
              (address, eip, size))

    return False


def hook_mem_unmapped(uc, access, address, size, value, user_data):
    eip = uc.reg_read(UC_X86_REG_EIP)

    if access == UC_MEM_WRITE:
        print("\tinvalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" %
              (address, eip, size, value))
    if access == UC_MEM_READ:
        print("\tinvalid READ of 0x%x at 0x%X, data size = %u" %
              (address, eip, size))

    return False


class EmulatorEngine(object):
    # initialization of system structures
    STRUCTURES_X86 = dict()
    STRUCTURES_X86['FS_0'] = 0
    STRUCTURES_X86['TEB'] = STRUCTURES_X86['FS_0'] + 0x18
    STRUCTURES_X86['PEB'] = STRUCTURES_X86['FS_0'] + 0x30
    STRUCTURES_X86['PEB_Ldr'] = STRUCTURES_X86['PEB'] + 0x0C
    STRUCTURES_X86['PEB_Ldr_InLoadOrder'] = STRUCTURES_X86['PEB_Ldr'] + 0x0C
    STRUCTURES_X86['PEB_Ldr_InMemOrder'] = STRUCTURES_X86['PEB_Ldr'] + 0x14
    STRUCTURES_X86['PEB_Ldr_InInitOrder'] = STRUCTURES_X86['PEB_Ldr'] + 0x1C

    EMU_ESP = 0x500
    EMU_EBP = EMU_ESP = 0x8
    EMU_MAX_INSTRUCTIONS = 0x1000
    SC_MAX_LENGTH = 0x2000
    SC_OFFSET = 0x2000
    SMC_BOUND = 0x200
    BASE_ADDR = 0

    @property
    def heur_level(self):
        return self.__heur_level

    @heur_level.setter
    def heur_level(self, value):
        self.__heur_level = value
        if (self.__heur_level >= self.max_heur_level):
            if self.stop:
                self.emu_engine.emu_stop()
                return False

            print('[!] HEUR level %d, shellcode detected. Exiting!' %
                  self.__heur_level)
            self.stop = True
            self.emu_engine.emu_stop()
            return False

    def hook_smc_check(self, uc, access, address, size, value, user_data):
        eip = uc.reg_read(UC_X86_REG_EIP)
        global write_bound_high, write_bound_low
        # Just check if the write target addr is near EIP
        if abs(eip - address - self.BASE_ADDR) < self.SMC_BOUND:
            print('[!] Self-modyfying code heuristic triggered!')
            self.heur_level += 0

            if write_bound_low is None:
                write_bound_low = address
                write_bound_high = address
            elif address < write_bound_low:
                write_bound_low = address
            elif address > write_bound_high:
                write_bound_high = address

    def hook_code(self, uc, addr, size, user_data):
        if self.stop:
            self.emu_engine.emu_stop()
            return False

        mem = uc.mem_read(addr, size)
        offs = 0
        (address, size, mnemonic, op_str) = self.disasm_engine.get_disas_single(
            str(mem), offs, addr=addr
        )
        print("  0x%x:\t%s\t%s" % (address, mnemonic, op_str))
        if (self.previous_instruction == 'call' and mnemonic == 'pop'):
            print('[!] GetPC (callpop) heuristic triggered!')
            self.heur_level += 1
        if (mnemonic == 'fnstenv'):
            print('[!] GetPC (fnstenv) heuristic triggered!')
            self.heur_level += 1
        self.previous_instruction = mnemonic
        self.previous_instruction_addr = struct.pack("<I", addr - 2)
        # print_registers(uc)
        return True

    def hook_mem_read(self, uc, access, address, size, value, user_data):
        if self.stop:
            self.emu_engine.emu_stop()
            return False

        if (address in self.STRUCTURES_X86.values()):
            print('')
            for k, v in self.STRUCTURES_X86.iteritems():
                if address == v:
                    print('[!] %s accessed!' % k)
                    self.heur_level += 1

        print("\tmem READ:  0x%x, data size = %u, data value = 0x%x" %
              (address, size, value))
        print("\tnear deref:")
        mem_reader(uc, address, 0x10)
        print('')

        return True

    def emulate(self, sc, offset=0):
        sc = sc[offset:offset + self.SC_MAX_LENGTH]
        self.emu_engine.mem_write(self.BASE_ADDR + self.SC_OFFSET, sc)
        # limit emulation by issuing int 3 breakpoint
        self.emu_engine.mem_write(
            self.BASE_ADDR + self.SC_MAX_LENGTH + len(sc), "\xCC\xCC\xCC\xCC")
        # emulation start
        print("[*] Emulator processing shellcode")
        # -1 for unlimited emulation
        self.emu_engine.emu_start(
            self.BASE_ADDR + self.SC_OFFSET, self.BASE_ADDR + self.SC_MAX_LENGTH + len(sc), 0, self.EMU_MAX_INSTRUCTIONS)
        print("[+] Processed!")

        if self.debug:
            # if shellcode is self modifying
            global write_bound_high, write_bound_low
            if write_bound_low is not None:
                print("\tShellcode address ranges:")
                print("\t   low:  0x%X" % write_bound_low)
                print("\t   high: 0x%X" % write_bound_high)
                print('')
                print("\tDecoded shellcode:")
                mem = self.emu_engine.mem_read(
                    self.BASE_ADDR + write_bound_low, (write_bound_high - write_bound_low))
                self.emu_engine.disasm.disas_all(str(mem))
            else:
                print('[-] Error decoding, no encoder detected')

    def __init__(self, disassembler, mode=32, debug=True, heur_level=3):
        self.stop = False
        self.max_heur_level = heur_level
        self.__heur_level = 0
        self.previous_instruction = ''
        self.debug = debug
        self.disasm_engine = disassembler
        # x86 32-bit mode for now
        self.emu_engine = Uc(UC_ARCH_X86, UC_MODE_32)
        self.emu_engine.disasm = self.disasm_engine
        self.emu_engine.mem_map(
            self.BASE_ADDR, 2 * 0x1000 * 0x1000
        )

        # map needed x86 structures to memory
        for k, v in self.STRUCTURES_X86.iteritems():
            self.emu_engine.mem_write(self.BASE_ADDR + v, p32(v))

        # add our custom emu hooks
        self.emu_engine.hook_add(UC_HOOK_MEM_READ, self.hook_mem_read)
        self.emu_engine.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
        self.emu_engine.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)
        self.emu_engine.hook_add(UC_HOOK_MEM_WRITE, self.hook_smc_check)
        self.emu_engine.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_unmapped)
        self.emu_engine.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)
        self.emu_engine.hook_add(UC_HOOK_INTR, hook_intr)

        if self.debug:
            self.emu_engine.hook_add(UC_HOOK_CODE, self.hook_code)

        # initialization of registers
        self.emu_engine.reg_write(
            UC_X86_REG_ESP, self.BASE_ADDR + self.EMU_ESP)
        self.emu_engine.reg_write(
            UC_X86_REG_EBP, self.BASE_ADDR + self.EMU_EBP)
        self.emu_engine.reg_write(
            UC_X86_REG_FS, self.BASE_ADDR)
