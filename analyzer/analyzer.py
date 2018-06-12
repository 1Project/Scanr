#!/usr/bin/python2
import re
# import disassembler engine
from disassembler.disassembler import *
# import emulator engine
from emulator.emulator import *


class AnalyzerEngine(object):
    BACKREF = 0x10

    OFFS_DB = (
        re.compile(r"\xE8.?\x00\x00\x00"),
        re.compile(r"\xE8\xFF\xFF\xFF"),
        re.compile(r"\x90\x90\x90\x90"),
        re.compile(r"\xD9\x74\x24[\x80-\xFF]"),
        re.compile(r"\xD9[\x70-\x7F]\x00\x00"),
        re.compile(r"\xEB\x5A"),
        re.compile(r"\xEB\x0C"),
        re.compile(r"\x64[\xA0-\xAF]\x30\x00\x00\x00"),
        re.compile(r"\xd9[\x70-\x7F][\x80-\xFF]"),
    )

    def get_offsets(self, code):
        offsets = list()
        match_list = list()

        for o in self.OFFS_DB:
            m = re.search(o, code)
            if m is not None:
                match_list.append(m)
        for m in match_list:
            offsets.append(max(0, m.start() - self.BACKREF))

        # heur match found nothing
        if len(offsets) == 0:
            offsets.append(0)

        return offsets

    def analyze(self, code, offset=0):
        self.emulator.emulate(code, offset=offset)

    def __init__(self, mode=32, debug=False):
        self.mode = mode
        self.debug = debug
        self.disassembler = DisassemblerEngine(self.mode)
        self.emulator = EmulatorEngine(
            self.disassembler, self.mode, self.debug)
