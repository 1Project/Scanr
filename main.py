#!/usr/bin/python
from __future__ import print_function
# other imports
import argparse
import struct
import sys
import time
# import main analyzer engine
from analyzer.analyzer import *
from networker.networker import *


def analyzeObject(sc, capture=None, interface=None, start_offset=0, limit=0x1000, debug=False):
    MAX_OFFSETS = 0x10

    analyzer = AnalyzerEngine(mode=32, debug=debug)
    offsets = analyzer.get_offsets(sc)
    if offsets:
        print('[+] Found %d potential offsets:' % len(offsets))
        if len(offsets) > MAX_OFFSETS:
            print('[!] Potential offsets (%d) is greater than the current MAX_OFFSETS (%d)!' % (
                len(offsets), MAX_OFFSETS))
        for offset in offsets[:MAX_OFFSETS]:
            print('\t0x%08x' % offset)
           # print('\t\t', end=' ')
            analyzer.disassembler.disas_all(sc, offset)

    for i, offset in enumerate(offsets):
        try:
            print('[!] Trying with offset number %d at 0x%08x' % (i, offset))
            analyzer.analyze(sc, offset)
        except UcError as uce:
            # print_registers(self.emu_engine)
            print("[-] Emulator error: %s" % uce)
        except Exception as e:
            print("[-] ERROR: %s" % e)


def main(obj_path=None, capture=None, interface=None, start_offset=0, limit=0x1000, debug=False):
    mode = None
    before = time.time()
    if obj_path:
        print('[!] Starting analysis in file mode')
        print('[*] Analyzing file %s' % obj_path)
        obj = obj_path.read()
        analyzeObject(obj, start_offset=start_offset,
                      limit=limit, debug=debug)
    elif capture:
        print('[!] Starting analysis in capture mode')
        print('[*] Analyzing capture %s' % capture)
        net = Networker(debug=debug)
        obj = net.analyzeCapture(capture)
        analyzeObject(obj, start_offset=start_offset,
                      limit=limit, debug=debug)
    elif interface:
        print('[!] Starting analysis in live capture mode')
        print('[*] Analyzing capture from %s interface' % interface)
        pass
    else:
        print('[-] Error: You have to specify file, capture or interface!')
        sys.exit(1)

    after = time.time()
    print('[+] Finished analysis, took %f seconds' % (after - before))


if __name__ == '__main__':
    # parse input argument
    parser = argparse.ArgumentParser(
        description='Windows shellcode emulation and detection tool')
    parser.add_argument('-f', dest='obj_path',
                        help='input file', type=file, required=False)
    parser.add_argument('-o', dest='start_offset',
                        help='shellcode start offset', required=False, default=0, type=int)
    parser.add_argument('-l', dest='limit', help='max instructions to analyze',
                        required=False, default=-1, type=int)
    parser.add_argument('-d', dest='debug', help='enable debug mode',
                        required=False, default=False, action='store_true')
    parser.add_argument('-i', dest='interface', help='network interface',
                        type=str, required=False)
    parser.add_argument('-c', dest='capture', help='network capture',
                        type=file, required=False)

    arguments = parser.parse_args()
    main(obj_path=arguments.obj_path, interface=arguments.interface, capture=arguments.capture, start_offset=arguments.start_offset,
         limit=arguments.limit, debug=arguments.debug)
