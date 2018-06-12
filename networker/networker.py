#!/usr/bin/python2
import re
import pcap
import dpkt
import time
# import disassembler engine
from disassembler.disassembler import *
# import emulator engine
from emulator.emulator import *


class Networker(object):
    def analyzeInterface(self, interface):
        pass

    def analyzeCapture(self, capture):
        pcap_reader = dpkt.pcap.Reader(capture)
        conn = {}

        for ts, buf in pcap_reader:
            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)
            # It this an IP packet?
            if not isinstance(eth.data, dpkt.ip.IP):
                print '[-] Error: Non IP Packet type, not supported %s\n' % eth.data.__class__.__name__
                continue

            # Grab ip packet
            ip = eth.data

            # Pull out fragment information
            df = bool(ip.off & dpkt.ip.IP_DF)
            mf = bool(ip.off & dpkt.ip.IP_MF)
            offset = ip.off & dpkt.ip.IP_OFFMASK

            # It this a TCP packet?
            if not isinstance(ip.data, dpkt.tcp.TCP):
                print '[-] Error: Non TCP Packet type, not supported %s\n' % eth.data.__class__.__name__
                continue

            tcp = ip.data
            tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
            if tupl in conn:
                conn[tupl] = conn[tupl] + tcp.data
            else:
                conn[tupl] = tcp.data

        for k in conn:
            # Try and parse what we have
            try:
                stream = conn[k]
                if stream[:4] == 'HTTP':
                    http = dpkt.http.Response(stream)
                    # print http.status
                else:
                    http = dpkt.http.Request(stream)
                    # print http.method, http.uri

            except dpkt.UnpackError:
                pass

        return str(http)

    def __init__(self, debug=False):
        self.fromFile, self.fromInterface = False, False
