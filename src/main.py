# *_*coding:utf-8 *_*

import socket as s
import os
import struct
import fcntl
import sched
import time
import random,sys
from select import select
from threading import Timer
from collections import Counter
from rawethernet import EthFrame
from rawip import IPDatagram
from rawtcp import TCPSegment


class PortScan:
    def __init__(self, iface, gateway_mac, sip, sport):
        print "begin to init software"
        self.socket = s.socket(s.AF_PACKET, s.SOCK_RAW)
        self.socket.bind((iface, s.SOCK_RAW))
        self.sip = s.inet_aton(sip)
        self.sport = sport
        self.scans = {}

        self.smac = self._get_local_mac(iface)
        print "get source mac over"
        self.ip_gateway = self._get_gateway_ip(iface)
        print "get gateway ip over:{}".format(s.inet_ntoa(self.ip_gateway))
        self.mac_gateway = gateway_mac
        self._get_gateay_mac()
        print "get gateway mac over"

        print("End init")

    def timeout(self, key):
        #print "check timeout"
        print "{} is closed".format(key)
        del self.scans[key]

    def send(self,addr, syn = 0, rst = 0):
        dip,dport = addr
        dip = s.inet_aton(dip)
        if syn == 1:
            key = "{0}:{1}".format(addr[0], addr[1])
            self.scans[key] = Timer(3, self.timeout, (key, ))
            self.scans[key].start()
    
        tcp_segment = TCPSegment(ip_src_addr=self.sip,
                                 ip_dest_addr=dip,
                                 tcp_src_port=self.sport,
                                 tcp_dest_port=dport,
                                 tcp_seq=random.randint(0x0001, 0xffff),
                                 tcp_ack_seq=0,
                                 tcp_furg=0, tcp_fack=0, tcp_fpsh=0,
                                 tcp_frst=rst, tcp_fsyn=syn, tcp_ffin=0,
                                 tcp_adwind=65535, data="")
        ip_data = tcp_segment.pack()
        # build IP datagram
        ip_datagram = IPDatagram(ip_src_addr=self.sip,
                                 ip_dest_addr=dip,
                                 data=ip_data)
        eth_data = ip_datagram.pack()
        # build Ethernet Frame
        eth_frame = EthFrame(dest_mac=self.mac_gateway,
                             src_mac=self.smac,
                             data=eth_data)
        phy_data = eth_frame.pack()
        # send raw data
        return self.socket.send(phy_data)

    def recv(self):
        bufsize = 1500
        print "recv_packet"
        while True:
            # wait with timeout for the readable socket
            if len(self.scans) == 0:
                print "ip set is Empty"
                #time.sleep(1.0)
                break
            rsock, wsock, exsock = select([self.socket], [], [], 1.0)
            # socket is ready to read, no timeout
            if self.socket in rsock:
                # process Ethernet frame
                phy_data = self.socket.recv(bufsize)
                eth_frame = EthFrame()
                eth_frame.unpack(phy_data)
                # process IP datagram
                eth_data = eth_frame.data
                ip_datagram = IPDatagram('', '')
                ip_datagram.unpack(eth_data)

                if ip_datagram.ip_proto == 6:
                    tcp_segment = TCPSegment('', '')
                    tcp_segment.unpack(ip_datagram.data)
                    src_ip = s.inet_ntoa(ip_datagram.ip_src_addr)
                    dest_ip = s.inet_ntoa(ip_datagram.ip_dest_addr)
                    src_port = tcp_segment.tcp_src_port
                    dest_port = tcp_segment.tcp_dest_port
                    self.check_ip(src_ip, src_port)
    def check_ip(self, ip, port):
        key = "{0}:{1}".format(ip, port)
        if self.scans.get(key):
            print "{} is open".format(key)
            self.scans[key].cancel()
            del self.scans[key]

    def _get_local_mac(self, iface):
        '''
        Get tge mac address of the local interface
        NOTE: MAC address already encoded
        '''
        try:
            mac = fcntl.ioctl(self.socket.fileno(), 0x8927,
                              struct.pack('256s', iface[:15]))[18:24]
            return mac
        except IOError:
            raise RuntimeError('Cannot get mac address of local interface %s'
                               % iface)

    def _get_gateway_ip(self, iface):
        '''
        Look up the gateway IP address from /proc/net/route
        '''
        with open('/proc/net/route') as route_info:
            for line in route_info:
                fields = line.strip().split()
                if fields[0] == iface and fields[1] == '00000000':
                    return struct.pack('<L', int(fields[2], 16))
            else:
                raise RuntimeError('Cannot find the default gateway Ip ' +
                                   'address in /proc/net/route, please ' +
                                   'pass the correct network interface name')
    def _get_gateay_mac(self):
        mac_bytes = self.mac_gateway.split(":")
        if len(mac_bytes) == 6:
            self.mac_gateway = struct.pack("!6B",
                                          int(mac_bytes[0], 16) ,
                                          int(mac_bytes[1], 16) ,
                                          int(mac_bytes[2], 16) ,
                                          int(mac_bytes[3], 16) ,
                                          int(mac_bytes[4], 16) ,
                                          int(mac_bytes[5], 16) )
            return True
        return False




if __name__ == "__main__":

    obj = PortScan('eth0', 'ee:ff:ff:ff:ff:ff', '172.17.42.150', 7001)
    if len(sys.argv) > 1:
        obj.send((sys.argv[1], int(sys.argv[2])), syn = 1)
    obj.recv()
