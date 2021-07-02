#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIpAddr = blasterIp
        self.blasteeIpAddr = "192.168.100.1"
        self.blasterEthAddr = "10:00:00:00:00:01"
        self.blasteeEthAddr = "20:00:00:00:00:01"
        self.myNum = num
        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        
        my_pkt = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        my_pkt[UDP].src = 4444
        my_pkt[UDP].dst = 5555
        # my_pkt += b'These are some application data bytes'

        my_pkt[Ethernet].src = self.blasteeEthAddr
        my_pkt[Ethernet].dst = self.blasterEthAddr

        my_pkt[IPv4].src = self.blasteeIpAddr
        my_pkt[IPv4].dst = self.blasterIpAddr
        # blaster packet format
        # <------- Switchyard headers -----> <----- Your packet header(raw bytes) ------> <-- Payload in raw bytes --->
        # -------------------------------------------------------------------------------------------------------------
        # |  ETH Hdr |  IP Hdr  |  UDP Hdr  | Sequence number(32 bits) | Length(16 bits) |   Variable length payload  |
        # -------------------------------------------------------------------------------------------------------------
        # debugger()
        sequence = struct.pack(">4s", packet[3].to_bytes()[0:4])
        payload = struct.pack(">8s", packet[3].to_bytes()[6:14])

        my_pkt += sequence
        my_pkt += payload

        log_info(f"Sending packet from blastee to blaster, pkt info {my_pkt}")
        self.net.send_packet(fromIface, my_pkt)


    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
