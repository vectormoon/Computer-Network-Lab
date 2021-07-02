#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

from struct import pack


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.LHS = 1
        self.RHS = 1
        self.senderWindow = int(senderWindow)
        self.length = int(length)
        self.num = int(num)
        self.timeout = (int(timeout) / 1000)
        self.recvTimeout = (int(recvTimeout) / 1000)
        # host info
        self.blasterIpAddr = "192.168.200.1"
        self.blasteeIpAddr = "192.168.100.1"
        self.blasterEthAddr = "10:00:00:00:00:01"
        self.blasteeEthAddr = "20:00:00:00:00:01"
        # statistics about the transmission
        self.Total_TX_time = 0
        self.Number_of_reTX = 0
        self.Number_of_coarse_TOs = 0
        self.Throughput = 0.0
        self.Goodput = 0.0
        # assistant data
        self.ACKd = [0] * (self.num+1)
        self.sent_pkt_flag = [0] * (self.num+1)
        self.frist_packet_sent_time = time.time()
        self.last_packet_sent_time = time.time()
        self.LHS_timer = time.time()
        self.coarse_TO_flag = 0


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        # TODO: handle packet and send ack
        # blastee packet format
        # <------- Switchyard headers -----> <----- Your packet header(raw bytes) ------> <-- Payload in raw bytes --->
        # -------------------------------------------------------------------------------------------------------------
        # |  ETH Hdr |  IP Hdr  |  UDP Hdr  |          Sequence number(32 bits)          |      Payload  (8 bytes)    |
        # -------------------------------------------------------------------------------------------------------------
        # debugger()
        sequence = struct.unpack(">i", packet[3].to_bytes()[0:4])
        self.ACKd[sequence[0]] = 1
        log_info (f"Receiving ack pakcet, packet info {packet}")
        if (self.LHS == self.num):
            return
        while (self.ACKd[self.LHS] == 1):
            self.LHS += 1
            self.LHS_timer = time.time()


    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[1].protocol = IPProtocol.UDP
        pkt[Ethernet].src = self.blasterEthAddr
        pkt[Ethernet].dst = self.blasteeEthAddr
        pkt[IPv4].src = self.blasterIpAddr
        pkt[IPv4].dst = self.blasteeIpAddr
        # handle coarse timeout
        max_ack_number = 0
        for i in range(len(self.ACKd)):
            if (self.ACKd[i] == 1):
                max_ack_number = i
        if (max_ack_number > self.LHS):
            self.coarse_TO_flag = 1
        # Do other things here and send packet
        if (time.time() - self.LHS_timer) > self.timeout:
            # debugger()
            self.Number_of_reTX += 1
            self.Throughput += self.length
            Sequence_number = self.LHS.to_bytes(4, "big")
            Length = self.length.to_bytes(2, "big")
            Variable_length_payload = struct.pack(">13s", bytes("hello, world!".encode('utf-8')))
            pkt += Sequence_number
            pkt += Length
            pkt += Variable_length_payload
            log_info (f"Retransmitting pakcet from blaster to blastee, sequence {self.LHS}, packet info {pkt}")
            self.net.send_packet("blaster-eth0", pkt)
        elif (self.coarse_TO_flag):
            self.coarse_TO_flag = 0
            self.Number_of_coarse_TOs += 1
        elif (self.RHS - self.LHS + 1 <= self.senderWindow) and (self.sent_pkt_flag[self.num-1] == 0):
            # <------- Switchyard headers -----> <----- Your packet header(raw bytes) ------> <-- Payload in raw bytes --->
            # -------------------------------------------------------------------------------------------------------------
            # |  ETH Hdr |  IP Hdr  |  UDP Hdr  | Sequence number(32 bits) | Length(16 bits) |   Variable length payload  |
            # -------------------------------------------------------------------------------------------------------------
            Sequence_number = self.RHS.to_bytes(4, "big")
            Length = self.length.to_bytes(2, "big")
            Variable_length_payload = struct.pack(">13s", bytes("Hello, world!".encode('utf-8')))
            pkt += Sequence_number
            pkt += Length
            pkt += Variable_length_payload
            log_info(f"Sending packet from blaster to blastee, sequence {self.RHS}, pkt info {pkt}")
            self.net.send_packet("blaster-eth0", pkt)
            self.sent_pkt_flag[self.RHS] = 1
            if (self.RHS - self.LHS + 1 < self.senderWindow) and (self.RHS < self.num):
                self.RHS += 1
            self.Throughput += self.length
            self.Goodput += self.length

    
    def calc_stats(self):
        # debugger()
        self.Total_TX_time = float(self.last_packet_sent_time - self.frist_packet_sent_time)
        self.Throughput = int(self.Throughput*8 / self.Total_TX_time)
        self.Goodput = int(self.Goodput*8 / self.Total_TX_time)


    def printing_stats(self):
        fmt = "{:^20}\t{:^20}"
        print("-------------------printing stats-------------------")
        print(fmt.format("Total_TX_time", self.Total_TX_time))
        print(fmt.format("Number_of_reTX", self.Number_of_reTX))
        print(fmt.format("Number_of_coarse_TOs", self.Number_of_coarse_TOs))
        print(fmt.format("Throughput", self.Throughput))
        print(fmt.format("Goodput", self.Goodput))
        print("----------------------------------------------------")


    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                if (self.LHS == self.num):
                    self.last_packet_sent_time = time.time()
                    break
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
        
        # debugger()
        self.calc_stats()
        self.printing_stats()
        self.shutdown()


    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
