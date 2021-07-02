#!/usr/bin/env python3

import time
import threading
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        # TODO
        self.interfaces = net.interfaces()
        self.ip_list = []
        self.eth_list = []
        self.name_list = []
        for i in self.interfaces:
            self.ip_list.append(i.ipaddr)
            self.eth_list.append(i.ethaddr)
            self.name_list.append(i.name)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            randnum = randint(1, 100)
            # drop
            if (randnum < 20):
                log_info ("middlebox drop packet")
            # modify and send
            else:
                middlebox_eth1_num = 0
                for i in range(len(self.name_list)):
                    if self.name_list[i] == "middlebox-eth1":
                        middlebox_eth1_num = i
                
                packet[Ethernet].src = self.eth_list[middlebox_eth1_num]
                packet[Ethernet].dst = "20:00:00:00:00:01"
                log_info(f"Sending packet {packet} to blastee")
                self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            randnum = randint(1, 100)
            # drop
            if (randnum < 20):
                log_info ("middlebox drop packet")
            # modify and send
            else:
                middlebox_eth0_num = 0
                for i in range(len(self.name_list)):
                    if self.name_list[i] == "middlebox-eth0":
                        middlebox_eth0_num = i
                
                packet[Ethernet].src = self.eth_list[middlebox_eth0_num]
                packet[Ethernet].dst = "10:00:00:00:00:01"
                log_info(f"Sending packet {packet} to blaster")
                self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :))")

    def start(self):
        '''A running daemon of the router.
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
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
