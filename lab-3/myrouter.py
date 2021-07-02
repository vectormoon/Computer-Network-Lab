#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = net.interfaces()
        self.ip_list = []
        self.arp_table = {}
        for i in self.interfaces:
            self.ip_list.append(i.ipaddr)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        
        input_port = self.net.interface_by_name(ifaceName)
        # log_info (f"-------------{input_port.ethaddr}----------------")

        if arp is None:
            log_info ("No ARP packet")
        else:
            self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
            log_info ("------------------------arp_table_info------------------------")
            for k,v in self.arp_table.items():
                log_info (f"        IP: {k}; MAC Address: {v}")
            log_info ("--------------------------------------------------------------")

            targetip_exist_flag = -1
            for i in range(len(self.ip_list)):
                if (self.ip_list[i] == arp.targetprotoaddr):
                    targetip_exist_flag = i
            # log_info (f"-------------{self.ip_list[targetip_exist_flag]}----------------")

            if (targetip_exist_flag != -1):
                arp_reply_pkt = create_ip_arp_reply(input_port.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                self.net.send_packet(ifaceName, arp_reply_pkt)
                log_info (f"Sending packet {arp_reply_pkt} to {ifaceName}")

    # def my_timeout(self, time_to_delete):
    #     pass

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

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
