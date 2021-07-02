#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.logging import *
import rebulid_pkt
import queue


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = net.interfaces()    
        self.arp_table = {}

        self.ip_list = []
        self.eth_list = []
        for i in self.interfaces:
            self.ip_list.append(i.ipaddr)
            self.eth_list.append(i.ethaddr)

        self.forwarding_table = {}
        # init by net.interfaces()
        for i in self.interfaces:
            my_netmask = i.netmask
            my_ipaddr = i.ipaddr
            log_debug (f"type of my_ipaddr: {type(my_ipaddr)}; type of my_netmask: {type(my_netmask)}")
            log_debug (f"value of my_ipaddr: {my_ipaddr}; value of my_netmask: {my_netmask}; value of i.netmask: {i.netmask}")
            sub_network_address = IPv4Address(ip_address((int(my_ipaddr) & int(my_netmask))))
            log_debug (f"value of subnet address: {sub_network_address}\n")
            self.forwarding_table[sub_network_address] = [my_netmask, '0.0.0.0', i.name]
        self.print_forwarding_table()
        # init by forwarding_table.txt
        with open('forwarding_table.txt') as f:
            while True:
                line = f.readline()
                if not line:
                    break
                else:
                    table_info = line.split()
                    self.forwarding_table[IPv4Address(table_info[0])] = [IPv4Address(table_info[1]), IPv4Address(table_info[2]), table_info[3]]
        self.print_forwarding_table()

        self.packet_queue = []


    def print_forwarding_table(self):
        log_info ("------------------------forwarding_table_info------------------------")
        for k,v in self.forwarding_table.items():
            log_info (f"        address: {k};  other: {v}.          ")
        log_info ("----------------------------------------------------------------------")
        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)

        input_port = self.net.interface_by_name(ifaceName)
        
        if (arp is not None):
            self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr

            log_info ("------------------------arp_table_info------------------------")
            for k,v in self.arp_table.items():
                log_info (f"        IP: {k}; MAC Address: {v}")
            log_info ("--------------------------------------------------------------")
            if arp.operation == ArpOperation.Request:
                targetip_exist_flag = -1
                for i in range(len(self.ip_list)):
                    if (self.ip_list[i] == arp.targetprotoaddr):
                        targetip_exist_flag = i
                if (targetip_exist_flag != -1):
                    arp_reply_pkt = create_ip_arp_reply(input_port.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, arp_reply_pkt)
                    log_info (f"Sending arp reply {arp_reply_pkt} to {ifaceName}")
        elif (ipv4 is not None):
            ipv4.ttl = ipv4.ttl - 1
            # ------------Task2: IP Forwarding Table Lookup ------------
            drop_flag = 0
            match_subnet = '0.0.0.0'
            match = 0
            # match router port, True->drop it 
            for address in self.interfaces:
                if (ipv4.dst == address.ipaddr):
                    # drop
                    drop_flag = 1
            # longest prefix matching rule
            if (drop_flag == 0):
                prefix_len = 0
                for address in self.forwarding_table.keys():
                    prefix = IPv4Address(address)
                    destaddr = ipv4.dst
                    matches = (int(prefix) & int(destaddr)) == int(prefix)
                    if (matches):
                        netaddr = IPv4Network(str(address) + '/' + str(self.forwarding_table[address][0]))
                        if (netaddr.prefixlen > prefix_len):
                            prefix_len = netaddr.prefixlen
                            match_subnet = IPv4Address(address)
                            match = 1
                # no match in table
                if (match == 0):
                    drop_flag = 1
            # ----------------------------------------------------------
            # rebulid packet
            if (drop_flag == 0):
                # put rebulid packet in queue
                if self.forwarding_table[match_subnet][1] == '0.0.0.0':
                    dstip = IPv4Address(ipv4.dst)
                else:
                    dstip = IPv4Address(self.forwarding_table[match_subnet][1])
                pkt = rebulid_pkt.rebulid_pkt(packet, match_subnet, self.forwarding_table[match_subnet][2], dstip)
                self.packet_queue.append(pkt)

    # ------------Task3: Forwarding the Packet and ARP ------------
    def forwarding(self):
        if (len(self.packet_queue) == 0):
            return
        handle_pkt = self.packet_queue[0]
        targetipaddr = handle_pkt.get_targetipaddress()
        router_send_to_host_port_name = handle_pkt.get_send_out_port()
        my_packet = handle_pkt.get_packet()
        router_forwarding_port_info = self.net.interface_by_name(router_send_to_host_port_name)
        if (targetipaddr in self.arp_table.keys()):
            # search arp table
            self.forwarding_packet(my_packet, router_send_to_host_port_name, targetipaddr, router_forwarding_port_info)
        elif (handle_pkt.get_num_of_retries() < 5):
            # send arp request
            self.send_arp_request(handle_pkt, router_forwarding_port_info, targetipaddr, router_send_to_host_port_name)
        elif (handle_pkt.get_num_of_retries() >= 5):
            # delete
            log_info (f"Delete packet {self.packet_queue[0].get_packet()}")
            del(self.packet_queue[0])
    # ----------------------------------------------------------
                               
    def forwarding_packet(self, my_packet, router_send_to_host_port_name, targetipaddr, router_forwarding_port_info):
        my_packet[Ethernet].src = router_forwarding_port_info.ethaddr
        my_packet[Ethernet].dst = self.arp_table[targetipaddr]
        self.net.send_packet(router_send_to_host_port_name, my_packet)
        log_info (f"Forwarding packet {my_packet} to {router_send_to_host_port_name}")
        del(self.packet_queue[0])

    def send_arp_request(self, handle_pkt, router_forwarding_port_info, targetipaddr, router_send_to_host_port_name):
        retry_flag = 0
        if ((time.time() - handle_pkt.get_recent_time()) > 1.0):
            retry_flag = 1
        if (retry_flag):
            arppacket = create_ip_arp_request(router_forwarding_port_info.ethaddr,router_forwarding_port_info.ipaddr,targetipaddr)
            handle_pkt.try_to_send()
            handle_pkt.update_time()
            self.net.send_packet(router_send_to_host_port_name, arppacket)
            log_info (f"Sending arp request {arppacket} to {router_send_to_host_port_name}")

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            self.forwarding()
            
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break
            log_info("handle_packet")
            # debugger()
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
