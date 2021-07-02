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
        
        self.icmperr = 0


    def print_forwarding_table(self):
        log_info ("------------------------forwarding_table_info------------------------")
        for k,v in self.forwarding_table.items():
            log_info (f"        address: {k};  other: {v}.          ")
        log_info ("----------------------------------------------------------------------")
        

    def icmp_error(self, origpkt, type_of_error, icmp_code, srcip, dstip):
        # origpkt = Ethernet() + IPv4() + ICMP()
        i = origpkt.get_header_index(Ethernet)
        del origpkt[i]

        eth = Ethernet()

        icmp = ICMP()
        icmp.icmptype = type_of_error
        icmp.icmpcode = icmp_code
        icmp.icmpdata.data = origpkt.to_bytes()[:28]

        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 64
        ip.src = srcip
        ip.dst = dstip

        pkt = eth + ip + icmp
        return pkt

    def prefix_match(self, dst):
        prefix_len = 0
        match_subnet = '0.0.0.0'
        for address in self.forwarding_table.keys():
            destaddr = dst
            prefixnet = IPv4Network(str(address) + '/' + str(self.forwarding_table[address][0]))
            matches = destaddr in prefixnet
            if (matches):
                if (prefixnet.prefixlen > prefix_len):
                    prefix_len = prefixnet.prefixlen
                    match_subnet = IPv4Address(address)
                    match = 1
        return match_subnet


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header(IPv4)
        icmp = packet.get_header(ICMP)

        input_port_info = self.net.interface_by_name(ifaceName)

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
                    arp_reply_pkt = create_ip_arp_reply(input_port_info.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                    self.net.send_packet(ifaceName, arp_reply_pkt)
                    log_info (f"Sending arp reply {arp_reply_pkt} to {ifaceName}")   
        elif (ipv4 is not None):
            targetip_exist_flag = -1
            for i in range(len(self.ip_list)):
                if (self.ip_list[i] == ipv4.dst):
                    targetip_exist_flag = i
            if (icmp is not None):
                # ------------Task2: Responding to ICMP echo requests ------------
                log_debug(f"icmp: {icmp}\nicmpcode: {icmp.icmpcode}\n icmpdata: {icmp.icmpdata}\n icmptype: {icmp.icmptype}")
                if (targetip_exist_flag != -1) and (icmp.icmptype == 8 and icmp.icmpcode == 0):
                    icmp_reply = ICMP()
                    # echo reply(ping)
                    icmp_reply.icmptype = 0
                    icmp_reply.icmpcode = 0
                    # copy info from icmp request to icmp reply
                    icmp_reply.icmpdata.sequence = icmp.icmpdata.sequence
                    icmp_reply.icmpdata.identifier = icmp.icmpdata.identifier
                    icmp_reply.icmpdata.data = icmp.icmpdata.data
                    # 2=ICMP
                    packet[2] = icmp_reply
                    # construct IP header
                    ipv4.dst = ipv4.src
                    ipv4.src = self.ip_list[targetip_exist_flag]
                # ----------------------------------------------------------------
            # ICMP time exceeded
            ipv4.ttl = ipv4.ttl - 1
            if ipv4.ttl <= 0:
                packet = self.icmp_error(packet, 11, 0, input_port_info.ipaddr, ipv4.src)
                ipv4.dst = ipv4.src
                ipv4.src = self.ip_list[targetip_exist_flag]
                self.icmperr = 1
            # ------------Task2: IP Forwarding Table Lookup ------------
            drop_flag = 0
            match_subnet = '0.0.0.0'
            match = 0
            # ICMP destination port unreachable
            for address in self.interfaces:
                if (ipv4.dst == address.ipaddr):
                    # drop
                    drop_flag = 1
                    packet = self.icmp_error(packet, 3, 3, input_port_info.ipaddr, ipv4.src)
                    ipv4.dst = ipv4.src
                    ipv4.src = self.ip_list[targetip_exist_flag]
                    match_subnet = self.prefix_match(ipv4.dst)
                    self.icmperr = 1
            # longest prefix matching rule
            if (drop_flag == 0):
                prefix_len = 0
                for address in self.forwarding_table.keys():
                    destaddr = ipv4.dst
                    prefixnet = IPv4Network(str(address) + '/' + str(self.forwarding_table[address][0]))
                    matches = destaddr in prefixnet
                    if (matches):
                        if (prefixnet.prefixlen > prefix_len):
                            prefix_len = prefixnet.prefixlen
                            match_subnet = IPv4Address(address)
                            match = 1
                # ICMP destination network unreachable
                if (match == 0):
                    drop_flag = 1
                    packet = self.icmp_error(packet, 3, 0, input_port_info.ipaddr, ipv4.src)
                    ipv4.dst = ipv4.src
                    ipv4.src = self.ip_list[targetip_exist_flag]
                    match_subnet = self.prefix_match(ipv4.dst)
                    self.icmperr = 1
            # ----------------------------------------------------------
            # rebulid packet
            if self.forwarding_table[match_subnet][1] == '0.0.0.0':
                dstip = IPv4Address(ipv4.dst)
            else:
                dstip = IPv4Address(self.forwarding_table[match_subnet][1])
            pkt = rebulid_pkt.rebulid_pkt(packet, match_subnet, self.forwarding_table[match_subnet][2], dstip, input_port_info)
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
        input_port_info = handle_pkt.get_input_port_info()
        # if (my_packet[1].src == IPv4Address('192.168.1.239')):
        #     debugger()
        if (targetipaddr in self.arp_table.keys()):
            # search arp table
            self.forwarding_packet(my_packet, router_send_to_host_port_name, targetipaddr, router_forwarding_port_info)
        elif (handle_pkt.get_num_of_retries() < 5):
            # send arp request
            self.send_arp_request(handle_pkt, router_forwarding_port_info, targetipaddr, router_send_to_host_port_name, input_port_info)
        elif (handle_pkt.get_num_of_retries() >= 5):
            # ICMP destination host unreachable
            targetip_exist_flag = -1
            for i in range(len(self.ip_list)):
                if (self.ip_list[i] == my_packet[IPv4].dst):
                    targetip_exist_flag = i
            # debugger()
            packet = self.icmp_error(my_packet, 3, 1, input_port_info.ipaddr, my_packet[IPv4].src)
            my_packet[IPv4].dst = my_packet[IPv4].src
            my_packet[IPv4].src = self.ip_list[targetip_exist_flag]
            match_subnet = self.prefix_match(my_packet[IPv4].dst)
            # self.net.send_packet(input_port_info.name, packet)
            log_info (f"Delete packet {self.packet_queue[0].get_packet()}")
            del(self.packet_queue[0])
            self.icmperr = 1
            if self.forwarding_table[match_subnet][1] == '0.0.0.0':
                dstip = IPv4Address(my_packet[IPv4].dst)
            else:
                dstip = IPv4Address(self.forwarding_table[match_subnet][1])
            pkt = rebulid_pkt.rebulid_pkt(packet, match_subnet, self.forwarding_table[match_subnet][2], dstip, input_port_info)
            self.packet_queue.append(pkt)
    # ----------------------------------------------------------
                               
    def forwarding_packet(self, my_packet, router_send_to_host_port_name, targetipaddr, router_forwarding_port_info):
        if (self.icmperr):
            my_packet[Ethernet].src = router_forwarding_port_info.ethaddr
            my_packet[Ethernet].dst = self.arp_table[targetipaddr]
            self.net.send_packet(router_send_to_host_port_name, my_packet)
            log_info (f"Forwarding packet {my_packet} to {router_send_to_host_port_name}")
            del(self.packet_queue[0])
            self.icmperr = 0
        else:
            my_packet[Ethernet].src = router_forwarding_port_info.ethaddr
            my_packet[Ethernet].dst = self.arp_table[targetipaddr]
            self.net.send_packet(router_send_to_host_port_name, my_packet)
            log_info (f"Forwarding packet {my_packet} to {router_send_to_host_port_name}")
            del(self.packet_queue[0])

    def send_arp_request(self, handle_pkt, router_forwarding_port_info, targetipaddr, router_send_to_host_port_name, input_port_info):
        retry_flag = 0
        if ((time.time() - handle_pkt.get_recent_time()) > 1.0):
            retry_flag = 1
        if (retry_flag):
            if (self.icmperr):
                arppacket = create_ip_arp_request(input_port_info.ethaddr,input_port_info.ipaddr,targetipaddr)
                handle_pkt.try_to_send()
                handle_pkt.update_time()
                self.net.send_packet(input_port_info.name, arppacket)
                log_info (f"Sending arp request {arppacket} to {input_port_info.name}")
            else:
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
