#!/usr/bin/env python3

'''
Ethernet hub in Switchyard.
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    ingress_pkt_num = 0
    egress_pkt_num = 0

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        
        ingress_pkt_num += 1
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            log_info(f"in:{ingress_pkt_num} out:{egress_pkt_num}")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
            log_info(f"in:{ingress_pkt_num} out:{egress_pkt_num}")
        else:
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    egress_pkt_num += 1
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    log_info(f"in:{ingress_pkt_num} out:{egress_pkt_num}")
                    net.send_packet(intf, packet)

    net.shutdown()
