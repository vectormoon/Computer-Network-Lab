'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    table = {}

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        # log_info (f"--------------------------{eth.src}-----------------------")
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        if (table.get(eth.src, -1) == -1):
            table[eth.src] = fromIface
            log_info(f"Record mac_adress: {eth.src}, interface: {fromIface}")
        if eth.dst not in mymacs:
            if (table.get(eth.dst, -1) != -1):
                net.send_packet(table[eth.dst], packet)
                log_info (f"Sending packet {packet} to {table[eth.dst]}")
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
        
        # for k,v in table.items():
        #     print("key:", k, "value:", v)


    net.shutdown()
