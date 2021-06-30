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
    age = 0

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
            if (len(table) == 5):
                sorted_table = sorted(table.items(), key=lambda x:x[1][1], reverse=True)
                del table[sorted_table[0][0]]
            for macAddress in list(table.keys()):
                table[macAddress][1] += 1
            table[eth.src] = [fromIface, age]
            log_info(f"Record mac_address: {eth.src}, interface: {fromIface}, age: {age}")

            # log_info("----------test info-----------")
            # for k,v in table.items():
            #     log_info(f"key: {k}, value: {v}")
            # log_info("----------test info-----------")

        elif (table.get(eth.src, -1) != -1):
            if table[eth.src][0] != fromIface:
                table[eth.src][0] = fromIface
                log_info(f"Update port mac_address: {table[eth.src][0]}, interface: {fromIface}")
                # log_info("----------test info-----------")
                # for k,v in table.items():
                #     log_info(f"key: {k}, value: {v}")
                # log_info("----------test info-----------")
            else:
                # log_info("----------test info-----------")
                # log_info(f"mac_address: {table[eth.src]}, port: {fromIface} not change")
                # log_info("----------test info-----------")
                pass
        if eth.dst not in mymacs:
            if (table.get(eth.dst, -1) != -1):
                for macAddress in list(table.keys()):
                    if (table[macAddress][1] < table[eth.dst][1]):
                        table[macAddress][1] += 1
                table[eth.dst][1] = 0
                net.send_packet(table[eth.dst][0], packet)
                log_info (f"Sending packet {packet} to {table[eth.dst]}")
                # log_info("----------test info-----------")
                # for k,v in table.items():
                #     log_info(f"key: {k}, value: {v}")
                # log_info("----------test info-----------")
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
        
        


    net.shutdown()
