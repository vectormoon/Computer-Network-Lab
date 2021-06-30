from switchyard.lib.userlib import *


def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def test_switch():
    s = TestScenario("switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = new_packet(
        "30:00:00:00:00:02",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.2",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth0 and eth2")
    )
    
    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = new_packet(
        "30:00:00:00:00:01",
        "20:00:00:00:00:01",
        "192.168.100.3",
        "192.168.100.1"
    )
    s.expect(
        PacketInputEvent("eth2", testpkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:01 to 20:00:00:00:00:01 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth1", testpkt, "eth0", testpkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:01 should be flooded out"
         "eth0 and eth2")
    )

    return s


scenario = test_switch()