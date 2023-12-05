# -----------------------------------------------------------------------------
# Scapy is a powerful Python-based interactive packet manipulation program and
# library. It can be used to forge or decode packets for a wide number of
# protocols, send them on the wire, capture them, match requests and replies,
# and much more.
# needed to load iso-tp kernel module
# https://github.com/hartkopp/can-isotp


from scapy.config import conf

from scapy.utils import hexdump
from scapy.sendrecv import sr1, sr
# from scapy.main import load_contrib #, load_layer

from scapy.layers.can import CAN
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, traceroute, TCP



from scapy.contrib.isotp import *
from scapy.contrib.cansocket_native import NativeCANSocket
# from scapy.contrib.cansocket import *

# load_layer("dns")
# load_layer("inet")
# load_layer("can")
# load_contrib("isotp")
# load_contrib("automotive.uds")


conf.contribs['CANSocket'] = {'use-python-can': False} # default
# load_contrib('cansocket_native') ## ??? needed? already contribs['isotp'] below
# conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}


# # # # # # # # # # # # # # # #  EXPERIMENT 1 # # # # # # # # # # # # # # # #
print("\nPLAYING WITH CAN FRAMES...\n", end="")
print("SKIPPED!")
# frame = CAN(flags='extended',
#             identifier=0x10010000,
#             length=8,
#             data=b'\x01\x02\x03\x04\x05\x06\x07\x08'
#             )
# print("CAN frame contents:")
# frame.show()
# print()
#
# print("Hexdump of the CAN frame:")
# hexdump(frame)
# print()

# # # # # # # # # # # # # # # #  EXPERIMENT 2 # # # # # # # # # # # # # # # #
print("\nPLAYING WITH BASICS...\n", end="")
print("SKIPPED!")

# packet = sr1(IP(dst="8.8.8.8")/UDP()/DNS(qd=DNSQR()))

# print()
# print("Packet summary:")
# print(packet.summary())
# print()
# print("Response:")
# print(packet.show())
# print()
# print("Packet hexdump:")
# print(hexdump(packet))
# print()
# print("DNS answer:")
# print(packet[DNS].an.show())
# print()


# print("Traceroute:")
# traceroute_ans, traceroute_unans = traceroute('www.secdev.org', maxttl=15)
# print()
#
# print("Simple port scanner:")
# portscanner_ans = sr(IP(dst=["scanme.nmap.org", "nmap.org"])/TCP(dport=[22, 80, 443, 31337]), timeout=3, verbose=False)[0]
# portscanner_ans.extend(sr(IP(dst=["scanme.nmap.org", "nmap.org"])/UDP(dport=53)/DNS(qd=DNSQR()), timeout=3, verbose=False)[0])
# portscanner_ans.make_table(lambda x, y: (x[IP].dst, x.sprintf('%IP.proto%/{TCP:%r,TCP.dport%}{UDP:%r,UDP.dport%}'), y.sprintf('{TCP:%TCP.flags%}{ICMP:%ICMP.type%}')))

# # # # # # # # # # # # # # # #  EXPERIMENT 3 # # # # # # # # # # # # # # # #
print("\nPLAYING WITH CAN SOCKETS...\n", end="")
print("SKIPPED!")
# print("Instantiating a new native can socket:")
# nc_socket = NativeCANSocket(channel="vcan0")
# print("sending a CAN frame...", end="")
# packet = CAN(identifier=0x123, data=b'01020304')
# nc_socket.send(packet)
# print("done")
# print("receiving a packet...", end="")
# rx_packet = nc_socket.recv()
# print("done\n")
# print("Received packet:")
# rx_packet.show()
#
# print("\nSniff some traffic:\n")
# pkts = nc_socket.sniff(timeout=5, count=10)
# print(pkts)
# pkts[0].show()

# # # # # # # # # # # # # # # # #  STEP 1  # # # # # # # # # # # # # # # # #
# On CAN networks, ISOTP (ISO-15765 Transport Protocol) is a communication
# protocol used in the automotive industry to transmit data. It is designed to
# provide a # reliable and efficient way to transfer large amounts of data,
# such as software updates and diagnostic data.

# There are four special frames:
#   - single frame
#   - first frame
#   - consecutive frame
#   - flow control frame

# It is used to address every individual ECU in the entire vehicle network.
# The gateway ECU will route ISOTP packets into the right subnet automatically.
# ISOTP supports several addressing schemes. Unfortunately, every OEM uses
# different addressing schemes: a good practice is to scan for ECUs with normal
# addressing with a CAN identifier range from 0x500-0x7ff.


print("\nPLAYING WITH ISO-TP...\n", end="")
print("SKIPPED!")

# isotp_packet = ISOTP(b"super packet for isotp transport protocol",
#                      tx_id=0x111, rx_id=0x222)
# print("Example of packet:\n")
# isotp_packet.show()
#
# print("underlying frames:\n")
# can_frames = isotp_packet.fragment()
# for can_frame in can_frames:
#     ISOTPHeader(bytes(can_frame)).show()
#
# print("reconstruct the message:\n")
# builder = ISOTPMessageBuilder()
# builder.feed(can_frames)
# print("message builder length: ", end="")
# print(len(builder))
# isotp_msg = builder.pop()
# print(repr(isotp_msg))
# print("message builder length: ", end="")
# print(len(builder))


# To identify all possible communication endpoints and their supported
# application layer protocols, a transport layer scan has to be performed
# first.
# IDS will immediately see illegitimate traffic. This may disturb
# safety-critical and real-time communication
# Procedure:
#   - Choose an addressing scheme
#   - Craft FF (first-frame) with payload length e.g. 100
#   - Send FF with all possible addresses according to the addressing scheme
#   - Listen for FC (flow-control) frames according to the chosen addressing
#     scheme
#   - If FC is detected, obtain all address information and information about
#     padding from the last FF and the received FC (e.g. source address SA,
#     target address TA, address extension AE, addressing scheme, padding)
#
# One could also perform passive scanning, not producing additional load

print("\nISO-TP SCANNING...\n")

isotp_scan_socket = isotp_scan (
                               NativeCANSocket(channel="vcan0"),
                               scan_range=range(0x120, 0x130),
                               can_interface="vcan0"
                               )

print(isotp_scan_socket)


# UDS is set as basecls
# sock = ISOTPNativeSocket("vcan0",
#                          tx_id=0x6f1,
#                          rx_id=0x610,
#                          ext_address=0x10,
#                          rx_ext_address=0xf1,
#                          basecls=UDS
#                          )




# # # # # # # # # # # # # # # # #  STEP 2  # # # # # # # # # # # # # # # # #
# On every identified ISOTP Endpoint, a UDS scan can be performed to identify
# the attack surface of this ECU (Endpoint).
