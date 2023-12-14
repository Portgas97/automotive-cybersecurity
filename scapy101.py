# # # # # # # # # # # # # # # #  EXPERIMENT 1 # # # # # # # # # # # # # # # #
print("\nPLAYING WITH CAN FRAMES...", end="")
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
print("\nPLAYING WITH BASICS...", end="")
print("SKIPPED!")

# packet = sr1(IP(dst="8.8.8.8")/UDP()/DNS(qd=DNSQR()))
#
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
#
#
# print("Traceroute:")
# traceroute_ans, traceroute_unans = traceroute('www.secdev.org', maxttl=15)
# print()
#
# print("Simple port scanner:")
# portscanner_ans = sr(IP(dst=["scanme.nmap.org", "nmap.org"])/TCP(dport=[22, 80, 443, 31337]), timeout=3, verbose=False)[0]
# portscanner_ans.extend(sr(IP(dst=["scanme.nmap.org", "nmap.org"])/UDP(dport=53)/DNS(qd=DNSQR()), timeout=3, verbose=False)[0])
# portscanner_ans.make_table(lambda x, y: (x[IP].dst, x.sprintf('%IP.proto%/{TCP:%r,TCP.dport%}{UDP:%r,UDP.dport%}'), y.sprintf('{TCP:%TCP.flags%}{ICMP:%ICMP.type%}')))

# # # # # # # # # # # # # # # #  EXPERIMENT 3 # # # # # # # # # # # # # # # #
print("\nPLAYING WITH CAN SOCKETS...", end="")
print("SKIPPED!")
# print("Instantiating a new native can socket:")
# nc_socket = NativeCANSocket(channel="vcan0")
# print("sending a CAN frame...", end="")
# packet = CAN(identifier=0x123, data=b'01020304')
# nc_socket.send(packet)
# print("done")
# print("receiving a packet...")
# rx_packet = nc_socket.recv()
# print("Received packet:")
# rx_packet.show()
#
# print("\nSniff some traffic:\n")
# sniffed_packets = nc_socket.sniff(timeout=5, count=10)
# print(sniffed_packets)
# sniffed_packets[0].show()
