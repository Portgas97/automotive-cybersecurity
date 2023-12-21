# # # # # # # # # # # # # # # # #  STEP 2  # # # # # # # # # # # # # # # # #
# On every identified ISOTP Endpoint, a UDS scan can be performed to identify
# the attack surface of this ECU (Endpoint).

print("\nUDS SCANNING...", end="")
print("SKIPPED!")

# let's instantiate a socket with basecls=UDS

# sock = ISOTPNativeSocket("vcan0",
#                          tx_id=0x6f1,
#                          rx_id=0x610,
#                          ext_address=0x10,
#                          rx_ext_address=0xf1,
#                          basecls=UDS
#                          )

# create a packet and send it

# read_by_id_pkt = UDS()/UDS_RDBI(identifiers=[0x172a])
# print("packet to be sent:\n")
# print(repr(read_by_id_pkt))
#
# try:
#     rx = sock.sr1(read_by_id_pkt, timeout=1)
# except:
#     print("Something went wrong, an exception occurred :(")
# else:
#     if rx is not None:
#         rx.show()
#
# print("\nexploring possible UDS packets:\n")
# print("SKIPPED!")
# explore("scapy.contrib.automotive.uds")

# print("\ndetails of UDS_SA:\n")
# ls(UDS_SA)

# print("\n sending tester present:\n")
# tps = UDS_TesterPresentSender(sock)
# tps.start()
# print("...stuff in here...")
# tps.stop()
# print("\n tester present finished.\n")


# scanning
# print("\nStarting the UDS service enumerator (scanning)\n")
# uds_scanner = UDS_Scanner(sock, test_cases=[UDS_ServiceEnumerator])
# uds_scanner.scan(timeout=10)
# uds_scanner.show_testcases()