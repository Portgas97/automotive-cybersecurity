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


print("imported isotp_scanning.py")

def main():
    print("\nPLAYING WITH ISO-TP...", end="")
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

    print("\nISO-TP SCANNING...", end="")
    print("SKIPPED!")
    # isotp_scan_socket = isotp_scan (
    #                                NativeCANSocket(channel="vcan0"),
    #                                scan_range=range(0x120, 0x130),
    #                                can_interface="vcan0"
    #                                )
    #
    # print(isotp_scan_socket)

if __name__ == '__main__':
    main()