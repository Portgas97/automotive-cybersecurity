# -----------------------------------------------------------------------------
# Scapy is a powerful Python-based interactive packet manipulation program and
# library. It can be used to forge or decode packets for a wide number of
# protocols, send them on the wire, capture them, match requests and replies,
# and much more. It is possible to load iso-tp kernel module 
# https://github.com/hartkopp/can-isotp

import utility
import global_
import argparse
from tests import *


# # # # # # # # # # # # # # # # #  STEP 4  # # # # # # # # # # # # # # # # #
# black-box testing of UDS services

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("interface", help="CAN bus interface")
    args = parser.parse_args()

    if args.verbose:
        print_debug("verbosity turned on")
        global_.VERBOSE_DEBUG = True


    global_.CAN_INTERFACE = args.interface
    print_debug("Socket initialized with can0 and server_id == 0x7ED")

    # TODO: global_.CAN_SOCKET is handled here but also modified in tests.py/set_listen_can_id
    # is it correct handled?? 
    # TODO: forse basta mettere nofilter=1 nella chiamata a sr per ricevere un po tutto
    with NativeCANSocket(channel=global_.CAN_INTERFACE,  
                         can_filters=[{'can_id': global_.SERVER_CAN_ID,
                                       'can_mask': 0x7ff}]) as nativecan_socket:
        global_.CAN_SOCKET = nativecan_socket
    

        print_banner = True
        while True:
            command: str = ""
            if print_banner:
                print_menu()
            print_banner = False

            command = input("Enter command: ")
            command = command.strip()

            if command == "":
                continue

            elif command == "help":
                print_banner = True

            elif command == "quit":
                break

            elif command == "clear":
                import os
                os.system("clear")
                continue

            # all tests must be set according to this one
            elif command == "isotp_scan":
                isotp_scanning()
                print_debug("Do you want to set the receiver and sender IDs now?")

            elif command == "set_my_ID":
                can_id = input("Enter the CAN bus ID to test (hex w/o 0x): ")
                set_my_can_id(int(can_id, 16))
            
            elif command == "set_listen_ID":
                can_id = input("Enter the CAN ID for sniffing (hex w/o 0x): ")
                set_listen_can_id(int(can_id, 16))

            elif command == "test_tp":
                exec_test_tp() 

            elif command == "test_dds":
                print_new_test_banner()
                print("Starting TEST_DDS\n")
                exec_test_dds()
                print("TEST_DSS finished.\n")

            elif command == "test_recu":
                exec_test_recu()

            elif command == "test_rsdi":
                exec_test_rdbi()

            elif command == "test_rsda":
                session = input("Enter diagnostic session for the test (hex "
                                "format, null for fuzzing): ").strip()
                if session == "":
                    exec_test_rsda()
                elif 0x00 < int(session) < 0xFF:
                    # exec_test_rsda(, int(session).to_bytes()) # TODO rebuild
                    pass
                else:
                    print("wrong session inserted, try again")
                    skip_input = True
            elif command == "":
                pass
            elif command == "":
                pass

            else:
                print_error("error: the inserted command does not exist")
                print("ERROR in command parsing")

        print_success("PROGRAM CLOSED.")


if __name__ == "__main__":
    main()


