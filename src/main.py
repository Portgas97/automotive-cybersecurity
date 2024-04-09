
# -----------------------------------------------------------------------------
# Scapy is a powerful Python-based interactive packet manipulation program and
# library. It can be used to forge or decode packets for a wide number of
# protocols, send them on the wire, capture them, match requests and replies,
# and much more.
# needed to load iso-tp kernel module
# https://github.com/hartkopp/can-isotp

import utility
from tests import *
import argparse

# # # # # # # # # # # # # # # # #  STEP 4  # # # # # # # # # # # # # # # # #
# black-box testing of UDS services

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("interface", help="CAN bus interface")
    args = parser.parse_args()

    if args.verbose:
        # TO DO correctly set these values
        print("verbosity turned on")
        utility.VERBOSE_DEBUG = True
        utility.EXTRA_VERBOSE_DEBUG = True


#    if len(sys.argv) > 1:
#        if sys.argv[1] == "-v":
#            utility.VERBOSE_DEBUG = True
#        elif sys.argv[1] == "-vv":
#            utility.EXTRA_VERBOSE_DEBUG = True

    utility.CAN_INTERFACE = args.interface
    print("Socket initialized with can0 and server_id == 0x7ED")
    utility.sock_can = NativeCANSocket(channel=CAN_INTERFACE, 
                                       can_filters=[{'can_id': utility.SERVER_CAN_ID,
                                                     'can_mask': 0x7ff}]) 

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
            utility.sock_can = None

            isotp_scanning(utility.sock_can)
            print("Do you want to set the receiver and senders ID now?")

        elif command == "set_my_ID":
            can_id = input("Enter the CAN bus ID to test (without 0x but in hex value): maybe 7e5?") # TO DO remove suggestion
            set_my_can_id(int(can_id, 16))
        
        elif command == "set_listen_ID":
            can_id = input("Enter the CAN ID for sniffing (without 0x but in hex value): maybe 7ed?") # TO DO remove suggestion
            set_listen_can_id(int(can_id, 16))

        elif command == "test_tp":
            exec_test_tp(utility.sock_can)

        elif command == "test_dds":
            exec_test_dds(utility.sock_can)

        elif command == "test_recu":
            exec_test_recu(utility.sock_can)

        elif command == "test_rsdi":
            exec_test_rdbi(utility.sock_can)

        elif command == "test_rsda":
            session = input("Enter diagnostic session for the test (hex "
                            "format, null for fuzzing): ").strip()
            if session == "":
                exec_test_rsda(utility.sock_can)
            elif 0x00 < int(session) < 0xFF:
                exec_test_rsda(utility.sock_can, int(session).to_bytes())
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


