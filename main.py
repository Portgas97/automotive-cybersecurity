# -----------------------------------------------------------------------------
# Scapy is a powerful Python-based interactive packet manipulation program and
# library. It can be used to forge or decode packets for a wide number of
# protocols, send them on the wire, capture them, match requests and replies,
# and much more.
# needed to load iso-tp kernel module
# https://github.com/hartkopp/can-isotp
import utility
from tests import *

# # # # # # # # # # # # # # # # #  STEP 4  # # # # # # # # # # # # # # # # #
# black-box testing of UDS services
# print("can information")
# ls(CAN)
# First, we want to verify the UDS availability
# conf.contribs['CAN']['remove-padding'] = True
def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == "-v":
            utility.VERBOSE_DEBUG = True
        elif sys.argv[1] == "-vv":
            utility.EXTRA_VERBOSE_DEBUG = True

    sock_vcan0 = ""
    while True:
        print_menu()
        command = input("Enter command: ")

        if command == "help":
            continue

        elif command == "quit":
            break

        elif command == "clear":
            import os
            os.system("clear")
            continue

        # all tests must be set according to this one
        elif command == "test_tp":
            sock_vcan0 = exec_test_tp()

        elif command == "test_dds":
            exec_test_dds(sock_vcan0)

        elif command == "test_recu":
            exec_test_recu(sock_vcan0)

        elif command == "test_rsdi":
            exec_test_rsdi(sock_vcan0)

        elif command == "":
            pass

        else:
            print_error("error: the inserted command does not exist")
            print("ERROR in command parsing")

    print_success("PROGRAM CLOSED.")

if __name__ == "__main__":
    main()


