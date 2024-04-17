import argparse
from scapy.contrib.cansocket_native import NativeCANSocket

import tests
import utility
from configuration import config_manager as ctx_man

# testing git # TODO remove 
def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-v", "--verbose", 
                        help="increase output verbosity", 
                        action="store_true")
    
    parser.add_argument("interface", 
                        help="CAN bus interface")
    
    args = parser.parse_args()

    if args.verbose:
        ctx_man.setVerboseDebug(True)
        utility.print_debug("verbosity turned on")
        print("Default configurations:")
        ctx_man.readConfigurations()

    ctx_man.setCanInterface(args.interface)

    # ! forse basta mettere nofilter=1 nella chiamata a sr per ricevere un po tutto
    socket = NativeCANSocket(channel=ctx_man.getCanInterface(),  
                         can_filters=[{'can_id': ctx_man.getServerCanId(),
                                       'can_mask': 0x7ff}]) 
    ctx_man.setCanSocket(socket)

    print_banner = True

    while True:

        command: str = ""
        if print_banner:
            utility.print_menu()
        print_banner = False

        command = input("\nEnter command: ")
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
            tests.isotp_scanning(NativeCANSocket(channel=ctx_man.getCanInterface())) 

            utility.print_debug("You can now set the receiver and sender IDs now!")

        elif command == "set_my_ID":
            can_id = input("Enter the CAN bus ID to test (hex w/o 0x): ")
            ctx_man.setCanId(int(can_id, 16))
        
        elif command == "set_listen_ID":
            can_id = input("Enter the CAN ID for sniffing (hex w/o 0x): ")
            ctx_man.setServerCanId(int(can_id, 16))
            socket = NativeCANSocket(channel=ctx_man.getCanInterface(), 
                                     can_filters=[
                                        {'can_id': ctx_man.getServerCanId(), 
                                        'can_mask': 0x7ff}])
            ctx_man.setCanSocket(socket)

        elif command == "test_tp":
            tests.exec_test_tp() 

        elif command == "test_dds":

            utility.print_new_test_banner()
            print("Starting TEST_DDS\n")

            from halo import Halo
            # spinner = Halo(text='Executing script', spinner='bouncingBar')
            # spinner.start()
            
            tests.exec_test_dds()
            
            # spinner.stop()
            print("\n Discovered sessions: ")
            ctx_man.getSessionGraph().printGraph()

            print("\n Pay attention to:")
            ctx_man.ToCheckGraph.printGraph()

            print("\nTEST_DSS finished.\n")

        elif command == "test_recu":
            tests.exec_test_recu()

        elif command == "test_rdbi":
            tests.exec_test_rdbi()

        elif command == "test_rsda":
            session = input("Enter diagnostic session for the test (hex "
                            "format, null for fuzzing): ").strip()
            if session == "":
                tests.exec_test_rsda()
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
            utility.print_error("error: the inserted command does not exist")
            print("ERROR in command parsing")

    ctx_man.CAN_SOCKET.close()
    utility.print_success("PROGRAM CLOSED.")


if __name__ == "__main__":
    main()


