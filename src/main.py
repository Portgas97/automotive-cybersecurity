import argparse
from scapy.contrib.isotp import ISOTPNativeSocket
from scapy.contrib.automotive.uds import UDS

import tests
import utility
from configuration import config_manager as ctx_man


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
    socket = ISOTPNativeSocket(iface=ctx_man.getCanInterface(), 
                               tx_id=ctx_man.getCanId(), 
                               rx_id=ctx_man.getServerCanId(),
                               padding=True, 
                               basecls=UDS)
    # NativeCANSocket(channel=ctx_man.getCanInterface(), can_filters=[{'can_id': ctx_man.getServerCanId(), 'can_mask': 0x7ff}]) 
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

        elif command == "isotp_scan":
            from scapy.contrib.cansocket_native import NativeCANSocket
            tests.isotp_scanning(NativeCANSocket(channel=ctx_man.getCanInterface())) 

            utility.print_debug("You can now set the receiver and sender IDs now!")

        elif command == "set_my_ID":
            can_id = input("Enter the CAN bus ID to test (hex w/o 0x): ")
            ctx_man.setCanId(int(can_id, 16))
        
        elif command == "set_listen_ID":
            can_id = input("Enter the CAN ID for sniffing (hex w/o 0x): ")
            ctx_man.setServerCanId(int(can_id, 16))
            socket = ISOTPNativeSocket(iface=ctx_man.getCanInterface(), 
                                       tx_id=ctx_man.getCanId(), 
                                       rx_id=ctx_man.getServerCanId(), 
                                       padding=True, 
                                       basecls=UDS)

            # socket = NativeCANSocket(channel=ctx_man.getCanInterface(), 
                                    #  can_filters=[
                                        # {'can_id': ctx_man.getServerCanId(), 
                                        # 'can_mask': 0x7ff}], 
                                        # basecls=utility.UDS)
            ctx_man.setCanSocket(socket)
            print(socket)
            print(ctx_man.getCanSocket())

        elif command == "test_tp":
            tests.exec_test_tp() 

        elif command == "test_dds":

            utility.print_new_test_banner()
            print("Starting TEST_DDS\n")

            # from halo import Halo
            # spinner = Halo(text='Executing script', spinner='bouncingBar')
            # spinner.start()
            tests.exec_test_dds()
            # spinner.stop()
            
            print("\n Discovered sessions: ")
            ctx_man.getSessionGraph().printGraph()

            print("\n Pay attention to:")
            ctx_man.ToCheckGraph.printGraph()

            print("\nTEST_DSS finished.\n")

        elif command == "scan_rdbi":
            tests.exec_test_scan_rdbi()

        elif command == "test_rdbi":
            did = int(input("Enter did: "), 16)
            tests.exec_test_rdbi(did)
        # TO DO

        elif command == "test_wdbi":
            did = int(input("Enter did: "), 16)
            data = int(input("Enter data: "), 16)
            tests.exec_test_wdbi(did=0x0000, data=data)

        # elif command == "test_rsda":
        #     session = input("Enter diagnostic session for the test (hex "
        #                     "format, null for fuzzing): ").strip()
        #     if session == "":
        #         tests.exec_test_rsda()
        #     elif 0x00 < int(session) < 0xFF:
        #         # exec_test_rsda(, int(session).to_bytes()) # TODO rebuild
        #         pass
        #     else:
        #         print("wrong session inserted, try again")
        #         skip_input = True

        elif command == "request_seed":
            rt = int(input("reset_type: "), 16)
            d = int(input("delay: "), 16)
            s = int(input("session: "), 16)
            sat = int(input("sa_type: "), 16)
            
            tests.exec_test_seed_request(reset_type=rt, delay=d, session=s, sa_type=sat)
                
        elif command == "get_current_session":
            tests.get_current_session()

        elif command == "set_new_session":
            session=int(input("Enter the new session: "), 16)
            tests.set_new_session(session)

        elif command == "request_upload":
            tests.exec_test_req_upload()

        elif command == "test_recu":
            subfunction=int(input("Enter the subfunction: "))
            tests.exec_test_recu(subfunction)     

        else:
            utility.print_error("error: the inserted command does not exist")
            print("ERROR in command parsing")

    ctx_man.CAN_SOCKET.close()
    utility.print_success("PROGRAM CLOSED.")


if __name__ == "__main__":
    main()


