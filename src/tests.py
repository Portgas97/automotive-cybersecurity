# file containing all the testcases for the blackbox testing

import utility
from utility import *

#################################  TEST_TP  #################################
def exec_test_tp(can_socket: NativeCANSocket) -> None:
    """
    Several tester present packet formats probing.

    This function modifies the flag global variable setting True in the
    position relative to the passed test, based on sr() response parsing.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print("\nBLACK-BOX TESTING\n")
    print("First, we test for length and packet format with TP CAN message. \n"
          "The following packets are sent (note that probably the underlying\n"
          "implementation adds \\x00 padding):\n")

    # ID is a value on 11 bits
    # testing for different lengths and data values
    for i in range(0,8):
        tp = CAN(identifier=CAN_IDENTIFIER,
                 length=8,
                 data=payloads[i])

        ans, _ = can_socket.sr(tp, timeout=1, verbose=0)

        # ans[0] to read the first answer
        # ans[0].answer to access the CAN object in the query-answer object
        # note that we may not receive a response, thus the exception handling
        global passed       
        try: 
            if ans[0] and ans[0].answer.data[1] == 0x7E: # positive response
                passed[i] = True
        except IndexError:
            continue
        
    print("Checking passed tests...\n")
    for idx, flag in enumerate(passed):
        if flag:
            print_success(f"Positive response from payload: ")
            print_hex(payloads[idx])
            print_success(f"with length: {lengths[idx]}")


# TO DO fare un test utility in cui si chiama semplicemente send_selected_tester_present
            
# TO DO fare un test utility per leggere la sessione di diagnostica corrente (usa RDBI a forse anche un UDS service)

# TO DO bruteforce test passed 


#################################  TEST_DDS  #################################
# Test for discovering supported diagnostic sessions (TEST_DDS)
def exec_test_dds(can_socket: NativeCANSocket) -> None:
    """
    It exploits UDS 0x10 and fuzzing to discover supported diagnostic sessions.

    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_DDS\n")

    create_and_send_packet(can_socket=can_socket,
                           service=0x10,
                           fuzz_range=0xFF, 
                           inter_tp=True)

    print("TEST_DSS finished.\n")

#################################  TEST_RECU  #################################
def exec_test_recu(can_socket: NativeCANSocket) -> None:
    """
    It requests and ECU hard reset by UDS service 0x11.

    This test shall be repeated for each active diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RECU\n")

    # TO DO apply in available sessions

    create_and_send_packet(can_socket=can_socket, 
                           service=0x11, 
                           subservice=None, 
                           data=None, 
                           data_len=0, 
                           fuzz_range=0xFF)

    print("TEST_RECU finished.\n")

#################################  TEST_  #################################
# test for measuring RNBG entropy TO DO

#################################  TEST_  #################################
# test for control ECU communication TO DO

#################################  TEST_  #################################
# test for control link baud rate TO DO

#################################  TEST_RSDI  #################################
def exec_test_rdbi(can_socket: NativeCANSocket) -> None:
    """
    It requests an ECU data read, exploiting the 0x22 UDS service.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RDBI\n")

    print_error("trying rdbi using fuzz range as DIDs....")
    create_and_send_packet(can_socket, 0x22, None, None, 0, 0xFFFF, False, True)

    print("TEST_RDBI finished.\n")

#################################  TEST_RSDA  #################################
def exec_test_rsda(can_socket: NativeCANSocket, session: bytes = b'') -> None:
    """
    It requests an ECU data read by memory address, service 0x23.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected by the CAN (or vcan) interface
    :param session:
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RSDA\n")

    if session != b'':
        for address in range(0x0000, 0xFFFF):
            create_and_send_packet(can_socket=can_socket, 
                                   service=0x10,
                                   subservice=session,
                                   fuzz_range=1, 
                                   inter_tp=True,
                                   multiframe=True)
            
            # |  addressAndLengthFormatIdentifier  |  memoryAddress  |  memorySize  |
            data_payload =    0x12.to_bytes(1, 'little')     \
                            + address.to_bytes(2, 'little')  \
                            + 0x01.to_bytes(1, 'little')
            
            create_and_send_packet(can_socket=can_socket,
                                   service= 0x23, 
                                   subservice=None,
                                   data=data_payload,
                                   data_len= 4,
                                   fuzz_range=0)
    else: 
        create_and_send_packet(can_socket=can_socket,
                               service=0x10,
                               subservice=None, 
                               fuzz_range=0xFF,
                               inter_tp=True,
                               multiframe=True)


    

#################################  TEST_RSSDI  ################################
# TO DO rebuild this function
def exec_test_rssdi(can_socket: NativeCANSocket) -> None:
    """
    It requests an ECU data read, exploiting the 0x24 UDS service.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RSSDI\n")

    if not send_selected_tester_present(can_socket, passed):
        print_error("ERROR: tp failed!")
    print_success("tester present correctly received")

    for session in range(0, 0xFF+1):
        payload = b'\x10' + session.to_bytes(1, 'little')
        rssdi_pkt = CAN(identifier=CAN_IDENTIFIER, length=2, data=payload)
        ans_rssdi_test = can_socket.sr(rssdi_pkt, verbose=0)[0]
        response_code = ans_rssdi_test[0].answer.data[0]
        if not check_response_code(0x10, response_code):
            print_error("ERROR in packet response")
        else:
            # TO DO multi-framing must be handled in the callee
            # TO DO some information should be recorded
            create_and_send_packet(can_socket, 0x24, 0xFFFF, multiframe=True)
    print("TEST_RSSDI finished.\n")

# TO DO seed randomness
# TO DO given a packet, reply it
# TO DO fuzzing create and send packets
# 
def isotp_scanning(can_socket: NativeCANSocket):
    """
    A transport layer scan.

    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
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

    # # # # # # # # # # # # # # # # #  STEP 1  # # # # # # # # # # # # # # # # #
    # On CAN networks, ISOTP (ISO-15765 Transport Protocol) is a communication
    # protocol used in the automotive industry to transmit data. It is designed to
    # provide a reliable and efficient way to transfer large amounts of data,
    # such as software updates and diagnostic data.
    #
    # There are four special frames:
    #   - single frame
    #   - first frame
    #   - consecutive frame
    #   - flow control frame
    #
    # It is used to address every individual ECU in the entire vehicle network.
    # The gateway ECU will route ISOTP packets into the right subnet automatically.
    # ISOTP supports several addressing schemes. Unfortunately, every OEM uses
    # different addressing schemes: a good practice is to scan for ECUs with normal
    # addressing with a CAN identifier range from 0x500-0x7ff.

    print("\nISO-TP SCANNING...", end="")

    isotp_scan_socket = isotp_scan(can_socket, verbose=True)

def set_my_can_id(id_value: int) -> None:
    """
    Set the CAN_ID global variable to work with a specific CAN ID value in next tests. 

    :param id_value: the value of the ID to set
    :return: -
    """
    utility.CAN_IDENTIFIER = id_value

def set_listen_can_id(id_value: int) -> None:
    """
    Updates the socket can filters to listen for correct messages. 

    :param id_value: the value of the ID to listen to
    :return: -
    """
    utility.sock_can = NativeCANSocket(channel=CAN_INTERFACE, 
                               can_filters=[{'can_id': id_value, 'can_mask': 0x7ff}])
