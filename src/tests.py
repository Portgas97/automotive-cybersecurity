# file containing the testcases for ECU blackbox testing

from utility import *
import global_

            
# TODO: fare un test utility per leggere la sessione di diagnostica corrente 
# (usa RDBI a forse anche un UDS service)
# TODO: bruteforce test passed 
# TODO: seed randomness / test for measuring RNBG entropy 
# TODO: given a packet, reply it
# TODO test for control ECU communication 
# TODO test for control link baud rate 



#################################  TEST_TP  #################################
# TODO: this test is shit because padding is applied underneath
def exec_test_tp(can_socket: NativeCANSocket =global_.CAN_SOCKET) -> None:
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
        tp = CAN(identifier=global_.CAN_IDENTIFIER,
                 length=8,
                 data=global_.payloads[i])

        ans, _ = can_socket.sr(tp, timeout=1, verbose=0)

        # ans[0] to read the first answer
        # ans[0].answer to access the CAN object in the query-answer object
        # note that we may not receive a response, thus the exception handling      
        try: 
            if ans[0] and ans[0].answer.data[1] == 0x7E: # positive response
                global_.passed[i] = True
        except IndexError:
            continue
        
    print("Checking passed tests...\n")
    for idx, flag in enumerate(global_.passed):
        if flag:
            print_success(f"Positive response from payload: ")
            print_hex(global_.payloads[idx])
            print_success(f"with length: {global_.lengths[idx]}")


#################################  TEST_DDS  #################################
# Test for discovering supported diagnostic sessions (TEST_DDS)
def exec_test_dds(can_socket: NativeCANSocket =global_.CAN_SOCKET, 
                  session_explored: list[int] =[0x01]) -> None:
    """
    It explore the session space recursively and builds a graph of available 
    sessions. 

    :param can_socket: socket connected to the CAN (or vcan) interface
    :param session_explored: maintains already seen sessions in the recursion
    :return: -
    """

    # PSEUDOCODE
    # fun(session_explored)
    # for i in range(session_space):
    #   k = session_explored.last()
    #   send(10k)
    #   if i not in session_explored:
    #       send(10i)
    #       if 10i available
    #           session_explored.push()
    #           recursive_call
    # session_explored.pop()

    for new_session in range(1, 256): # scan the session space
        active_session = session_explored[-1] 
        dsc = create_packet(0x10, active_session)
        res, _ = send_receive(can_socket, dsc) # maintain the current session
        #check_response_code(0x10, res[0].answer.data[1]) # TODO troppe stampe

        if new_session not in session_explored: # if not already found
            session_probe = create_packet(0x10, new_session)
            res, _ = send_receive(can_socket, session_probe)

            if res[0].answer.data[1] == 0x50: # session is reachable
                session_explored.append(new_session)

                global_.SessionsGraph.addVertex(new_session)
                global_.SessionsGraph.AddEdge({active_session, new_session})

                # recursive exploration from new session
                exec_test_dds(can_socket, session_explored) 

    session_explored.pop(-1)


#################################  TEST_RECU  #################################
def exec_test_recu(can_socket: NativeCANSocket =global_.CAN_SOCKET) -> None:
    """
    It requests and ECU hard reset by UDS service 0x11.

    This test shall be repeated for each active diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RECU\n")

    # TODO: apply in available sessions

    # TODO change with new functions
    # create_and_send_packet(can_socket=can_socket, 
    #                        service=0x11, 
    #                        subservice=None, 
    #                        data=None, 
    #                        data_len=0, 
    #                        fuzz_range=0xFF)

    print("TEST_RECU finished.\n")


#################################  TEST_RSDI  #################################
def exec_test_rdbi(can_socket: NativeCANSocket =global_.CAN_SOCKET) -> None:
    """
    It requests an ECU data read, exploiting the 0x22 UDS service.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RDBI\n")

    print_error("trying rdbi using fuzz range as DIDs....")
    # TODO change with new functions
    # create_and_send_packet(can_socket, 0x22, None, None, 0, 0xFFFF, False, True)

    print("TEST_RDBI finished.\n")

#################################  TEST_RSDA  #################################
def exec_test_rsda(can_socket: NativeCANSocket =global_.CAN_SOCKET, 
                   session: bytes = b'') -> None:
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
            # TODO change with new functions
            # create_and_send_packet(can_socket=can_socket, 
            #                        service=0x10,
            #                        subservice=session,
            #                        fuzz_range=1, 
            #                        inter_tp=True,
            #                        multiframe=True)
            
            # | addressAndLengthFormatIdentifier | memoryAddress | memorySize |
            data_payload =    0x12.to_bytes(1, 'little')     \
                            + address.to_bytes(2, 'little')  \
                            + 0x01.to_bytes(1, 'little')
            # TODO change with new functions
            # create_and_send_packet(can_socket=can_socket,
            #                        service= 0x23, 
            #                        subservice=None,
            #                        data=data_payload,
            #                        data_len= 4,
            #                        fuzz_range=0)
    else: 
        # TODO change with new functions
        # create_and_send_packet(can_socket=can_socket,
        #                        service=0x10,
        #                        subservice=None, 
        #                        fuzz_range=0xFF,
        #                        inter_tp=True,
        #                        multiframe=True)
        pass


#################################  TEST_RSSDI  ################################
# TODO: rebuild this function
def exec_test_rssdi(can_socket: NativeCANSocket =global_.CAN_SOCKET) -> None:
    """
    It requests an ECU data read, exploiting the 0x24 UDS service.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    print_new_test_banner()
    print("Starting TEST_RSSDI\n")

    if not send_selected_tester_present(can_socket, global_.passed):
        print_error("ERROR: tp failed!")
    print_success("tester present correctly received")

    for session in range(0, 0xFF+1):
        payload = b'\x10' + session.to_bytes(1, 'little')
        rssdi_pkt = CAN(identifier=global_.CAN_IDENTIFIER, 
                        length=2, 
                        data=payload)
        ans_rssdi_test = can_socket.sr(rssdi_pkt, verbose=0)[0]
        response_code = ans_rssdi_test[0].answer.data[0]
        if not check_response_code(0x10, response_code):
            print_error("ERROR in packet response")
        else:
            # TODO: multi-framing must be handled in the callee
            # TODO: some information should be recorded
            # TODO change with new functions
            # create_and_send_packet(can_socket, 0x24, 0xFFFF, multiframe=True)
            pass
    print("TEST_RSSDI finished.\n")



#############################  TEST_ISOTPSCANNING  #############################
def isotp_scanning(can_socket: NativeCANSocket =global_.CAN_SOCKET) -> None:
    """
    To identify all possible communication endpoints and their supported
    application layer protocols, a transport layer scan has to be performed
    first.
    Procedure:
      - Choose an addressing scheme
      - Craft FF (first-frame) with payload length e.g. 100
      - Send FF with all possible addresses according to the addressing scheme
      - Listen for FC (flow-control) frames according to the chosen addressing
        scheme
      - If FC is detected, obtain all address information and information about
        padding from the last FF and the received FC (e.g. source address SA,
        target address TA, address extension AE, addressing scheme, padding)
    
    One could also perform passive scanning, not producing additional load

    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    
    print("\nISO-TP SCANNING...", end="")

    _ = isotp_scan(can_socket, output_format="text") #, verbose=True)


################################  SET_CLIENT_ID  ###############################
def set_my_can_id(id_value: int) -> None:
    """
    Set the CAN_ID global variable to work with a specific CAN ID value in next
    tests. 

    :param id_value: the value of the ID to set
    :return: -
    """
    global_.CAN_IDENTIFIER = id_value


################################  SET_SERVER_ID  ###############################

def set_listen_can_id(id_value: int) -> None:
    """
    Updates the socket can filters to listen for correct messages. 

    :param id_value: the value of the ID to listen to
    :return: -
    """
    global_.CAN_SOCKET = NativeCANSocket(channel=global_.CAN_INTERFACE, 
                                         can_filters=[{'can_id': id_value, 
                                                       'can_mask': 0x7ff}])
