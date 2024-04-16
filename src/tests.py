# file containing the testcases for ECU blackbox testing

import utility
from configuration import config_manager as ctx_man
            
# TODO: fare un test utility per leggere la sessione di diagnostica corrente \
# (usa RDBI a forse anche un UDS service)
# TODO: bruteforce test passed 
# TODO: seed randomness / test for measuring RNBG entropy 
# TODO: given a packet, reply it
# TODO test for control ECU communication 
# TODO test for control link baud rate 
# TODO: command for maintain a given session
# TODO: test for requesting security access
# TODO: test for available services
# TODO: reset ecu hard or soft then clear DTC info (service 0x14 --> 04.14.FF.FF.FF.00.00.00)
# TODO: idea da ISO UDS



# ============================================================================ #
# =                                GLOBALS                                   = #
# ============================================================================ #
# variables used to establish the correct packet format in tester present
lengths = [1, 2, 1, 2, 2, 2, 1, 2] # TODO: is it really global?
payloads =  [  # TODO: is it really global?
            b'\x01\x3E',
            b'\x02\x3E\x00',
            b'\x01\x3E\x00\x00\x00\x00\x00\x00',
            b'\x02\x3E\x00\x00\x00\x00\x00\x00',
            b'\x02\x3E\x80',
            b'\x02\x3E\x80\x00\x00\x00\x00\x00', 
            b'\x01\x3E\x66\x66\x66\x66\x66\x66',
            b'\x02\x3E\x00\x55\x55\x55\x55\x55'
            ]
passed = [False for i in range(0,8)]



# ============================================================================ #
# =                                TEST_TP                                   = #
# ============================================================================ #
# TODO: this test is shit because padding is applied underneath
def exec_test_tp() -> None:
    """
    Several tester present packet formats probing.

    This function modifies the flag global variable setting True in the
    position relative to the passed test, based on sr() response parsing.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """

    global lengths, payloads, passed
    print("\nBLACK-BOX TESTING\n")
    print("First, we test for length and packet format with TP CAN message. \n"
          "The following packets are sent (note that probably the underlying\n"
          "implementation adds \\x00 padding):\n")

    # ID is a value on 11 bits
    # testing for different lengths and data values

    can_socket = ctx_man.getCanSocket()

    for i in range(0,8):
        tp = utility.CAN(identifier=ctx_man.getCanId(),
                 length=8,
                 data=payloads[i])
        
        ans, _ = can_socket.sr(tp, timeout=1, verbose=0)
        # ans[0] to read the first answer
        # ans[0].answer to access the CAN object in the query-answer object
        # note that we may not receive a response, thus the exception handling      
        try: 
            if ans[0] and ans[0].answer.data[1] == 0x7E: # positive response
                passed[i] = True
        except IndexError:
            continue
        
    print("Checking passed tests...\n")
    for idx, flag in enumerate(passed):
        if flag:
            print(f"Positive response from payload: ")
            utility.print_hex(payloads[idx])
            print(f"with length: {lengths[idx]}")



def send_selected_tester_present(socket: utility.NativeCANSocket,
                                 can_id: int,
                                 ) -> bool:
    """
    Sends just one TP packet, based on previously determined conditions.

    :param socket: the socket connected to the can or vcan interface
    :param can_id: # TODO and check all the other functions for this param
    :return: True at the first positive response, False otherwise.
    """
    global payloads, passed

    for i, flag in enumerate(passed):
        if flag is True:
            selected_request = utility.CAN(identifier=can_id,
                                    length=8,
                                    data=payloads[i])

            tp_ans, _ = socket.sr(selected_request, inter=0.5, retry=-2, timeout=1, verbose=0)
            # print("tester present response: ")
            # print(tp_ans[0].answer.data)
            if tp_ans[0] and tp_ans[0].answer.data[1] == 0x7E:
                return True
            else:
                continue

    utility.print_error("Something went wrong in TesterPresent probe\n")
    return False

# ============================================================================ #
# =                                TEST_DDS                                  = #
# ============================================================================ #
# Test for discovering supported diagnostic sessions (TEST_DDS)
def exec_test_dds(current_node: int=0x01) -> None:
    """
    It explore the session space recursively and builds a graph of available 
    sessions. 

    :param can_socket: socket connected to the CAN (or vcan) interface
    :param client_can_id: CAN bus identifier to use in CAN message 
    :param session_graph: graph representing the automaton of the available ECU 
    sessions
    :param current_node: where the function is arrived in session exploration
    :return: -
    """
    can_socket = ctx_man.getCanSocket()
    client_can_id = ctx_man.getCanId()
    session_graph = ctx_man.getSessionGraph()
    # scan the session space
    for new_session in range(1, 256): 

        active_session = current_node
        dsc = utility.create_packet(can_id=client_can_id, 
                            service=0x10, 
                            subservice=active_session)
        
        # maintain the current session
        res, _ = utility.send_receive(dsc, can_socket) 
        # TODO other NRC can be analysed, not only positive responses

        # if not already found
        if not session_graph.findChildNode(active_session, new_session): 
            session_probe = utility.create_packet(can_id=client_can_id, 
                                          service=0x10, 
                                          subservice=new_session)

            res, _ = utility.send_receive(session_probe, can_socket)

            try: 
                if res[0].answer.data[1] == 0x50: # session is reachable
                    session_graph.AddEdge([active_session, new_session])
                    session_graph.addVertex(new_session)
                    # recursive exploration from new session
                    exec_test_dds(current_node=new_session) 
            except:
                utility.print_debug("An exception occured.")
                


# ============================================================================ #
# =                               TEST_RECU                                  = #
# ============================================================================ #
def exec_test_recu() -> None:
    """
    It requests different ECU resets by UDS service 0x11.

    This test shall be repeated for each active diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) 
    :param client_can_id: CAN bus identifier to use in CAN message
    :param session_graph: graph representing the automaton of the available ECU 
    sessions
    :return: -
    """
    utility.print_new_test_banner()
    print("Starting TEST_RECU\n")

    can_socket = ctx_man.getCanSocket()
    client_can_id = ctx_man.getCanId()
    session_graph = ctx_man.getSessionGraph()
    
    for ses in session_graph.getVertices():

        utility.print_debug(f"ses: {ses}")

        packets = utility.fuzz(can_id=client_can_id, 
                       service=0x11,
                       fuzz_subservice=True, 
                       fuzz_subservice_range=0xFF)
    
        for i,p in enumerate(packets):
            # diagnostic session control
            dsc = utility.create_packet(can_id=client_can_id, 
                                service=0x10, 
                                subservice=ses)
            _, _ = utility.send_receive(dsc, can_socket) 
            # TODO check result
            # TODO make a send_diagnosti_session_control()

            res, _ = utility.send_receive(p, can_socket)
            ret = utility.read_response_code(res)
            if ret != -1:
                print(f"{i}: ", end="")
                utility.check_response_code(11, ret)
            else:
                print("{i}: strange behaviour, ECU is not responding?")
                print(f"double check session {ses} and packet {p.show()}")

    print("TEST_RECU finished.\n")


# ============================================================================ #
# =                               TEST_RDBI                                  = #
# ============================================================================ #
def exec_test_rdbi() -> None:
    """
    It requests an ECU data read, exploiting the 0x22 UDS service.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    utility.print_new_test_banner()
    print("Starting TEST_RDBI\n")

    can_socket = ctx_man.getCanSocket()

    utility.print_error("trying rdbi using fuzz range as DIDs....")
    # TODO change with new functions
    # create_and_send_packet(can_socket, 0x22, None, None, 0, 0xFFFF, False, True)

    print("TEST_RDBI finished.\n")


# ============================================================================ #
# =                               TEST_RSDA                                  = #
# ============================================================================ #
def exec_test_rsda(session: bytes = b'') -> None:
    """
    It requests an ECU data read by memory address, service 0x23.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected by the CAN (or vcan) interface
    :param session:
    :return: -
    """
    utility.print_new_test_banner()
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


# ============================================================================ #
# =                               TEST_RSSDI                                 = #
# ============================================================================ #
# TODO: rebuild this function
def exec_test_rssdi(can_socket: utility.NativeCANSocket, can_id: int) -> None:
    """
    It requests an ECU data read, exploiting the 0x24 UDS service.

    This test shall be repeated for each supported diagnostic session.
    :param can_socket: socket connected to the CAN (or vcan) interface
    :return: -
    """
    utility.print_new_test_banner()
    print("Starting TEST_RSSDI\n")

    if not send_selected_tester_present(can_socket, can_id):
        utility.print_error("ERROR: tp failed!")
    utility.print_success("tester present correctly received")

    for session in range(0, 0xFF+1):
        payload = b'\x10' + session.to_bytes(1, 'little')
        rssdi_pkt = utility.CAN(identifier=can_id, 
                        length=2, 
                        data=payload)
        ans_rssdi_test = can_socket.sr(rssdi_pkt, verbose=0)[0]
        response_code = ans_rssdi_test[0].answer.data[0]
        if not utility.check_response_code(0x10, response_code):
            utility.print_error("ERROR in packet response")
        else:
            # TODO: multi-framing must be handled in the callee
            # TODO: some information should be recorded
            # TODO change with new functions
            # create_and_send_packet(can_socket, 0x24, 0xFFFF, multiframe=True)
            pass
    print("TEST_RSSDI finished.\n")



# ============================================================================ #
# =                              TEST_ISOTP                                  = #
# ============================================================================ #
def isotp_scanning(can_socket: utility.NativeCANSocket) -> None:
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

    _ = utility.isotp_scan(can_socket) #, output_format="text") #, verbose=True)


