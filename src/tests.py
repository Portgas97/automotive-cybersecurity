
# file containing the testcases for ECU blackbox testing

import utility
from scapy.all import Raw
from configuration import config_manager as ctx_man
from scapy.contrib.automotive.uds import UDS, UDS_RDBI, UDS_RDBIPR, UDS_TP, UDS_TPPR, UDS_RU, UDS_RUPR, \
                                         UDS_DSC, UDS_DSCPR, UDS_ER, UDS_ERPR, UDS_WDBI, UDS_WDBIPR, \
                                         UDS_SA, UDS_SAPR, UDS_NR


# ============================================================================ #
# =                                GLOBALS                                   = #
# ============================================================================ #
# variables used to establish the correct packet format in tester present
lengths = [1, 2, 1, 2, 2, 2, 1, 2] 
payloads =  [  
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
# =                                TEST_DDS                                  = #
# ============================================================================ #
# Test for discovering supported diagnostic sessions (TEST_DDS)
def exec_test_dds(current_node: int=0x01) -> None:
    """
    It explore the session space recursively and builds a graph of available 
    sessions. 

    :param current_node: where the function is arrived in session exploration
    :return: -
    """
    can_socket = ctx_man.getCanSocket()
    client_can_id = ctx_man.getCanId()
    session_graph = ctx_man.getSessionGraph()
    
    # scan the session space
    for new_session in range(1, 256): 

        active_session = current_node   

        if active_session == new_session:
            continue

        if not utility.send_diagnostic_session_control(active_session):
            utility.print_error(f"Diagnostic Session Control error, from"
                                f"{hex(active_session)} to {hex(new_session)}")
            ctx_man.ToCheckGraph.addVertex(active_session)
            ctx_man.ToCheckGraph.addVertex(new_session)
            ctx_man.ToCheckGraph.AddEdge([active_session, new_session])
            continue

        recursion = True
        if new_session in session_graph.getVertices():
            recursion = False

        session_probe = utility.create_packet(service=0x10, 
                                                subservice=new_session)

        res, _ = utility.send_receive(session_probe)

        try: 
            # TODO other NRC can be analysed, not only positive responses
            # print(f"From {hex(active_session)} to {hex(new_session)}", end="")
            # ret = utility.read_response_code(res)
            # utility.check_response_code(0x10, ret, ['ALL'])

            if utility.read_response_code(res) == 0x50: # session is reachable
                session_graph.AddEdge([active_session, new_session])
                session_graph.addVertex(new_session)
                # recursive exploration from new session
                if recursion:
                    exec_test_dds(current_node=new_session) 
        except:
            utility.print_debug("An exception occured.")
                


# ============================================================================ #
# =                               TEST_RECU                                  = #
# ============================================================================ #
def exec_test_recu(subfunction :int) -> None:
    """
    It requests different ECU resets by UDS service 0x11. This test shall be \
    repeated for each active diagnostic session.

    :param subfunction: the kind of reset to be performed. 
    :return: -

    """
    # utility.print_new_test_banner()
    # print("Starting TEST_RECU\n")

    recu_pkt = UDS()/UDS_ER(resetType=subfunction)

    res, _ = utility.send_receive(recu_pkt)

    if utility.read_response_code(res) == 0x51:
        print("resetting ECU")
    else:
        print("Some error occured. See packet:")
        try:
            print(res[0].answer.show())
        except:
            print("retry, no response detected.")


    #### OLD to remove
    # can_socket = ctx_man.getCanSocket()
    # client_can_id = ctx_man.getCanId()
    # session_graph = ctx_man.getSessionGraph()
    
    # for ses in session_graph.getVertices():

    #     utility.print_debug(f"scanning session: {hex(ses)}")

    #     packets = utility.fuzz(service=0x11,
    #                            fuzz_subservice=True, 
    #                            fuzz_subservice_range=0xFF)
    
    #     for p in packets:
            
    #         utility.print_debug("-------------------------------------------")
    #         if not utility.send_diagnostic_session_control(ses):
    #             utility.print_error("diagnostic session control error")
    #             continue 
    #         print(p.show())
    #         res, _ = utility.send_receive(p)
    #         ret = utility.read_response_code(res)
    #         subret = utility.read_subresponse_code(res) # TO DO check with new third param
    #         if ret == 0x51:
    #             print(f"Session {ses} allows packet {p.show()}")
    #         elif ret != -1:
    #             utility.check_response_code(11, ret, flag_list=['NEG'])
    #             utility.check_response_code(11, subret, flag_list=['NEG'])
    #         else:
    #             print("{i}: strange behaviour, ECU is not responding?")
    #             print(f"double check session {ses} and packet {p.show()}")

    # print("TEST_RECU finished.\n")


# ============================================================================ #
# =                            TEST_SCAN_RDBI                                = #
# ============================================================================ #
def exec_test_scan_rdbi(explore_sessions: bool =False) -> None:
    """
    It requests an ECU data read, exploiting the 0x22 UDS service.

    :param explore_sessions: if True, performs the scan in all the available sessions
    :return: -
    """
    utility.print_new_test_banner()
    print("Starting TEST_RDBI\n")

    can_socket = ctx_man.getCanSocket()

    if explore_sessions:
        session_range = ctx_man.SessionsGraph.getVertices()
    else:
        session_range = [0x01]

    for session in session_range: # general test, in studied case the different sessions produce same results
        
        rdbi_packets = utility.fuzz(service=0x22, 
                                    fuzz_data=True, 
                                    fuzz_data_range=0xFFFF)
        
        for packet in rdbi_packets:
            
            utility.send_diagnostic_session_control(session)
            # TODO oppure mando 1 fuori e start tester present thread?
            result_list, _ = utility.send_receive(packet, multiframe=True)  
            for i in range(len(result_list)):
                if i != 0:
                    print(f"Result {i}") # TODO remove, check multiframing
                ret = utility.read_response_code(result_list, i)
                subret = utility.read_subresponse_code(result_list, i, 3)
                if ret == 0x62:
                    print("data from {:02X}{:02X}:\t".format(result_list[i].query.data[2], result_list[i].query.data[3]), end="")
                    ans_len = result_list[i].answer.data[0]
                    
                    # do not print datalen, UDS service, and associated DID
                    for k in range(4, ans_len + 1):
                        print("{:02X}".format(result_list[i].answer.data[k]), end="")
                    print("\t\t|\t", end="")
                    for k in range(2, ans_len + 1):
                        if not str(result_list[i].answer.data[k]).isprintable():
                            print('-', end="")
                        else:
                            print("{:c}".format(result_list[i].answer.data[k]), end="")
                    did = utility.concatenate_hex(result_list[i].query.data[2], result_list[i].query.data[3])
                    utility.interpret_did(did)

                    # print(result_list[i].answer.data.hex())
                    
                else:
                    pass
                    # utility.print_debug("{:02X}{:02X}:".format(result_list[i].query.data[2], result_list[i].query.data[3]), end="")
                    # if ctx_man.VERBOSE_DEBUG:
                        # utility.check_response_code(0x22, subret, ['NEG'])

    print("TEST_RDBI finished.\n")



# ============================================================================ #
# =                                TEST_TP                                   = #
# ============================================================================ #
# TODO may be no more useful
def exec_test_tp() -> None:
    """
    Several tester present packet formats probing.

    This function modifies the flag global variable setting True in the
    position relative to the passed test, based on sr() response parsing.
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

    """
    for i in range(0,8):
        tp = utility.CAN(identifier=ctx_man.getCanId(),
                 length=8,
                 data=payloads[i])
        
        ans, _ = can_socket.sr(tp, timeout=1, verbose=0)
        # ans[0] to read the first answer
        # ans[0].answer to access the CAN object in the query-answer object
        # note that we may not receive a response, thus the exception handling      
        try: 
            if ans[0] and utility.read_response_code(ans) == 0x7E: # positive response
                passed[i] = True
        except IndexError:
            continue
        
    print("Checking passed tests...\n")
    for idx, flag in enumerate(passed):
        if flag:
            print(f"Positive response from payload: ")
            utility.print_hex(payloads[idx])
            print(f"with length: {lengths[idx]}")
    """ 

    tp_pkt = UDS()/UDS_TP() #/Raw(b'\x00\x00\x00\x00\x00')
    print(tp_pkt)

    print('-')

    print(tp_pkt.show())
    # print(tp_pkt)
    # if UDS in tp_pkt:
    #     print("ok")
    #     layer_after = tp_pkt[UDS].payload.copy()
    # pad = Padding()
    # pad.load = '\\x00' * 5  # Adjust the number of zeros as needed
    # layer_before = tp_pkt.copy()
    # layer_before[UDS].remove_payload()
    # tp_pkt = layer_before / Raw(pad) / layer_after

    can_socket.sr(tp_pkt, timeout=1, verbose=1)



def send_selected_tester_present(socket: utility.NativeCANSocket,
                                 can_id: int,
                                 ) -> bool:
    """
    Sends just one TP packet, based on previously determined conditions.

    :param socket: the socket connected to the can or vcan interface
    :param can_id: the CAN identifier to set in the request
    :return: True at the first positive response, False otherwise.
    """
    global payloads, passed

    for i, flag in enumerate(passed):
        if flag is True:
            selected_request = utility.CAN(identifier=can_id,
                                    length=8,
                                    data=payloads[i])

            tp_ans, _ = socket.sr(selected_request, inter=0.5, retry=-2, timeout=1, verbose=0)
            if tp_ans[0] and utility.read_response_code(tp_ans) == 0x7E:
                return True
            else:
                continue

    utility.print_error("Something went wrong in TesterPresent probe\n")
    return False


# ============================================================================ #
# =                               TEST_RDBI                                  = #
# ============================================================================ #
def exec_test_rdbi(did :int) -> None:
    """
    It requests data from the passed data identifier. 

    :param did: integer representing the DID to query.
    :return: displays information on the screen. 
    """
    req_rdbi_pkt = UDS()/UDS_RDBI(identifiers=[did])
    
    res, _ = utility.send_receive(req_rdbi_pkt)   

    # print(res[0].answer)
    if utility.read_response_code(res) == 0x62:
        print("Read DID performed")
        print("Data:")
        print(res[0].answer.load)
    else:
        print("Error in RDBI")



# ============================================================================ #
# =                               TEST_WDBI                                  = #
# ============================================================================ #
def exec_test_wdbi(did :int, data :int) -> None:
    """
    Writes data into did (UDS service 0x2E)

    :param did: where to write
    :param data: what to write
    :return: nothing, displays information to the screen. 
    """
    data_bytes = data.to_bytes(2, 'big')
    req_wdbi_pkt = UDS()/UDS_WDBI(dataIdentifier=did)/Raw(data_bytes)
    
    res, _ = utility.send_receive(req_wdbi_pkt)   

    # print(res[0].answer)
    if utility.read_response_code(res) == 0x6E:
        print("Write DID performed")
        print("Data:")
        print(res[0].answer.load)
    else:
        print("Error in WDBI")



# ============================================================================ #
# =                               TEST_RSDA                                  = #
# ============================================================================ #
# TODO update, but not necessary for the thesis
def exec_test_rsda(session: bytes = b'') -> None:
    """
    It requests an ECU data read by memory address, service 0x23.

    This test shall be repeated for each supported diagnostic session.
    :param session:
    :return: -
    """
    utility.print_new_test_banner()
    print("Starting TEST_RSDA\n")

    if session != b'':
        for address in range(0x0000, 0xFFFF):
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
            # create_and_send_packet(can_socket=can_socket,
            #                        service= 0x23, 
            #                        subservice=None,
            #                        data=data_payload,
            #                        data_len= 4,
            #                        fuzz_range=0)
    else: 
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
# TODO, update but not necessary for the thesis
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
        response_code = ans_rssdi_test[0].answer.data[1]
        if not utility.check_response_code(0x10, response_code):
            utility.print_error("ERROR in packet response")
        else:
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



# ============================================================================ #
# =                          TEST_REQUEST_SEED                               = #
# ============================================================================ #

def exec_test_seed_request(reset_type :int=0, 
                           delay :int=0, 
                           session :int=0, 
                           sa_type :int=0) -> None:
    """
    Request a seed in the SecurityAccess service. 

    :param reset_type: which kind of reset to perform priori to the seed request
    :param delay: if >0, waits delay seconds prior to the seed request, after the reset
    :param session: in which session perform the request
    :param sa_type: subservice to set
    :return: nothing, displays information
    """
    if reset_type:
        er_pkt = UDS()/UDS_ER(resetType=reset_type)

        res, _ = utility.send_receive(er_pkt)   

        if utility.read_response_code(res) == 0x51:
            utility.print_debug("ecu_reset done.")
        else:
            print("Error in ecu reset.")

    import time
    time.sleep(delay)

    # Go to correct session
    if session:
        # this dsc is not general (not always a direct access can be performed)
        # a session_path should be passed 
        dsc_packet = UDS()/UDS_DSC(diagnosticSessionType=session)
        res, _ = utility.send_receive(dsc_packet) 
        if utility.read_response_code(res) == 0x50: 
            utility.print_debug("Session entered")

    # Request seed
    sa_pkt = UDS()/UDS_SA(securityAccessType=sa_type)
    res, _ = utility.send_receive(sa_pkt)

    if utility.read_response_code(res) == 0x67:
        print(res.securitySeed.hex())
    else: 
        # print("Seed request failed (" + UDS_NR.negativeResponseCodes[res.negativeResponseCode] + ")")
        print("sa-seed_request failed")


# ============================================================================ #
# =                        GET_CURRENT_SESSION                               = #
# ============================================================================ #
def get_current_session() -> int:
    """
    Retrieves the current active session for the user in the ECU exploiting
    data identifier XXXX. 

    :return: integer representing the current active session
    """
    cur_ses_packet = UDS()/UDS_RDBI(identifiers=[0xF186]) # = utility.create_packet(0x22, 0, b'\xF1\x89', 2)

    res, _ = utility.send_receive(cur_ses_packet)

    if utility.read_response_code(res) == 0x62:
        print("data: ", end="")
        cur_ses = int.from_bytes(res[0].answer.load, 'little')
        print(hex(cur_ses))
        return cur_ses
    else:   
        return -1 
    

def set_new_session(session :int) -> None:
    """
    This function sets the session in the server ECU through the usage
    of the diagnostic session control service (0x10)

    :param session: integer, it is the new session to set
    :return: - 
    """
    new_ses_pkt = UDS()/UDS_DSC(diagnosticSessionType=session)
    res, _ = utility.send_receive(new_ses_pkt)

    if utility.read_response_code(res) == 0x50:
        print("new session correctly established")
        print("REMEMBER TO MAINTAIN IT!")
    else:
        print("error in new session establishment")


# ============================================================================ #
# =                                 TP_LOOP                                  = #
# ============================================================================ #
# TODO thread for tester present sending (currently implemented in a bash script)



# ============================================================================ #
# =                         TEST_REQUEST_UPLOAD                              = #
# ============================================================================ #
def exec_test_req_upload():
    """
    Performs an upload request. 

    :return: nothing, displays status information. 
    """
    req_up_pkt = UDS()/UDS_RU(dataFormatIdentifier=0x0000, 
                              memorySizeLen=2, 
                              memoryAddressLen=2, 
                              memoryAddress1=0xFF00, 
                              memorySize1=0x01)
    
    res, _ = utility.send_receive(req_up_pkt)   

    print(res[0].answer)
    if utility.read_response_code(res) == 0x75:
        print("Request upload successfully sent")
        print("Data:")
        print(res[0].answer.load)
    else:
        print("Error in request upload")


# TODO reset ecu hard or soft then clear DTC info (service 0x14 --> 04.14.FF.FF.FF.00.00.00)
# TODO Sending session change requests for session 0x2 in a loop while ECU boots up
# TODO seed randomness / test for measuring RNBG entropy (currently using cc.py)
# TODO or sending tester present requests while ECU boots up
# TODO test for available services (currently using cc.py)
# TODO given a packet, reply it (can be done on canutils)
# TODO test for control link baud rate 