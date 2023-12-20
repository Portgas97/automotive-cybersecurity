# file containing all the testcases for the blackbox testing
import sys

from utility import *

#################################  TEST_TP  #################################
def exec_test_tp():
    print("\nBLACK-BOX TESTING\n")
    print("First, we test for length and packet format with TP CAN message. \n"
          "The following packets are sent (note that probably the underlying\n"
          "implementation adds \\x00 padding):\n")

    ans_list = [[] for i in range(0,7)]
    unans_list = [[] for i in range(0,7)]

    sock_vcan0 = NativeCANSocket(channel="vcan0")

    # ID is a value on 29 bits
    # testing for different lengths and data values
    for i in range(0,7):
        tp = CAN(identifier=CAN_IDENTIFIER,
                 length=lengths[i],
                 data=payloads[i])
        hexdump(tp)
        ans, unans = sock_vcan0.sr(tp, verbose=0)
        ans_list[i].append(ans)
        unans_list[i].append(unans)

        # ans[0] to read the first answer
        # ans[0].answer to access the CAN object in the query-answer object
        ## print("The returned payload should be the following:")
        ## print(ans[0].answer.data)

        if ans[0] and ans[0].answer.data[0] == 0x7E:
            passed[i] = True

    print("Checking passed tests...\n")
    for idx, flag in enumerate(passed):
        if flag:
            print_success(f"Positive response from payload: {payloads[idx]} "
                    f"with length: {lengths[idx]}")

    return sock_vcan0


# bruteforce test passed TO DO

def byte_length(hex_int):
    return (hex_int.bit_length() + 7) // 8

def create_and_send_packet(can_socket,
                           service,
                           fuzz_range,
                           pkt_length,
                           can_id=CAN_IDENTIFIER):
    print_debug(f"passed args: "
                f"can_socket: {can_socket}, service: {service}, fuzz_range: "
                f"{fuzz_range}, pkt_length: {pkt_length}, can_id: {can_id}")

    for idx in range(0, fuzz_range + 1):
        print_debug(f"\nidx: {idx}")
        byte_len = byte_length(fuzz_range)
        print_debug(f"byte_len: {byte_len}")
        print_debug(f"hex_service: {service.to_bytes(1,'little')}")
        print_debug(f"idx_hex:{idx.to_bytes(1, 'little')}")
        fuzz_value = (service.to_bytes(1, 'little') +
                      idx.to_bytes(byte_len, 'little'))
        print_debug(f"fuzz_value: {fuzz_value}")
        test_pkt = CAN(identifier=can_id,
                       length=pkt_length,
                       data=fuzz_value)
        # print_debug(f"test_pkt: {test_pkt.show()}")
        print_debug("waiting for test packet...")
        test_ans = can_socket.sr(test_pkt, verbose=0)[0]
        if not test_ans[0]:
            continue

        response_code = test_ans[0].answer.data[0]
        print_debug(f"service: {service}")
        check_response_code(service, response_code)


#################################  TEST_DDS  #################################
# Test for discovering supported diagnostic sessions (TEST_DDS)
def exec_test_dds(can_socket):
    print_new_test_banner()
    print("Starting TEST_DDS\n")

    if not send_selected_tester_present(can_socket, passed):
        exit()
    print_success("tester present correctly received")

    create_and_send_packet(can_socket, 0x10, 0xFF, 2)
    print("TEST_DSS finished.\n")


#################################  TEST_RECU  #################################
# Test reset of the ECU (TEST_RECU)
# request and ECU hard reset by UDS service 0x11

def exec_test_recu(can_socket):
    print_new_test_banner()
    print("Starting TEST_RECU\n")

    continue_subtest = True
    payload = b'\x11'
    for i in range(0, 0xFF + 1):
        fuzz_value = payload + i.to_bytes(1, 'little')
        print_debug(f"fuzz value: {fuzz_value}")
        if i < 0x06:
            if not send_selected_tester_present(can_socket, passed):
                exit()
            print_success("tester present correctly received")
        recu_pkt = CAN(identifier=CAN_IDENTIFIER, length=2, data=fuzz_value)
        ans_recu_test = can_socket.sr(recu_pkt, verbose=0)[0]
        response_code = ans_recu_test[0].answer.data[0]
        if check_response_code(0x11, response_code):
            break
    print("TEST_RECU finished.\n")


#################################  TEST_  #################################
# test for measuring RNBG entropy TO DO


#################################  TEST_  #################################
# test for control ECU communication TO DO


#################################  TEST_  #################################
# test for control link baud rate TO DO


#################################  TEST_RSDI  #################################
def exec_test_rsdi(can_socket):
    print_new_test_banner()
    print("Starting TEST_RSDI\n")

    if not send_selected_tester_present(can_socket, passed):
        exit()
    print_success("tester present correctly received")

    create_and_send_packet(can_socket, b'0x22', 0xFFFF, 3)
    print("TEST_RSDI finished.\n")


