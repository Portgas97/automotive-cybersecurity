# -----------------------------------------------------------------------------
# Scapy is a powerful Python-based interactive packet manipulation program and
# library. It can be used to forge or decode packets for a wide number of
# protocols, send them on the wire, capture them, match requests and replies,
# and much more.
# needed to load iso-tp kernel module
# https://github.com/hartkopp/can-isotp
import utility
from utility import *

if len(sys.argv) > 1:
    if sys.argv[1] == "-v":
        utility.VERBOSE_DEBUG = True


# # # # # # # # # # # # # # # # #  STEP 4  # # # # # # # # # # # # # # # # #
# black-box testing of UDS services

# print("can information")
# ls(CAN)

# First, we want to verify the UDS availability

# conf.contribs['CAN']['remove-padding'] = True

CAN_IDENTIFIER = 0x1FFFFFFF # TO DO must be set properly, using scanning
                            # modules

print("\nBLACK-BOX TESTING\n")
print("First, we test for length and packet format with TP CAN message. \n"
      "The following packets are sent (note that probably the underlying\n"
      "implementation adds \\x00 padding):\n")

lengths = [2, 2, 1, 2, 2, 2, 1]
payloads = [b'\x3E\x00\x00\x00\x00\x00\x00',
            b'\x3E\x80\x00\x00\x00\x00\x00',
            b'\x3E\x00\x00\x00\x00\x00\x00',
            b'\x3E\x80\x00\x00\x00\x00\x00',
            b'\x3E\x00',
            b'\x3E\x80',
            b'\x3E']
passed = [False, False, False, False, False, False, False]
ans_list = [[] for i in range(0,7)]
unans_list = [[] for i in range(0,7)]

sock_vcan0 = NativeCANSocket(channel="vcan0")

# ID is a value on 29 bits
# we test for different lengths and data values
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
    print("The returned payload should be the following:")
    print(ans[0].answer.data)

    if ans[0] and ans[0].answer.data[0] == 0x7E:
        passed[i] = True

print("Checking passed tests...\n")
for idx, flag in enumerate(passed):
    if flag:
        print_success(f"Positive response from payload: {payloads[idx]} "
                f"with length: {lengths[idx]}")

def send_selected_tester_present(socket, passed_tests):
    for i, flag in enumerate(passed_tests):
        if flag is True:
            selected_request = CAN(identifier=CAN_IDENTIFIER,
                                    length=lengths[i],
                                    data=payloads[i])
            if VERBOSE_DEBUG:
                print("Waiting for tester present...")
            print(i)
            tp_ans = socket.sr(selected_request, verbose=0)[0]
            if tp_ans[0] and tp_ans[0].answer.data[0] == 0x7E:
                return True
            else:
                continue
    print_error("Something went wrong in TesterPresent probe\n")
    return False
def check_response_code(req_code, resp_code):
    if resp_code == req_code + 0x40:
        print_success("Positive response found")
        return True
    elif resp_code == 0x12:
        print_error("error: subFunctionNotSupported")
    elif resp_code == 0x13:
        print_error("error: incorrectMessageLengthOrInvalidFormat")
        print("WARNING: possible implementation error")
    elif resp_code == 0x22:
        print_error("error: conditionsNotCorrect")
    elif resp_code == 0x33:
        print_error("error: securityAccessDenied")
    else:
        print_error("error: unexpected response")
    return False

# all the subsequent tests must be set according to the previous one

# bruteforce test passed TO DO

# TEST for discovering supported diagnostic sessions (TEST_DDS)
print_new_test_banner()

if not send_selected_tester_present(sock_vcan0, passed):
    exit()
print_success("tester present correctly received")

print("Starting TEST_DDS\n")
payload = b'\x10'
for i in range(0, 0xFF+1):
    fuzz_value = payload + i.to_bytes(1, 'little')

    dds_pkt = CAN(identifier=CAN_IDENTIFIER, length=2, data=fuzz_value)
    ans_dds_test = sock_vcan0.sr(dds_pkt, verbose=0)[0]
    if not ans_dds_test[0]:
        continue

    response_code = ans_dds_test[0].answer.data[0]
    check_response_code(0x10, response_code)

print("TEST_DSS finished.\n")


# TEST reset the ECU (TEST_RECU)
# request and ECU hard reset by UDS service 0x11
print_new_test_banner()

continue_subtest = True
payload = b'\x11'
for i in range(0, 0xFF+1):
    fuzz_value = payload + i.to_bytes(1, 'little')
    print(f"fuzz value: {fuzz_value}")
    if i < 0x06:
        if not send_selected_tester_present(sock_vcan0, passed):
            exit()
        print_success("tester present correctly received")
    recu_pkt = CAN(identifier=CAN_IDENTIFIER, length=2, data=fuzz_value)
    ans_recu_test = sock_vcan0.sr(recu_pkt, verbose=0)[0]
    response_code = ans_recu_test[0].answer.data[0]
    if check_response_code(0x11, response_code):
        break

print("FINISHED.")














