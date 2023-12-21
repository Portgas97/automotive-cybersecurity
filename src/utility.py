# from scapy.config import conf

import sys  # accessing cmd line argments
import atexit
import signal
from colorama import Fore, Style  # coloring output

from scapy.utils import hexdump
from scapy.packet import ls  # ,explore
from scapy.sendrecv import sr1, sr

# from scapy.main import load_contrib #, load_layer

from scapy.layers.can import CAN
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP, traceroute, TCP

from scapy.contrib.isotp import *
from scapy.contrib.cansocket_native import NativeCANSocket
from scapy.contrib.automotive.uds import *
from scapy.contrib.automotive.uds_scan import UDS_Scanner, \
    UDS_ServiceEnumerator

# from scapy.contrib.cansocket import *
# load_layer("dns")
# load_layer("inet")
# load_layer("can")
# load_contrib("isotp")
# load_contrib("automotive.uds")

import scapy101
import obd_scanning
import uds_scanning
import isotp_scanning

conf.contribs['CANSocket'] = {'use-python-can': False} # default
# load_contrib('cansocket_native') ## ??? needed? already contribs['isotp'] below
# conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}

VERBOSE_DEBUG = False
EXTRA_VERBOSE_DEBUG = False
CAN_IDENTIFIER = 0x1FFFFFFF # TO DO must be set properly, using scanning modules

lengths = [2, 2, 1, 2, 2, 2, 1]
payloads = [b'\x3E\x00\x00\x00\x00\x00\x00',
            b'\x3E\x80\x00\x00\x00\x00\x00',
            b'\x3E\x00\x00\x00\x00\x00\x00',
            b'\x3E\x80\x00\x00\x00\x00\x00',
            b'\x3E\x00',
            b'\x3E\x80',
            b'\x3E']
passed = [False, False, False, False, False, False, False]

def handle_exit():
    """
    TO DO Operations to be performed at program exit.

    :return: -
    """
    print("exit_handler() invoked")

# atexit.register(handle_exit())

def handle_sigterm():
    """
    TO DO Operations to be performed at sigterm.

    :return: -
    """
    print("handle_sigterm() invoked")

def handle_sigint():
    """
    TO DO Operations to be performed at sigint.

    :return: -
    """
    print("handle_sigint() invoked")

# signal.signal(signal.SIGTERM, handle_sigterm())
# signal.signal(signal.SIGINT, handle_sigint())

def send_selected_tester_present(socket: NativeCANSocket,
                                 passed_tests: list # list[bool] produce error
                                 ) -> bool:
    """
    Sends several TP packets, based on previously determined conditions.

    :param socket: the socket connected to the can or vcan interface
    :param passed_tests: array of bools, to retrieve info of passed TP formats
    :return: True at the first positive response, False otherwise.
    """
    global VERBOSE_DEBUG, CAN_IDENTIFIER, lengths, payloads
    for i, flag in enumerate(passed_tests):
        if flag is True:
            selected_request = CAN(identifier=CAN_IDENTIFIER,
                                    length=lengths[i],
                                    data=payloads[i])
            if VERBOSE_DEBUG:
                print("Waiting for tester present...")
            print_debug(i)
            tp_ans = socket.sr(selected_request, verbose=0)[0]
            if tp_ans[0] and tp_ans[0].answer.data[0] == 0x7E:
                return True
            else:
                continue
    print_error("Something went wrong in TesterPresent probe\n")
    return False

def print_error(error_message: str) -> None:
    """
    Prints a red error message, only if verbose output is set.

    :param error_message: string to print to the console, error information
    :return: -
    """
    global VERBOSE_DEBUG
    if VERBOSE_DEBUG is True:
        print(Fore.RED + error_message + Style.RESET_ALL)

def print_success(message: str) -> None:
    """
    Prints a green message to the console, if verbose output is set.

    :param message: information to print to the console
    :return: -
    """
    global VERBOSE_DEBUG
    if VERBOSE_DEBUG is True:
        print(Fore.GREEN + message + Style.RESET_ALL)

def print_debug(message: str) -> None:
    """
    Prints general information to the console, only if strong verbosity is set.

    :param message: information to print to the console
    :return: -
    """
    global EXTRA_VERBOSE_DEBUG
    if EXTRA_VERBOSE_DEBUG is True:
        print(message)

def print_new_test_banner() -> None:
    """
    Prints a test separator to the console for readability.

    :return: -
    """
    global VERBOSE_DEBUG
    if VERBOSE_DEBUG is True:
        print(
            "#####################################################################\n"
            "#####################################################################\n"
            "############################## NEW TEST #############################\n"
            "#####################################################################\n"
            "#####################################################################\n"
        )

def check_response_code(req_code: int, resp_code: int) -> bool:
    """
    It checks for UDS positive or negative response, displaying relative info.

    :param req_code: UDS service request identifier
    :param resp_code: UDS service response identifier
    :return: True in case of positive response, False otherwise
    """
    if resp_code == req_code + 0x40:
        print_success("Positive response found")
        return True

    # common response codes
    elif resp_code == 0x10:
        print_error("error: general reject")
    elif resp_code == 0x11:
        print_error("error: service not supported")
    elif resp_code == 0x12:
        print_error("error: sub function not supported")
    elif resp_code == 0x13:
        print_error("error: incorrect message length ot invalid format")
        print("WARNING: possible implementation error")
    elif resp_code == 0x14:
        print_error("error: response too long")
    elif resp_code == 0x21:
        print_error("error: busy repeat request")
    elif resp_code == 0x22:
        print_error("error: conditions not correct")
    elif resp_code == 0x24:
        print_error("error: request sequence error")
    elif resp_code == 0x25:
        print_error("error: no response from sub-net component")
    elif resp_code == 0x26:
        print_error("error: failure prevents execution of request action")
    elif resp_code == 0x31:
        print_error("error: request out of range")
    elif resp_code == 0x33:
        print_error("error: security access denied")
    elif resp_code == 0x35:
        print_error("error: invalid key")
    elif resp_code == 0x36:
        print_error("error: exceeded number of attempts")
    elif resp_code == 0x37:
        print_error("error: required time delay not expired")
    elif resp_code in range(0x38,0x4F+1):
        print_error("error: reserved by Extended Data Link Security Document")
    elif resp_code == 0x70:
        print_error("error: upload/download not accepted")
    elif resp_code == 0x71:
        print_error("error: transfer data suspended")
    elif resp_code == 0x72:
        print_error("error: general programming failure")
    elif resp_code == 0x73:
        print_error("error: wrong block sequence counter")
    elif resp_code == 0x78:
        print_error("error: request correctly received, response is pending")
    elif resp_code == 0x7E:
        print_error("error: sub-function not supported in active session")
    elif resp_code == 0x7F:
        print_error("error: service not supported in active session")

    # specific conditions driven response codes
    elif resp_code == 0x81:
        print_error("error: rpm too high")
    elif resp_code == 0x82:
        print_error("error: rpm too low")
    elif resp_code == 0x83:
        print_error("error: engine is running")
    elif resp_code == 0x84:
        print_error("error: engine is not running")
    elif resp_code == 0x85:
        print_error("error: engine run-time too low")
    elif resp_code == 0x86:
        print_error("error: temperature too high")
    elif resp_code == 0x87:
        print_error("error: temperature too low")
    elif resp_code == 0x88:
        print_error("error: vehicle speed to high")
    elif resp_code == 0x89:
        print_error("error: vehicle speed to low")
    elif resp_code == 0x8A:
        print_error("error: throttle/pedal too high")
    elif resp_code == 0x8B:
        print_error("error: throttle/pedal to low")
    elif resp_code == 0x8C:
        print_error("error: transmission range not in neutral")
    elif resp_code == 0x8D:
        print_error("error: transmission range not in gear")
    elif resp_code == 0x8F:
        print_error("error: brake switch(es) not closed")
    elif resp_code == 0x90:
        print_error("error: shifter lever not in park")
    elif resp_code == 0x91:
        print_error("error: torque converter clutch locked")
    elif resp_code == 0x92:
        print_error("error: voltage too high")
    elif resp_code == 0x93:
        print_error("error: voltage too low")

    # otherwise
    else:
        print_error("error: unexpected response")
    return False

def print_menu() -> None:
    """
    Prints banner and menu options.

    :return: -
    """
    print( Fore.LIGHTRED_EX +
            "          _______         \n"
            "         //  ||\ \        \n"
            "   _____//___||_\ \___    \n"
            "   )  _          _    \   \n"
            "   |_/ \________/ \___|   \n"
            "  ___\_/________\_/______ \n"
           + Style.RESET_ALL
        )

    print(  "Please, choose one of the following command:           \n")
    print(
              Fore.LIGHTRED_EX + "\t help" + Style.RESET_ALL +
              ": print this menu\n"

            + Fore.LIGHTRED_EX + "\t quit" + Style.RESET_ALL +
              ": program exit\n"

            + Fore.LIGHTRED_EX + "\t clear" + Style.RESET_ALL +
              ": clear screen and print command menu\n"

            + Fore.LIGHTRED_EX + "\t test_tp" + Style.RESET_ALL +
              ": tester present probe (establish correct packet format)\n"

            + Fore.LIGHTRED_EX + "\t test_dds" + Style.RESET_ALL +
              ": missing text\n"

            + Fore.LIGHTRED_EX + "\t test_recu" + Style.RESET_ALL +
              ": missing text\n"

            + Fore.LIGHTRED_EX + "\t test_rsdi" + Style.RESET_ALL +
              ": missing text\n"

            + Fore.LIGHTRED_EX + "\t other" + Style.RESET_ALL +
              ": ... TO DO\n"
            )

def byte_length(hex_int: int) -> int:
    """
    It computes how many bytes are necessary for a given hex integer value.

    :param hex_int: integer value in hexadecimal representation
    :return: the number of necessary bytes to represent the passed value
    """
    return (hex_int.bit_length() + 7) // 8


# TO DO creare una create_packet separata
# TO DO creare una send_and_receive
# TO DO il fuzzing si farà fuori, tipo burst_packets nel caso si possano
# mandare tutti di fila, nel caso di test come rsda dopo ogni pacchetto
# bisognare chiamare un'altra funzione, quindi questa funzione qui sotto va
# scomposta.

def create_and_send_packet(can_socket: NativeCANSocket,
                           service: int,
                           fuzz_range: int,
                           pkt_length: int,
                           can_id: int =CAN_IDENTIFIER
                           ) -> None:
    """
    It builds a CAN packet given the args, sends it and parse the response.

    :param can_socket: socket connected to the can interface
    :param service: UDS service to send
    :param fuzz_range: range for payload value fuzzing
    :param pkt_length: length of the payload
    :param can_id: CAN identifier
    :return: -
    """
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
        if not check_response_code(service, response_code):
            print_error("ERROR: wrong packet response\n")



