# from scapy.config import conf

import sys  # accessing cmd line argments
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

def print_error(error_message):
    if VERBOSE_DEBUG is True:
        print(Fore.RED + error_message + Style.RESET_ALL)

def print_success(message):
    if VERBOSE_DEBUG is True:
        print(Fore.GREEN + message + Style.RESET_ALL)

def print_new_test_banner():
    if VERBOSE_DEBUG is True:
        print(
            "#####################################################################\n"
            "#####################################################################\n"
            "############################## NEW TEST #############################\n"
            "#####################################################################\n"
            "#####################################################################\n"
        )

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
