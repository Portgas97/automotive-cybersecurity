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