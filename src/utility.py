# ============================================================================ #
# =                                IMPORTS                                   = #
# ============================================================================ #
import sys  # to access CLI argments
import atexit # TODO maybe later
import signal # TODO maybe later
import time

from colorama import Fore, Style  # coloring output # TODO: better to use loggin library

from scapy.layers.can import CAN
# from scapy.contrib.isotp import *
from scapy.contrib.cansocket_native import NativeCANSocket
from scapy.contrib.automotive.uds import conf, Packet

from scapy.plist import (
    PacketList,
    QueryAnswer,
    SndRcvList,
)

# conf.contribs['CANSocket'] = {'use-python-can': False} 
conf.contribs['CAN']['remove-padding'] = True
conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
from scapy.contrib.isotp import isotp_scan # must be after import above

# TODO si possono fare funzioni di utilità basandosi su
 # QueryAnswer(
#   query=<CAN  identifier=XXX length=XXX data=XXX |>,
#   answer=<CAN  flags=XXX identifier=XXX length=XXX reserved=XXX data=XXX |>
# )

from configuration import config_manager as ctx_man

# ============================================================================ #
# =                         UTILITY FUNCTIONS                                = #
# ============================================================================ #

def handle_exit():
    """
    TODO: Operations to be performed at program exit.

    :return: -
    """
    print("exit_handler() invoked")

# atexit.register(handle_exit())

def handle_sigterm():
    """
    TODO: Operations to be performed at sigterm.

    :return: -
    """
    print("handle_sigterm() invoked")

# signal.signal(signal.SIGTERM, handle_sigterm())


def handle_sigint():
    """
    TODO: Operations to be performed at sigint.

    :return: -
    """
    print("handle_sigint() invoked")

# signal.signal(signal.SIGINT, handle_sigint())


def print_error(error_message: str) -> None:
    """
    Prints a red error message, only if verbose output is set.

    :param error_message: string to print to the console, error information
    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(Fore.RED + error_message + Style.RESET_ALL)


def print_success(message: str) -> None:
    """
    Prints a green message to the console, if verbose output is set.

    :param message: information to print to the console
    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(Fore.GREEN + message + Style.RESET_ALL)


def print_debug(message: str) -> None:
    """
    Prints general information to the console, only if strong verbosity is set.

    :param message: information to print to the console
    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(Fore.YELLOW + message + Style.RESET_ALL)


def print_new_test_banner() -> None:
    """
    Prints a test separator to the console for readability.

    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(
            "\n"
            "#####################################################################\n"
            "#####################################################################\n"
            "############################## NEW TEST #############################\n"
            "#####################################################################\n"
            "#####################################################################\n"
        )

# TODO: test delim function, not done
def print_hex(hex_string, delim="") -> None:
    """
    It prints the hexadecimal value instead of decoding it, e.g. in ASCII. 

    :param hex_string: array of hexadecimal values
    :return: -
    """
    value_list = list(''.join('{:02X}'.format(hex_value)) for hex_value in hex_string)
    if delim != "":
        print('.'.join(x for x in value_list), delim)
    else:
        print('.'.join(x for x in value_list))


# TODO decorate
# setBit() returns an integer with the bit at 'offset' set to 1.
def setBit(int_type, offset):
    mask = 1 << offset
    return(int_type | mask)

# TODO decorate
# testBit() returns a nonzero result, 2**offset, if the bit at 'offset' is one.
def testBit(int_type, offset):
    mask = 1 << offset
    return(int_type & mask)

# TODO decorate
def build_flag_mask(flag_list :list[str]) -> int:
    mask = int(0x0000000)
    for flag in flag_list:
        if flag == 'ALL':
            mask = 0xFFFFFFF
            break
        elif flag == 'POS':
            setBit(mask, 0)
            break
        elif flag == 'NEG':
            mask = 0xFFFFFFE
            break
        elif flag == 'SPECIFIC':
            setBit(mask, 24)
        elif flag == 'SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION':
            setBit(mask, 23)
        elif flag == 'SUBFUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION':
            setBit(mask, 22)
        elif flag == 'REQUEST_RECEIVED_RESPONSE_PENDING':
            setBit(mask, 21)
        elif flag == 'WRONG_BLOCK_SEQUENCE_COUNTER':
            setBit(mask, 20)
        elif flag == 'GENERAL_PROGRAMMING_FAILURE':
            setBit(mask, 19)
        elif flag == 'TRANSFER_DATA_SUSPENDED':
            setBit(mask, 18)
        elif flag == 'UPLOAD_DOWNLOAD_NOT_ACCEPTED':
            setBit(mask, 17)
        elif flag == 'RESERVED_BY_EDLSD':
            setBit(mask, 16)
        elif flag == 'REQUIRED_TIME_DELAY_NOT_EXPIRED':
            setBit(mask, 15)
        elif flag == 'EXCEEDED_NUMBER_OF_ATTEMPT':
            setBit(mask, 14)
        elif flag == 'INVALID_KEY':
            setBit(mask, 13)
        elif flag == 'SECURITY_ACCESS_DENIED':
            setBit(mask, 12)
        elif flag == 'REQUEST_OUT_OF_RANGE':
            setBit(mask, 11)
        elif flag == 'FAILURE_PREVENTS_EXECUTION':
            setBit(mask, 10)
        elif flag == 'NO_RESPONSE_FROM_SUBNET_COMPONENTE':
            setBit(mask, 9)
        elif flag == 'REQUEST_SEQUENCE_ERROR':
            setBit(mask, 8)
        elif flag == 'CONDITIONS_NOT_CORRECT':
            setBit(mask, 7)
        elif flag == 'BUSY_REPEAT_REQUEST':
            setBit(mask, 6)
        elif flag == 'RESPONSE_TOO_LONG':
            setBit(mask, 5)
        elif flag == 'INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT':
            setBit(mask, 4)
        elif flag == 'SUBFUNCTION_NOT_SUPPORTED':
            setBit(mask, 3)
        elif flag == 'SERVICE_NOT_SUPPORTED':
            setBit(mask, 2)
        elif flag == 'GENERAL_REJECT':
            setBit(mask, 1)
    return mask


def check_response_code(req_code :int, 
                        resp_code :int, 
                        flag_list :list[str]=['ALL']) -> bool:
    """
    It checks for UDS positive or negative response, displaying relative info.

    :param req_code: UDS service request identifier
    :param resp_code: UDS service response identifier
    :return: True in case of positive response, False otherwise
    """

    mask = build_flag_mask(flag_list)

    if resp_code == req_code + 0x40 and testBit(mask, 0):
        print_success("Positive response found")
        return True
    
    # common response codes
    elif resp_code == 0x10 and (testBit(mask, 1) or mask == 0xFFFFFFF):
        print_error("error: general reject")
    elif resp_code == 0x11 and (testBit(mask, 2) or mask == 0xFFFFFFF):
        print_error("error: service not supported")
    elif resp_code == 0x12 and (testBit(mask, 3) or mask == 0xFFFFFFF):
        print_error("error: sub-function not supported")
    elif resp_code == 0x13 and (testBit(mask, 4) or mask == 0xFFFFFFF):
        print_error("error: incorrect message length or invalid format")
        print("WARNING: possible implementation error")
    elif resp_code == 0x14 and (testBit(mask, 5) or mask == 0xFFFFFFF):
        print_error("error: response too long")
    elif resp_code == 0x21 and (testBit(mask, 6) or mask == 0xFFFFFFF):
        print_error("error: busy repeat request")
    elif resp_code == 0x22 and (testBit(mask, 7) or mask == 0xFFFFFFF):
        print_error("error: conditions not correct")
    elif resp_code == 0x24 and (testBit(mask, 8) or mask == 0xFFFFFFF):
        print_error("error: request sequence error")
    elif resp_code == 0x25 and (testBit(mask, 9) or mask == 0xFFFFFFF):
        print_error("error: no response from sub-net component")
    elif resp_code == 0x26 and (testBit(mask, 10) or mask == 0xFFFFFFF):
        print_error("error: failure prevents execution of request action")
    elif resp_code == 0x31 and (testBit(mask, 11) or mask == 0xFFFFFFF):
        print_error("error: request out of range")
    elif resp_code == 0x33 and (testBit(mask, 12) or mask == 0xFFFFFFF):
        print_error("error: security access denied")
    elif resp_code == 0x35 and (testBit(mask, 13) or mask == 0xFFFFFFF):
        print_error("error: invalid key")
    elif resp_code == 0x36 and (testBit(mask, 14) or mask == 0xFFFFFFF):
        print_error("error: exceeded number of attempts")
    elif resp_code == 0x37 and (testBit(mask, 15) or mask == 0xFFFFFFF):
        print_error("error: required time delay not expired")
    elif resp_code in range(0x38,0x4F+1):
        if (testBit(mask, 16) or mask == 0xFFFFFFF):
            print_error("error: reserved by Extended Data Link Security Document")
    elif resp_code == 0x70 and (testBit(mask, 17) or mask == 0xFFFFFFF):
        print_error("error: upload/download not accepted")
    elif resp_code == 0x71 and (testBit(mask, 18) or mask == 0xFFFFFFF):
        print_error("error: transfer data suspended")
    elif resp_code == 0x72 and (testBit(mask, 19) or mask == 0xFFFFFFF):
        print_error("error: general programming failure")
    elif resp_code == 0x73 and (testBit(mask, 20) or mask == 0xFFFFFFF):
        print_error("error: wrong block sequence counter")
    elif resp_code == 0x78 and (testBit(mask, 21) or mask == 0xFFFFFFF):
        print_error("error: request correctly received, response is pending")
    elif resp_code == 0x7E and (testBit(mask, 22) or mask == 0xFFFFFFF):
        print_error("error: sub-function not supported in active session")
    elif resp_code == 0x7F and (testBit(mask, 23) or mask == 0xFFFFFFF):
        print_error("error: service not supported in active session")

    # specific conditions driven response codes
    elif mask == 0xFFFFFFF or mask == 0xFFFFFFE or testBit(mask, 24):
        if resp_code == 0x81:
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
        if mask == 0xFFFFFFF or mask == 0xFFFFFFE:
            print_error("error: unexpected response")
    return False


def print_menu() -> None:
    """
    Prints banner and menu options.

    :return: -
    """
    print( Fore.LIGHTRED_EX +
            "          _______         \n" # type: ignore 
            "         //  ||\ \        \n" # type: ignore
            "   _____//___||_\ \___    \n" # type: ignore
            "   )  _          _    \   \n" # type: ignore
            "   |_/ \________/ \___|   \n" # type: ignore
            "  ___\_/________\_/______ \n" # type: ignore
           + Style.RESET_ALL
        )

    print(  "Please, choose one of the following command:           \n")
    print(
              Fore.LIGHTRED_EX + "\t help" + Style.RESET_ALL +
              ": display this menù\n"

            + Fore.LIGHTRED_EX + "\t quit" + Style.RESET_ALL +
              ": program exit\n"

            + Fore.LIGHTRED_EX + "\t clear" + Style.RESET_ALL +
              ": clear the screen and print this command menu\n"
            
            + Fore.LIGHTRED_EX + "\t isotp_scan" + Style.RESET_ALL +
              ": scans for ISO-TP endpoints\n"

            + Fore.LIGHTRED_EX + "\t set_my_ID" + Style.RESET_ALL +
              ": set up the internal state to work with the (next) passed CAN ID.\n"

            + Fore.LIGHTRED_EX + "\t set_listen_ID" + Style.RESET_ALL +
              ": set up the internal state to listen messages from the (next) passed CAN ID.\n"

            + Fore.LIGHTRED_EX + "\t test_tp" + Style.RESET_ALL +
              ": tester present probe (establish correct packet format)\n"

            + Fore.LIGHTRED_EX + "\t test_dds" + Style.RESET_ALL +
              ": find all the available sessions\n"

            + Fore.LIGHTRED_EX + "\t test_recu" + Style.RESET_ALL +
              ": missing text\n"

            + Fore.LIGHTRED_EX + "\t test_rsdi" + Style.RESET_ALL +
              ": missing text\n"

            + Fore.LIGHTRED_EX + "\t other" + Style.RESET_ALL +
              ": ... TODO:\n"
            )


def byte_length(hex_int: int) -> int:
    """
    It computes how many bytes are necessary for a given hex integer value.

    :param hex_int: integer value in hexadecimal representation
    :return: the number of necessary bytes to represent the passed value
    """
    return (hex_int.bit_length() + 7) // 8


def create_packet(service: int =0, 
                  subservice: int =0,
                  data: bytes =b'',
                  data_len: int =0, 
                  ) -> Packet:
    """
    Builds a CAN packet depending on the parameter passed. 

    :param service: UDS service to set
    :param subservice: UDS subservice
    :param data: optional data used in some UDS services
    :param data_len: length of the data above
    :return: the built CAN packet
    """
    can_id = ctx_man.CAN_IDENTIFIER

    pld: bytes
    if service:
        pld = service.to_bytes(1, 'little')
    if subservice:
        pld += subservice.to_bytes(1, 'little') # type: ignore
    if data != b'': 
        pld += data    # type: ignore
      
    # concatenate the dlc with fuzz value
    payload = (len(pld)).to_bytes(1, 'little') + pld

    # TODO: length, payload, and padding must be set properly based on test_tp test 

    # print_debug(f"test packet payload: ")
    # print_hex(payload)
    return CAN(identifier=can_id, length=8, data=payload)


def send_receive(packet :Packet, 
                 multiframe :bool=False) -> tuple[SndRcvList, PacketList]:
    """
    Calls the sr() scapy function, it distinguish between single and multiframe
    cases. 

    :param can_socket: socket to work with
    :param packet: CAN packet to send
    :param multiframe: flag to enable multiframe handling
    :return: a tuple of answered query-answer and unanswered packets
    """
    can_socket = ctx_man.CAN_SOCKET
    if not multiframe:
            results, unanswered = can_socket.sr(packet, retry=0, timeout=0.3, verbose=0)
    else:
        results, unanswered = can_socket.sr(packet, 
                                            timeout=3,
                                            verbose=1, 
                                            multi=True, 
                                            threaded=True)
    try:
        results[0]
    except Exception as e:
        print_debug(f"Exception: {e}, probably no response from ECU")

    return results, unanswered


def fuzz(service: int =0, # TODO i don't know, myabe it will be always required (except for service fun obv.)
         subservice: int =0,
         fuzz_service: bool =False, 
         fuzz_subservice: bool =False,
         fuzz_data: bool =False,
         # fuzz_data_len: bool =False, 
         fuzz_service_range: int =1, 
         fuzz_subservice_range: int =1, 
         fuzz_data_range: int =0, 
         # fuzz_data_len_range: int =0, 
         ) -> list[Packet]:
    """
    Creates a list of packets based on fuzzing conditions. 

    :param service: service to use in all the packets
    :param subservice: subservice to use in all the packets
    :param fuzz_service: flag to enable service fuzzing
    :param fuzz_subservice: flag to enable subservice fuzzing
    :param fuzz_data: flag to enable data fuzzing
    :param fuzz_service_range: range of fuzzing in case of service fuzzing
    :param fuzz_subservice_range: range of fuzzing in case of subservice fuzzing
    :param fuzz_data_range: range of fuzzing in case of data fuzzing
    :return: a list of packets
    """
    # can_id = ctx_man.CAN_IDENTIFIER # maybe not necessary 

    packets_list = []
    if fuzz_service and not fuzz_subservice and not fuzz_data:
        # fuzz solo service
        pass

    elif not fuzz_service and fuzz_subservice and not fuzz_data:
        # fuzz solo subservice
        for fuzzval in range(fuzz_subservice_range + 1):
            packets_list.append(create_packet(service=service, 
                                              subservice=fuzzval))

    elif not fuzz_service and not fuzz_subservice and fuzz_data:
        for fuzzval in range(fuzz_data_range + 1):
            packets_list.append(create_packet(service=service, 
                                              data=fuzzval.to_bytes(4, 'little'),
                                              data_len=4))

    elif fuzz_service and fuzz_subservice and not fuzz_data:
        # fuzz service and subservice
        pass
    
    elif fuzz_service and not fuzz_subservice and fuzz_data:
        # fuzz service and data
        pass
    
    elif not fuzz_service and fuzz_subservice and fuzz_data:
        # fuzz subservice and data
        pass

    elif fuzz_service and fuzz_subservice and fuzz_data:
        # complete fuzzing
        pass

    else:
        #error?
        pass
    return packets_list

# TODO decorate
def read_response_code(packet: SndRcvList, index :int=0) -> int:
    try: 
        return packet[index].answer.data[1]
    except IndexError:
        return -1
    
# TODO decorate
def send_diagnosti_session_control(session :int) -> bool:
    can_socket = ctx_man.getCanSocket()
    client_can_id = ctx_man.getCanId()
    
    dsc = create_packet(service=0x10, subservice=session)
    res, unans = send_receive(dsc) 
    try:
        print(unans[0].show())
    except:
        pass
    ret = read_response_code(res)
    if ret == 0x50:
        return True
    return False


# TODO for cool console display (not-scrolling)
# import os,time

# clear = lambda: os.system('cls')      # or os.system('clear') for Unix

# for i in range(10,0,-1):
#     clear()
#     print i
#     time.sleep(1)