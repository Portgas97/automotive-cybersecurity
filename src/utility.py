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

from classes import config_manager as ctx_man

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


def create_packet(can_id: int, 
                  service: int =0, 
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
    :param can_id: CAN identifier
    :return: the built CAN packet
    """
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


def send_receive(packet: Packet, 
                 can_socket: NativeCANSocket, 
                 multiframe: bool =False) -> tuple[SndRcvList, PacketList]:
    """
    Calls the sr() scapy function, it distinguish between single and multiframe
    cases. 

    :param can_socket: socket to work with
    :param packet: CAN packet to send
    :param multiframe: flag to enable multiframe handling
    :return: a tuple of answered query-answer and unanswered packets
    """
    if not multiframe:
            results, unanswered = can_socket.sr(packet, retry=0, timeout=0.3, verbose=0)
    else:
        results, unanswered = can_socket.sr(packet, verbose=1, multi=True)
    try:
        results[0]
    except Exception as e:
        print_debug(f"Exception: {e}, probably no response from ECU")

    return results, unanswered


def fuzz(can_id: int, 
         service: int =0, # TODO i don't know, myabe it will be always required (except for service fun obv.)
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
    
    packets_list = []
    if fuzz_service and not fuzz_subservice and not fuzz_data:
        # fuzz solo service
        pass

    elif not fuzz_service and fuzz_subservice and not fuzz_data:
        # fuzz solo subservice
        for fuzzval in range(fuzz_subservice_range + 1):
            packets_list.append(create_packet(can_id=can_id,  
                                              service=service,
                                              subservice=fuzzval))

    elif not fuzz_service_range and not fuzz_subservice and fuzz_data:
        # fuzz solo data
        pass

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
