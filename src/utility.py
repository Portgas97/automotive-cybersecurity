# from scapy.config import conf
# from scapy.utils import hexdump
# from scapy.packet import ls, explore
# from scapy.sendrecv import sr1, sr

import sys  # to access CLI argments
import atexit
import signal
from colorama import Fore, Style  # coloring output # TODO: better to use loggin library

from scapy.layers.can import CAN

# from scapy.contrib.isotp import *
from scapy.contrib.cansocket_native import NativeCANSocket
from scapy.contrib.automotive.uds import *


from scapy.plist import (
    PacketList,
    QueryAnswer,
    SndRcvList,
)

import global_
import time

# conf.contribs['CANSocket'] = {'use-python-can': False} # default

conf.contribs['CAN']['remove-padding'] = True
conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}
from scapy.contrib.isotp import isotp_scan

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


def send_selected_tester_present(socket: NativeCANSocket,
                                 passed_tests: list # list[bool] produce error
                                 ) -> bool:
    """
    Sends just one TP packet, based on previously determined conditions.

    :param socket: the socket connected to the can or vcan interface
    :param passed_tests: array of bools, to retrieve info of passed TP formats
    :return: True at the first positive response, False otherwise.
    """

    for i, flag in enumerate(passed_tests):
        if flag is True:
            selected_request = CAN(identifier=global_.CAN_IDENTIFIER,
                                    length=8,
                                    data=global_.payloads[i])
            # if global_.VERBOSE_DEBUG:
            #    print("Waiting for tester present...")

            tp_ans, _ = socket.sr(selected_request, inter=0.5, retry=-2, timeout=1, verbose=0)
            # time.sleep(5)
            # print("tester present response: ")
            # print(tp_ans[0].answer.data)
            if tp_ans[0] and tp_ans[0].answer.data[1] == 0x7E:
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
    if global_.VERBOSE_DEBUG is True:
        print(Fore.RED + error_message + Style.RESET_ALL)

def print_success(message: str) -> None:
    """
    Prints a green message to the console, if verbose output is set.

    :param message: information to print to the console
    :return: -
    """
    if global_.VERBOSE_DEBUG is True:
        print(Fore.GREEN + message + Style.RESET_ALL)

def print_debug(message: str) -> None:
    """
    Prints general information to the console, only if strong verbosity is set.

    :param message: information to print to the console
    :return: -
    """
    if global_.VERBOSE_DEBUG is True:
        print(Fore.YELLOW + message + Style.RESET_ALL)

def print_new_test_banner() -> None:
    """
    Prints a test separator to the console for readability.

    :return: -
    """
    if global_.VERBOSE_DEBUG is True:
        print(
            "#####################################################################\n"
            "#####################################################################\n"
            "############################## NEW TEST #############################\n"
            "#####################################################################\n"
            "#####################################################################\n"
        )

# TODO: decorate this function
# TODO: test delim function, not done
def print_hex(hex_string, delim=""):
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


# TODO: creare una create_packet separata
# TODO: creare una send_and_receive
# TODO: il fuzzing si farà fuori, tipo burst_packets nel caso si possano
# mandare tutti di fila, nel caso di test come rsda dopo ogni pacchetto
# bisognare chiamare un'altra funzione, quindi questa funzione qui sotto va
# scomposta.

# TODO: description
def create_packet(service: int =0, 
                  subservice: int =0,
                  data: bytes =b'',
                  data_len: int =0, 
                  can_id: int =global_.CAN_IDENTIFIER) -> Packet:
    
    if service:
        pld = service.to_bytes(1, 'little') 
    if subservice:
        pld += subservice.to_bytes(1, 'little')
    if data != b'': 
        if data_len != 0:
            pld += data.to_bytes(data_len, 'little')   
    
        
        
    # concatenate the dlc with fuzz value
    payload = (len(pld)).to_bytes(1, 'little') + pld

    # TODO: length, payload, and padding must be set properly based on test_tp test 

    # print_debug(f"test packet payload: ")
    # print_hex(payload)
    return CAN(identifier=can_id, length=8, data=payload)

# TODO: description
def send_receive(can_socket: NativeCANSocket, 
                 packet: Packet,
                 client_can_id: int =global_.CAN_IDENTIFIER,
                 multiframe: bool =False) -> tuple[SndRcvList, PacketList]:

    if not multiframe:
            results, unanswered = can_socket.sr(packet, retry=2, timeout=2, verbose=0)
    else:
        results, unanswered = can_socket.sr(packet, retry=2, verbose=0, multi=True)
    try:
        results[0]
    except Exception as e:
        print_debug(f"Exception: {e}, probably no response from ECU")

    return results, unanswered


    # print_debug("response: ")
    # print_hex(test_ans[0].answer.data)
    
    ### response_code = results[0].answer.data[1]
    ### check_response_code(service, response_code)

# TODO: description
def fuzz(service: int =0,
         subservice: int =0,
         fuzz_service: bool =False, 
         fuzz_subservice: bool =False,
         fuzz_data: bool =False,
         # fuzz_data_len: bool =False, 
         fuzz_service_range: int =1, 
         fuzz_subservice_range: int =1, 
         fuzz_data_range: int =0, 
         # fuzz_data_len_range: int =0
         ) -> list[Packet]:
    
    packets_list = []
    if fuzz_service and not fuzz_subservice and not fuzz_data:
        # fuzz solo service
        pass

    elif not fuzz_service and fuzz_subservice and not fuzz_data:
        # fuzz solo subservice
        for fuzzval in range(fuzz_subservice_range + 1):
            packets_list.append(create_packet(service, fuzzval))

    
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


def create_and_send_packet(can_socket: NativeCANSocket,
                           service: int,
                           subservice: int =None,
                           data: int=None,
                           data_len: int=0,
                           fuzz_range: int =0,
                           inter_tp: bool =False, 
                           multiframe: bool =False,
                           can_id: int =global_.CAN_IDENTIFIER
                           ) -> tuple[SndRcvList, PacketList]:
    """
    It builds a CAN packet given the args, sends it and parse the response.

    :param can_socket: socket connected to the can interface
    :param service: UDS service to send
    :param subservice: specifies an exact subservice for the request
    :param data: information needed for some service
    :param data_len: on how many byte data parameter is passed
    :param fuzz_range: range for payload value fuzzing
    :param inter_tp: wheter to send a tester present before each message
    :param multiframe: if True tells the function to handle the multiframe case
    :param can_id: client CAN identifier
    :return: two list composed of answered and unanswered messages
    """

    ans_list = []
    for idx in range(0, fuzz_range + 1):

        #print_debug(f"\nidx: {idx}")

        if inter_tp:
            if not send_selected_tester_present(can_socket, global_.passed):
                print_error("ERROR: tp failed!")
                return 
            print_success("tester present correctly received")
        
        byte_len = byte_length(fuzz_range)
        if subservice is not None:
            fuzz_value = (service.to_bytes(1, 'little') + subservice.to_bytes(1, 'little'))
        elif data is not None: 
            # non è detto che non si voglia settare sia subservice che data, da verificare???
            # l'eventuale bruteforcing di data è stato quindi rimandato al chiamante
            fuzz_value = (service.to_bytes(1, 'little') + data.to_bytes(data_len, 'little'))       
        else:
            fuzz_value = (service.to_bytes(1, 'little') + idx.to_bytes(byte_len, 'little'))
            
            
        # concatenate the dlc with fuzz value
        payload = (1 + byte_len).to_bytes(1, 'little') + fuzz_value

        # TODO: length, payload, and padding must be set properly based on test_tp test 

        # print_debug(f"test packet payload: ")
        # print_hex(payload)
        test_pkt = CAN(identifier=can_id,
                       length=8, 
                       data=payload)

        # TODO: va aggiunto il padding a fuzz_value??? Dipende da TP, ora come ora no

        # print_debug("waiting for test packet...")

        if not multiframe:
            results, unanswered = can_socket.sr(test_pkt, retry=2, timeout=2, verbose=0)
            
        else:
            results, unanswered = can_socket.sr(test_pkt, retry=2, verbose=0, multi=True)
        try:
            results[0]
        except Exception as e:
            print_debug(f"Exception: {e}, probably no response from ECU")
            continue

        ans_list.append(results)

        # print_debug("response: ")
        # print_hex(test_ans[0].answer.data)
        # QueryAnswer(
        #   query=<CAN  identifier=XXX length=XXX data=XXX |>,
        #   answer=<CAN  flags=XXX identifier=XXX length=XXX reserved=XXX data=XXX |>
        # )
        response_code = results[0].answer.data[1]
        check_response_code(service, response_code)
        
        # TODO: metterei due liste
        # una relativa alle positive responses, in cui si restituisce il payload
        # che ha provocato la risposta e il valore della risposta
        # una con i NRC, etc. 

    return ans_list, None



# TODO: reset ecu hard or soft then clear DTC info (service 0x14 --> 04.14.FF.FF.FF.00.00.00)


# TODO si possono fare funzioni di utilità basandosi su
 # QueryAnswer(
#   query=<CAN  identifier=XXX length=XXX data=XXX |>,
#   answer=<CAN  flags=XXX identifier=XXX length=XXX reserved=XXX data=XXX |>
# )
