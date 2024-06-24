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
from scapy.contrib.automotive.uds import conf, Packet, UDS, UDS_TP

from scapy.plist import (
    PacketList,
    QueryAnswer,
    SndRcvList,
)

# conf.contribs['CANSocket'] = {'use-python-can': False} 
# conf.contribs['CAN']['remove-padding'] = False

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


def print_error(error_message: str, end='\n') -> None:
    """
    Prints a red error message, only if verbose output is set.

    :param error_message: string to print to the console, error information
    :param end: character for EOL
    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(Fore.RED + error_message + Style.RESET_ALL)


def print_success(message: str, end='\n') -> None:
    """
    Prints a green message to the console, if verbose output is set.

    :param message: information to print to the console
    :param end: character for EOL
    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(Fore.GREEN + message + Style.RESET_ALL)


def print_debug(message: str, end='\n') -> None:
    """
    Prints general information to the console, only if strong verbosity is set.

    :param message: information to print to the console
    :param end: character for EOL
    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(Fore.YELLOW + message + Style.RESET_ALL, end=end)


def print_new_test_banner() -> None:
    """
    Prints a test separator to the console for readability.

    :return: -
    """
    if ctx_man.VERBOSE_DEBUG:
        print(
            "\n"
            "#####################################################################\n"
            "############################## NEW TEST #############################\n"
            "#####################################################################\n"
        )

def print_hex(hex_string :str, end :str='\n') -> None:
    """
    It prints the hexadecimal value instead of decoding it, e.g. in ASCII. 

    :param hex_string: array of hexadecimal values
    :param end: character for EOL
    :return: -
    """
    value_list = list(''.join('{:02X}'.format(hex_value)) for hex_value in hex_string)
    print('.'.join(x for x in value_list), end=end)


def concatenate_hex(a :str, b :str) -> str:
    """
    It concatenates two strings as hexadecimal numbers. 

    :param a: first string 
    :param b: second string 
    :return: the concatenated string
    """
    return f'{a:02x}{b:02x}'


def setBit(int_type :int, offset :int) -> int:
    """
    It returns an integer with the bit at 'offset' set to 1.

    :param int_type: argument to modify 
    :param offset: where to set the bit
    :return: the modified integer with bit at offset set to 1
    """
    mask = 1 << offset
    return (int_type | mask)


def testBit(int_type :int, offset :int) -> int:
    """
    It returns a nonzero result, 2**offset, if the bit at 'offset' is one.

    :param int_type: argument to test
    :param offset: where to test
    :return: true if the integer has a bit set to 1 in 'offset' position
    """
    mask = 1 << offset
    return (int_type & mask)


def build_flag_mask(flag_list :list[str]) -> int:
    """
    It creates a mask based on a list of passed flags. 

    :param flag_list: list of standard flag to create the appropriate mask. 
    :retun: mask
    """
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
    :param flag_list: list of strings used to set banners to display
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
        print_error(f"error: service {req_code} not supported")
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
        print_error(f"error: service {req_code} not supported in active session")

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
              ": tester present probe (establish correct packet format). \n"

            + Fore.LIGHTRED_EX + "\t test_dds" + Style.RESET_ALL +
              ": find all the available sessions. \n"

            + Fore.LIGHTRED_EX + "\t test_rdbi" + Style.RESET_ALL +
              ": request specific DIDs.\n"

            + Fore.LIGHTRED_EX + "\t scan_rdbi" + Style.RESET_ALL +
              ": scan all the DIDs.\n"

            + Fore.LIGHTRED_EX + "\t test_wdbi" + Style.RESET_ALL +
              ": writes specified DIDs.\n"

            + Fore.LIGHTRED_EX + "\t test_recu" + Style.RESET_ALL +
              ": reset the ECU (different modes).\n"

            # + Fore.LIGHTRED_EX + "\t test_rsdi" + Style.RESET_ALL +
            #   ": read sensitive data by identifier\n"
            
            + Fore.LIGHTRED_EX + "\t request_seed" + Style.RESET_ALL +
              ": request security access. Params: reset_type, delay, session, access_type. \n"

            + Fore.LIGHTRED_EX + "\t get_current_session" + Style.RESET_ALL +
              ": retrieve the current active session in the ECU.\n"

            + Fore.LIGHTRED_EX + "\t set_new_session" + Style.RESET_ALL +
              ": set diagnostic session. \n"

            + Fore.LIGHTRED_EX + "\t request_upload" + Style.RESET_ALL +
              ": tries to flash memory. \n" 

            + Fore.LIGHTRED_EX + "\t other" + Style.RESET_ALL +
              ": to be continued... \n"
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
  
    return CAN(identifier=can_id, length=8, data=payload)


def send_receive(packet :Packet, 
                 multiframe :bool=False) -> tuple[SndRcvList, PacketList]:
    """
    Calls the sr() scapy function, it distinguish between single and multiframe
    cases. 

    :param packet: CAN packet to send
    :param multiframe: flag to enable multiframe handling
    :return: a tuple of answered (query+answer) and unanswered packets
    """
    can_socket = ctx_man.CAN_SOCKET
    if not multiframe:
            results, unanswered = can_socket.sr(packet, 
                                                retry=0, 
                                                timeout=0.3, 
                                                verbose=0)
    else:
        results, unanswered = can_socket.sr(packet, 
                                            timeout=0.03,
                                            verbose=0, 
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
         fuzz_data_len: bool =False, 
         fuzz_service_range: int =1, 
         fuzz_subservice_range: int =1, 
         fuzz_data_range: int =0, 
         fuzz_data_len_range: int =0, 
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
        # fuzz solo data 
        for fuzzval in range(fuzz_data_range + 1):
            # TODO check
            # ! at least RDBI wants this order for the bytes 
            fuzzval_bytearray = bytearray(fuzzval.to_bytes(byte_length(fuzz_data_range), 'little'))
            fuzzval_bytearray_inverted = fuzzval_bytearray[::-1]
            fuzzval_inverted = bytes(fuzzval_bytearray_inverted)

            packets_list.append(create_packet(service=service, 
                                              data=fuzzval_inverted
                                              #data_len=4
                                              ))

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


def read_response_code(packet: SndRcvList, packet_index :int=0, code_index :int=1) -> int:
    """
    This function tries to extract the service of a received packet. 

    :param packet: list of potentially received packets
    :param packet_index: index of the interesting packet
    :param code_index: for future implementations (string related to a service)
    :return: service integer or -1 in case of error
    """
    try: 
        # result = packet[packet_index].answer.data[code_index] # old
        
        # layer = packet[packet_index].answer.getlayer(1)
        # print(layer)
        result = packet[packet_index].answer.service
    except IndexError:
        return -1
    else:
        return result
    
def read_subresponse_code(packet :SndRcvList, packet_index :int=0, subcode_index :int=2) -> int:
    """
    This function tries to extract the sub-service of a received packet. 

    :param packet: list of potentially received packets
    :param packet_index: index of the interesting packet
    :param code_index: for future implementations (string related to a subservice)
    :return: service integer or -1 in case of error
    """
    try:
        return packet[packet_index].answer.data[subcode_index]
    except IndexError:
        return -1
    

def send_diagnostic_session_control(session :int) -> bool:
    """
    It sends a 10XX diagnostic packet. 

    :param session: integer representing the session to enter. 
    :return: boolean (false for errors)
    """
    can_socket = ctx_man.getCanSocket()
    client_can_id = ctx_man.getCanId()
    
    dsc = create_packet(service=0x10, subservice=session)
    res, unans = send_receive(dsc) 
    ret = read_response_code(res)
    if ret == 0x50:
        return True
    return False


def interpret_did(did_value :str) -> None:
    """
    It renslates integer did values to actual or possible related strings. 

    :param did_value: the integer to interpret. 
    :return: nothing, displays information on screen. 
    """
    did_value = int(did_value, 16)
    if did_value > 0x0000 and did_value < 0x00FF:
        print("\tISOSAEReserved")
    elif did_value > 0x0100 and did_value < 0xA5FF:
        print("\tVehicleManufacturerSpecific")
    elif did_value > 0xA600 and did_value < 0xA7FF:
        print("\tReservedForLegislativeUse")
    elif did_value > 0xA800 and did_value < 0xACFF:
        print("\tVehicleManufacturerSpecific")
    elif did_value > 0xAD00 and did_value < 0xAFFF:
        print("\tReservedForLegislativeUse")
    elif did_value > 0xB000 and did_value < 0xB1FF:
        print("\tVehicleManufacturerSpecific")
    elif did_value > 0xB200 and did_value < 0xBFFF:
        print("\tReservedForLegislativeUse")
    elif did_value > 0xC000 and did_value < 0xC2FF:
        print("\tVehicleManufacturerSpecific")
    elif did_value > 0xC300 and did_value < 0xCEFF:
        print("\tReservedForLegislativeUse")
    elif did_value > 0xCF00 and did_value < 0xEFFF:
        print("\tVehicleManufacturerSpecific")
    elif did_value > 0xF000 and did_value < 0xF00F:
        print("\tnetworkConfigurationDataForTractorTrailerApplicationDID")
    elif did_value > 0xF010 and did_value < 0xF0FF:
        print("\tvehicleManufacturerSpecific")
    elif did_value > 0xF100 and did_value < 0xF17F:
        print("\tidentificationOptionVehicleManufacturerSpecificDID")
    elif did_value == 0xF180:
        print("\tBootSoftwareIdentificationDID")
    elif did_value == 0xF181:
        print("\tapplicationSoftwareIdentificationDID")
    elif did_value == 0xF182:
        print("\tapplicationDataIdentificationDID")
    elif did_value == 0xF183:
        print("\tbootSoftwareFingerprintDID")
    elif did_value == 0xF184:
        print("\tapplicationSoftwareFingerprintDID")
    elif did_value == 0xF185:
        print("\tapplicationDataFingerprintDID")
    elif did_value == 0xF186:
        print("\tActiveDiagnosticSessionDID")
    elif did_value == 0xF187:
        print("\tvehicleManufacturerSparePartNumberDID")
    elif did_value == 0xF188:
        print("\tvehicleManufacturerECUSoftwareNumberDID")
    elif did_value == 0xF189:
        print("\tvehicleManufacturerECUSOftwareVerionNumberDID")
    elif did_value == 0xF18A:
        print("\tsystemSupplierIdentifierDID")
    elif did_value == 0xF18B:
        print("\tECUManufacturingDateDID")
    elif did_value == 0xF18C:
        print("\tECUSerialNumberDID")
    elif did_value == 0xF18D:
        print("\tsupportedFunctionalUnitsDID")
    elif did_value == 0xF18E:
        print("\tVehicleManufacturerKitAssemblyPartNumberDID")
    elif did_value == 0xF18F:
        print("\tRegulationXSoftwareIdentificationNumbers(RxSWIN)")
    elif did_value == 0xF190:
        print("\tVINDataIdentifier")
    elif did_value == 0xF191:
        print("\tvehicleManufacturerECUHardwareNumberDID")
    elif did_value == 0xF192:
        print("\tsystemSupplierECUHardwareNumberDID")
    elif did_value == 0xF193:
        print("\tsystemSupplierECUHardwareVersionNumberDID")
    elif did_value == 0xF194:
        print("\tsystemSupplierECUSoftwareNumberDID")
    elif did_value == 0xF195:
        print("\tsystemSupplierECUSoftwareVersionNumberDID")
    elif did_value == 0xF196:
        print("\texhaustRegulationOrTypeApprovalNumberDID")
    elif did_value == 0xF197:
        print("\tsystemNameOrEngineTypeDID")
    elif did_value == 0xF198:
        print("\trepairShopCodeOrTesterSerialNumberDID")
    elif did_value == 0xF199:
        print("\tprogrammingDateDID")
    elif did_value == 0xF19A:
        print("\tcalibrationRepairShopCodeOrCalibrationEquipmentSerialNumberDID")
    elif did_value == 0xF19B:
        print("\tcalibrationDateDID")
    elif did_value == 0xF19C:
        print("\tcalibrationEquipmentSoftwareNumberDID")
    elif did_value == 0xF19D:
        print("\tECUInstallationDateDID")
    elif did_value == 0xF19E:
        print("\tODXFileDateIdentifier")
    elif did_value == 0xF19F:
        print("\tEntityDataIdentifier")
    elif did_value > 0xF1A0 and did_value < 0xF1EF:
        print("\tidentificationOptionVehicleManufacturerSpecific")
    elif did_value > 0xF1F0 and did_value < 0xF1FF:
        print("\tidentificationOptionSystemSupplierSpecific")
    elif did_value > 0xF200 and did_value < 0xF2FF:
        print("\tperiodicDataIdentifier")
    elif did_value > 0xF300 and did_value < 0xF3FF:
        print("\tDynamicallyDefineDataIdentifier")
    elif did_value > 0xF400 and did_value < 0xF5FF:
        print("\tOBDDataIdentifier")
    elif did_value > 0xF600 and did_value < 0xF6FF:
        print("\tOBDMonitorDataIdentifier")
    elif did_value > 0xF700 and did_value < 0xF7FF:
        print("\tOBDDataIdentifier")
    elif did_value > 0xF800 and did_value < 0xF8FF:
        print("\tOBDInfoTypeDataIdentifier")
    elif did_value > 0xF900 and did_value < 0xF9FF:
        print("\tTachographDataIdentifier")
    elif did_value > 0xFA00 and did_value < 0xFA0F:
        print("\tAirbarDeploymentDID")
    elif did_value == 0XFA10:
        print("\tNumberofEDRDevices")
    elif did_value == 0XFA11:
        print("\tEDRIdentification")
    elif did_value == 0XFA12:
        print("\tEDRDeviceAddressInformation")
    elif did_value > 0xFA13 and did_value < 0xFA18:
        print("\tEDREntries")
    elif did_value > 0xFA19 and did_value < 0xFAFF:
        print("\tSafetySystemDID")
    elif did_value > 0XFB00 and did_value < 0xFCFF:
        print("\tReservedForLegislativeUse")
    elif did_value > 0XFD00 and did_value < 0xFEFF:
        print("\tSystemSupplierSpecific")
    elif did_value == 0XFF00:
        print("\tUDSVersionDID")
    elif did_value == 0xFF01:
        print("\tReservedForISO15765-5")
    elif did_value > 0xFF02 and did_value < 0xFFFF:
        print("\tISOSAEReserved")

    
# for cool console display (not-scrolling)
# import os,time

# clear = lambda: os.system('cls')      # or os.system('clear') for Unix

# for i in range(10,0,-1):
#     clear()
#     print i
#     time.sleep(1)