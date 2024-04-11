# file containing global variables
from classes import graph
from utility import NativeCANSocket

VERBOSE_DEBUG = False  # verbosity flag
CAN_IDENTIFIER = 0x7E5 # my CAN ID
SERVER_CAN_ID = 0x7ED  # ECU server CAN ID # TODO: in the future, this variable now is used only in main.py
CAN_INTERFACE = "can0" # interface for CAN communication
CAN_SOCKET = NativeCANSocket()   # socket for CAN communication


# variables used to establish the correct packet format
# through tester present probings
lengths = [1, 2, 1, 2, 2, 2, 1, 2] # TODO: in the future, this variable now is used only in a print
payloads =  [  # TODO: in the future, this variable now is used in a print and in another file (thus no global)
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

SessionsGraph = graph({"0x10" : []}) # Default diagnostic always available 