
# TO DO comment all with descriptions
# TO DO forse alcune di queste variabili sono usate solamente all'interno di un file, non ha senso 
# portarle fuori, si mettono lì e si accedono con global keyword penso


VERBOSE_DEBUG = False
EXTRA_VERBOSE_DEBUG = False
CAN_IDENTIFIER = 0x7E5 # 0x714 # TO DO must be set properly, using scanning modules
SERVER_CAN_ID = 0x7ED
CAN_INTERFACE = "can0"
CAN_SOCKET = None # TO DO change to uppercase

lengths = [1, 2, 1, 2, 2, 2, 1, 2]
payloads = [b'\x01\x3E',
            b'\x02\x3E\x00',
            b'\x01\x3E\x00\x00\x00\x00\x00\x00',
            b'\x02\x3E\x00\x00\x00\x00\x00\x00',
            b'\x02\x3E\x80',
            b'\x02\x3E\x80\x00\x00\x00\x00\x00', 
            b'\x01\x3E\x55\x55\x55\x55\x55\x55',
            b'\x02\x3E\x00\x55\x55\x55\x55\x55',
            ]
passed = [False for i in range(0,8)]