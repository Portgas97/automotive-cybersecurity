from scapy.contrib.cansocket_native import NativeCANSocket
from graph import Graph

# ============================================================================ #
# ============================================================================ #
# =                         CONFIGURATION MANAGER                            = #
# ============================================================================ #
# ============================================================================ #

# TODO description

class ConfigurationManager:

    def __init__(self):
            self.VERBOSE_DEBUG = False  # verbosity flag
            self.CAN_IDENTIFIER = 0x7E5 # my CAN ID # TODO not set in production
            self.SERVER_CAN_ID = 0x7ED  # ECU server CAN ID # TODO not set in production
            self.CAN_INTERFACE = "can0" # interface for CAN communication

            # TODO not set in production
            # Default diagnostic is always available
            self.SessionsGraph = Graph({0x01 : []})
            self.ToCheckGraph = Graph({})
            # self.SessionsGraph = Graph({0x01 : [0x03, 0x40, 0x4f], 
                                        # 0x03 : [0x01, 0x40, 0x4f], 
                                        # 0x40 : [0x01, 0x03, 0x4f], 
                                        # 0x4f : [0x01, 0x03, 0x40]}) 
            self.CAN_SOCKET = NativeCANSocket()
    
    def getConfigurations(self):
            return self.__dict__.keys()
    
    def readConfigurations(self):
        for conf in self.__dict__.keys():
            print(f"[{conf}] => \"{self.__dict__[conf]}\"")

    def getVerboseDebug(self):
        return self.VERBOSE_DEBUG
    
    def setVerboseDebug(self, verbosity :bool):
        self.VERBOSE_DEBUG = verbosity
    
    def getCanId(self):
        return self.CAN_IDENTIFIER

    def setCanId(self, can_id :int):
        self.CAN_IDENTIFIER = can_id
    
    def getServerCanId(self):
        return self.SERVER_CAN_ID

    def setServerCanId(self, server_can_id :int):
        self.SERVER_CAN_ID = server_can_id

    def getCanInterface(self):
        return self.CAN_INTERFACE
    
    def setCanInterface(self, interface :str):
        self.CAN_INTERFACE = interface
    
    def getSessionGraph(self):
        return self.SessionsGraph
    
    def setSessionGraph(self, graph_dict):
        self.SessionsGraph = graph_dict
        
    def getCanSocket(self):
        return self.CAN_SOCKET
    
    def setCanSocket(self, can_socket :NativeCANSocket):
        self.CAN_SOCKET = can_socket
    

# global instantiation 
config_manager = ConfigurationManager()
