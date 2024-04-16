# file containing useful classes 

from scapy.contrib.cansocket_native import NativeCANSocket

class graph:
        
    def __init__(self,gdict=None):
        if gdict is None:
            gdict = {}
        self.gdict = gdict

    def edges(self):
        return self.findedges()
    
    def getVertices(self):
        return list(self.gdict.keys())
    
    # Add the vertex as a key
    def addVertex(self, vrtx):
        if vrtx not in self.gdict:
            self.gdict[vrtx] = []

    # Add the new edge
    def AddEdge(self, edge):
        # edge = set(edge)
        (vrtx1, vrtx2) = tuple(edge)
        if vrtx1 in self.gdict:
            self.gdict[vrtx1].append(vrtx2)
        else:
            self.gdict[vrtx1] = [vrtx2]

    # List the edge names
    def findedges(self):
        edgename = []
        for vrtx in self.gdict:
            for nxtvrtx in self.gdict[vrtx]:
                if {nxtvrtx, vrtx} not in edgename:
                    edgename.append({vrtx, nxtvrtx})
            return edgename

    # Prints the graph structure
    def printGraph(self):
        for vrtx in self.gdict:
            print(f"{hex(vrtx)} \t-> \t[", end="")
            for e in self.gdict[vrtx]:
                print(f" {hex(e)} ", end="")
            print("]")
        
    # Check if value is present in subtree
    def findChildNode(self, root_node: int, value: int) -> bool:
        if (value == root_node) or (value in self.gdict[root_node]):
            return True
        return False

class ConfigurationManager:

    def __init__(self):
            self.VERBOSE_DEBUG = False  # verbosity flag
            self.CAN_IDENTIFIER = 0x7E5 # my CAN ID
            self.SERVER_CAN_ID = 0x7ED  # ECU server CAN ID # TODO: in the future, this variable now is used only in main.py
            self.CAN_INTERFACE = "can0" # interface for CAN communication
            self.SessionsGraph = graph({0x01 : []}) # Default diagnostic is always available
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
