# file containing useful classes 

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
                print(f"{vrtx} -> {self.gdict[vrtx]}")
            
    # Check if value is present in subtree
        def findChildNode(self, root_node: int, value: int) -> bool:
            if (value == root_node) or (value in self.gdict[root_node]):
                return True
            return False

            

# ? examples 
# TODO delete  
# Create the dictionary with graph elements
# graph_elements = { 
#     "a" : ["b", "c"],
#     "b" : ["a", "d"],
#     "c" : ["a", "d"],
#     "d" : ["e"],
#     "e" : ["d"]
#     }
# g = graph(graph_elements)
# g.addVertex("f")
# print(g.getVertices())
# g.AddEdge({'a','e'})
# g.AddEdge({'a','c'})
# print(g.edges())