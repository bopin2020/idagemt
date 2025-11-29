from .protocolmodel import *

class GraphStub():
    def __init__(self,
                 name):
        self.name = name
        self.graph = nx.Graph()

    def add_edge(self,node1,node2):
        self.graph.add_edge(node1,node2)

    def query_shortest_path(self,node1,node2):
        return nx.shortest_path(self.graph,node1,node2)