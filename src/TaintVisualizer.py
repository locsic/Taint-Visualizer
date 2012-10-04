__author__ = 'Loc Nguyen'
__contact__ = 'locvnguy@gmail.com'

import argparse
import re
import TaintTree
import networkx as nx
import matplotlib.pyplot as plt

roottree = nx.DiGraph()

class Node(object):
  def __init__(self, initial):
    pattern = re.compile(r"""
                          \[(?P<uuid>\d+)\]
                          (?P<type>(reg|mem))
                          _(?P<name>\w+)
                          \[(?P<byteindex>[\d:-]+)\]
                          \[(?P<threadids>[\d:-]+)\]
                          (\<-(?P<edgeann>.*))*
                          """, re.VERBOSE)
    m = pattern.search(initial)
    self.uuid = m.group('uuid')
    #print m.group('uuid')
    self.typ = m.group('type') #Check to see if 'type' is a reserved word
    self.name = m.group('name')
    self.byte_in = m.group('byteindex')
    self.threadids = m.group('threadids')
    self.edgeann = m.group('edgeann')

  def __str__(self):
    return self.uuid

  def extract_data(s):
    #>>> setup = ur"import re; regex =re.compile("\[(?P<uuid>\d+)\](?P<type>(reg|mem))_(?P<name ...
    #>>> t = timeit.Timer('regex.search(string)',setup)
    #>>> t.timeit(10000)
    #0.0240871906281
    #
    pattern = re.compile(r"""
                          \[(?P<uuid>\d+)\]
                          (?P<type>(reg|mem))
                          _(?P<name>\w+)
                          \[(?P<byteindex>[\d:-]+)\]
                          \[(?P<threadids>[\d:-]+)\]
                          (\<-(?P<edgeann>.*?))*
                          """, re.VERBOSE)
    m = pattern.search(s)
    self.uuid = m.group('uuid')
    self.typ = m.group('typ')
    self.name = m.group('name')
    self.byte_in = m.group('byteindex')
    self.threadids = m.group('threadids')
    self.edgeann = m.group('edgeann')

#
# insert a node into a tree at the specific depth (tab) level
# keep track of last inserted node so we can follow up its predecessor
#

class Inserter(object):
  def __init__(self, node, depth = 0):
    self.node = node
    self.depth = depth
    global roottree
    roottree.add_node(node)
    roottree.add_edge("ROOT", node)

  def __call__(self, data, depth):
    global rootree
    newNode = Node(data)
    if (depth > self.depth):
      roottree.add_node(newNode)
      if self.node.edgeann is not None:
        roottree.add_edge(self.node, newNode, anno=self.node.edgeann)
      else: 
        roottree.add_edge(self.node, newNode)
      self.depth = depth
    elif(depth == self.depth):
      roottree.add_node(newNode)
      if self.node.edgeann is not None:
        roottree.add_edge(roottree.predecessors(self.node)[0], newNode, anno=roottree.predecessors(self.node)[0].edgeann)
      else: 
        roottree.add_edge(roottree.predecessors(self.node)[0], newNode)
      #self.node.parent.add(newNode)
    else:
      #print roottree.pred(self.node)
      parent = roottree.predecessors(self.node)[0]
      for i in range(0, self.depth - depth):
        parent = roottree.predecessors(parent)[0]
      roottree.add_node(newNode)
      if self.node.edgeann is not None:
        roottree.add_edge(parent, newNode, anno=parent.edgeann)
      else:
        roottree.add_edge(parent, newNode)
      self.depth = depth
    self.node = newNode

def print_tree(node, depth = 0):
  print '%s%s' % (' ' * depth, node.uuid)
  for child in node.children:
    print_tree(child, depth + 1)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='TaintAnalyzer')
  parser.add_argument("-t", "--taint",
                    help="input taint FILE", metavar="FILE",
                    required=True)
  args = vars(parser.parse_args())
  print args['taint']
  #global roottree
  roottree.add_node("ROOT")
  f = open(args['taint'], 'r')
  inserter = Inserter(None)
  for line in f:
    line = line.rstrip('\n')
    depth = re.match('\t*', line).group(0).count('\t')
    #New tree root
    if(depth == 0):
      tree = Node(line.rstrip('\n'))
      inserter = Inserter(tree)
    else:
      nodedata = line[depth:]
      inserter(nodedata, depth)
  plt.title("taint_treex")
  pos = nx.spring_layout(roottree)
  ##nx.write_dot(roottree, 'test.dot')
  #nx.draw_networkx(roottree)
  ##pos=nx.graphviz_layout(roottree,prog='dot')
  ##pos=nx.graphviz_layout(roottree,prog='dot')
  ######NODES######
  nx.draw_networkx_nodes(roottree, pos, node_size=3000, node_color='white')
  ######EDGES######
  nx.draw_networkx_edges(roottree, pos, width=6, alpha=0.5, edge_color='black')
  ######LABELS######
  nx.draw_networkx_labels(roottree, pos, font_size=10, font_family='sans-serif')
  ##nx.draw_networkx_nodes(roottree, pos=nx.spring_layout(roottree), node_size=1200, node_shape='o', node_color='0.75')
  ##nx.draw_networkx_edges(roottree, pos=nx.spring_layout(roottree), width=2, edge_color='b')
  ##nx.draw_networkx_labels(roottree, pos=nx.spring_layout(roottree), fontsize=2, labelloc='c')
  ###labels = dict((n,d['anno']) for n,d in roottree.nodes(data=True))
  ###print labels
  nx.draw_networkx_edge_labels(roottree, pos, font_size=6, labelloc='c')
  ##nx.draw(roottree,pos=nx.spring_layout(roottree),labels=True, arrows=False)
  plt.axis('off')
  plt.savefig('taint_tree.png')
  plt.show()
