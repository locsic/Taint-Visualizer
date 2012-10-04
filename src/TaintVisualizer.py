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
                          (\<-(?P<edgeann>.*?))*
                          """, re.VERBOSE)
    m = pattern.search(initial)
    self.uuid = m.group('uuid')
    self.typ = m.group('typ') #Check to see if 'type' is a reserved word
    self.name = m.group('name')
    self.byte_in = m.group('byteindex')
    self.threadids = m.group('threadids')
    self.edgeann = m.group('edgeann')

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
      roottree.add(newNode)
      if self.node.edgeann is not None:
        roottree.add_edge(self.node, newNode, ann=self.node.edgeann)
      else: 
        roottree.add_edge(self.node, newNode)
      self.depth = depth
    elif(depth == self.depth):
      roottree.add(newNode)
      if self.node.edgeann is not None:
        roottree.add_edge(roottree.pred(self.node), newNode, ann=self.node.edgeann)
      else: 
        roottree.add_edge(roottree.pred(self.node), newNode)
      #self.node.parent.add(newNode)
    else:
      parent = roottree.pred(self.node)
      for i in range(0, self.depth - depth):
        parent = roottree.pred(parent)
      roottree.add(newNode)
      if self.node.edgeann is not None:
        roottree.add_edge(parent, newnode, ann=self.node.edgeann)
      else:
        roottree.add_edge(parent, newnode)
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
  inFile = open(args['taint'])
  global roottree
  roottree.add_node("ROOT")
  with open(inFile, 'r') as f:
    for line in f:
      depth = re.match('\t*', line).group(0).count('\t')
      line = line.rstrip('\n')
      #New tree root
      if(depth == 0):
        tree = Node(line.rstrip('\n'))
        inserter = Inserter(tree)
      else:
        nodedata = line[depth:]
        inserter(nodedata, depth)
