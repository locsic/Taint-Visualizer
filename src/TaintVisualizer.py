__author__ = 'Loc Nguyen'
__contact__ = 'locvnguy@gmail.com'

import argparse
import re
import TaintTree
import networkx as nx
import matplotlib.pyplot as plt

roottree = nx.DiGraph()

class Node(object):
  def __init__(self, initial = None):
    self.uuid=str(initial)

  def __str__(self):
    return self.uuid

  def extract_data(self, s):
    #Temporary solution is to parse a text file until we get the C struct passed in
    pattern = re.compile(r"""
                          \[(?P<uuid>\d+)\]
                          (?P<type>(reg|mem))
                          _(?P<name>[\d\w_]+)
                          \[(?P<startind>[\d\w:-]+)\]
                          (\[(?P<endind>[\d\w:-]+)\])?
                          (\<-(?P<edgeann>[\d\w\s%(),-]+))?
                          ({D}(?P<child>[\d]+))?
                          """, re.VERBOSE)
    m = pattern.search(s)
    print s
    self.uuid = m.group('uuid')
    #print m.group('uuid')
    self.typ = m.group('type') #Check to see if 'type' is a reserved word
    self.name = m.group('name')
    self.startind = m.group('startind')
    self.endind = m.group('endind')
    self.edgeann = m.group('edgeann')
    self.child = m.group('child')

def insert_node(data):
  global roottree
  tempNode = None
  uuid = extract_uuid(data)
  #Create new node and add to roottree
  #Reimplment without exception
  if roottree.has_node(uuid):
    tempNode = roottree.node[uuid]['inode']
    tempNode.extract_data(data)
  else:
    tempNode = Node()
    tempNode.extract_data(data)
    roottree.add_node(uuid, inode = tempNode)
  if tempNode.child is not None:
    for x in tempNode.child.split(' '):
      newNode = Node(x)
      roottree.add_node(x, inode = newNode)
      #roottree.add_edge(tempNode, newNode, anno=tempNode.edgeann)
      roottree.add_edge(str(tempNode), x, anno=tempNode.edgeann)

def extract_uuid(s):
  pattern = re.compile(r"""
                        \[(?P<uuid>\d+)\].*
                        """, re.VERBOSE)
  m = pattern.search(s)
  return str(m.group('uuid'))

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='TaintAnalyzer')
  parser.add_argument("-t", "--taint",
                    help="input taint FILE", metavar="FILE",
                    required=True)
  args = vars(parser.parse_args())
  print args['taint']
  #global roottree
  f = open(args['taint'], 'r')
  # Read input file line by line
  for line in f:
    insert_node(line.rstrip('\n'))

  ###Matplotlib###
  plt.title("taint_treex")
  pos = nx.spring_layout(roottree)
  ##nx.write_dot(roottree, 'test.dot')
  #nx.draw_networkx(roottree)
  ##pos=nx.graphviz_layout(roottree,prog='dot')
  ##pos=nx.graphviz_layout(roottree,prog='dot')
  ######NODES######
  #nx.draw_networkx_nodes(roottree, pos, node_size=3000, node_color='white')
  #nx.draw_networkx_nodes(roottree, pos, node_size=3000, node_color='blue', nodelist=[x for x in roottree.nodes()])
  nx.draw_networkx_nodes(roottree, pos, node_size=3000, node_color='blue', nodelist=[x for x in roottree.nodes() if roottree.node[x]['inode'].typ == 'reg'])
  nx.draw_networkx_nodes(roottree, pos, node_size=3000, node_color='green', nodelist=[x for x in roottree.nodes() if roottree.node[x]['inode'].typ == 'mem'])
  #nx.draw_networkx_nodes(roottree, pos, node_size=3000, node_color='blue', nodelist=[x for x in roottree.nodes()['inode if x.typ == 'reg'])
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
