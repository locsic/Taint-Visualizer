__author__ = 'Loc Nguyen'
__contact__ = 'locvnguy@gmail.com'

import argparse
import re
import TaintTree
import networkx as nx
import matplotlib.pyplot as plt

#roottree = nx.DiGraph()
roottree = nx.MultiDiGraph()

class Node(object):
  def __init__(self, initial = None):
    self.uuid=str(initial)

  def __str__(self):
    return self.uuid

  def label(self):
    return "[%s]%s_%s\n[%s][%s]" % (self.uuid, self.typ, self.name, self.startind, self.endind)

  def extract_data(self, s):
    #Temporary solution is to parse a text file until we get the C struct passed in
    pattern = re.compile(r"""
                          \[(?P<uuid>\d+)\]
                          (?P<type>(reg|mem))
                          _(?P<name>[\d\w_]+)
                          \[(?P<startind>[\d\w:-]+)\]
                          (\[(?P<endind>[\d\w:-]+)\])?
                          (\<-(?P<edgeann>[\d\w\s%(),-]+))?
                          ({D}(?P<child_d>[\d\s]+))?
                          ({C}(?P<child_c>[\d\s]+))?
                          """, re.VERBOSE)
    m = pattern.search(s)
    self.uuid = m.group('uuid')
    #print m.group('uuid')
    self.typ = m.group('type') #Check to see if 'type' is a reserved word
    self.name = m.group('name')
    self.startind = m.group('startind')
    self.endind = m.group('endind')
    self.edgeann = m.group('edgeann')
    self.child_c = m.group('child_c')
    self.child_d = m.group('child_d')

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
  #Data Children
  child_edges(tempNode)

def child_edges(node):
  global roottree
  for attr, value in node.__dict__.iteritems():
      if(attr.startswith('child')):
          x = getattr(node, attr)
          if x is not None:
              for child in x.split():
                  if roottree.has_node(child):
                      roottree.add_edge(str(node), child, anno=node.edgeann, edgetype=attr.split('_')[1])
                  else:
                      newNode = Node(child)
                      roottree.add_node(child, inode = newNode)
                      roottree.add_edge(str(node), child, anno=node.edgeann, edgetype=attr.split('_')[1])

def extract_uuid(s):
  pattern = re.compile(r"""
                        \[(?P<uuid>\d+)\].*
                        """, re.VERBOSE)
  m = pattern.search(s)
  return str(m.group('uuid'))

def edge_color():
  global roottree
  colors = []
  for edge,data in roottree.edges_iter(data=True):
      return 'red' if data['edgetype'] == 'c' else 'blue'
  return colors

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
  roottree.reverse(copy=False)

  ###Matplotlib###
  plt.title(args['taint'])
  plt.figure(figsize=(50,30))
  #pos = nx.spring_layout(roottree)
  nx.write_dot(roottree, 'test.dot')
  #nx.draw_networkx(roottree)
  ##pos=nx.graphviz_layout(roottree,prog='dot', args='')
  pos=nx.graphviz_layout(roottree,prog='dot', args='-Goverlap=false')
  ##pos=nx.graphviz_layout(roottree,prog='fdp')
  ######NODES######
  #node_labels=dict([(u,d['anno']) for u,d in roottree.edges(data=True)])
  #roottree = nx.relabel_nodes(roottree, node_labels)
  #nx.draw_networkx_nodes(roottree, pos, node_shape='o', node_size=500, node_color='red', nodelist=[x for x in roottree.nodes() if roottree.node[x]['inode'].child_d is None])
  nx.draw_networkx_nodes(roottree, pos, node_shape='o', node_size=500, node_color='red', alpha=.5, nodelist=[x for x in roottree.nodes() if not roottree.successors(x)])
  #nx.draw_networkx_nodes(roottree, pos, node_size=500, node_color='brown', nodelist=[x for x in roottree.nodes() if (roottree.node[x]['inode'].typ == 'reg' and roottree.node[x]['inode'].child_d is not None)])
  nx.draw_networkx_nodes(roottree, pos, node_size=500, node_color='purple', nodelist=[x for x in roottree.nodes() if (roottree.node[x]['inode'].typ == 'reg' and roottree.successors(x))])
  #nx.draw_networkx_nodes(roottree, pos, node_size=500, node_color='orange', nodelist=[x for x in roottree.nodes() if (roottree.node[x]['inode'].typ == 'mem' and roottree.node[x]['inode'].child_d is not None)])
  nx.draw_networkx_nodes(roottree, pos, node_size=500, node_color='orange', nodelist=[x for x in roottree.nodes() if (roottree.node[x]['inode'].typ == 'mem' and roottree.successors(x))])
  #nx.draw_networkx_nodes(roottree, pos, node_size=500, node_color='orange', nodelist=[x for x in roottree.nodes() if roottree.node[x]['inode'].typ == 'mem'])
  nx.draw_networkx_nodes(roottree, pos, node_shape='o', node_size=500, node_color='red', nodelist=[x for x in roottree.nodes() if not roottree.predecessors(x)])
  ######EDGES######
  #edge_c=dict([((u,v),d['edgetype']) for u,v,d in roottree.edges(data=True)])
  nx.draw_networkx_edges(roottree, pos, width=1, alpha=0.6, arrows=True, edge_color='red', style='dashed', edgelist=[(x,y) for x,y,d in roottree.edges(data=True) if (d['edgetype'] == 'c')])
  nx.draw_networkx_edges(roottree, pos, width=1, alpha=0.5, arrows=True, edge_color='black', edgelist=[(x,y) for x,y,d in roottree.edges(data=True) if (d['edgetype'] == 'd')])
  ######NODE LABELS######
  node_labels=dict([(u,d['inode'].label()) for u,d in roottree.nodes(data=True)])
  offset = 13
  pos_labels = {}
  keys = pos.keys()
  for key in keys:
      x, y = pos[key]
      pos_labels[key] = (x-offset, y)
  nx.draw_networkx_labels(roottree, pos=pos_labels, labels=node_labels, font_size=10, font_family='sans-serif')
  #nx.draw_networkx_labels(roottree, pos, font_size=6, font_family='sans-serif')
  ##nx.draw_networkx_nodes(roottree, pos=nx.spring_layout(roottree), node_size=1200, node_shape='o', node_color='0.75')
  ##nx.draw_networkx_edges(roottree, pos=nx.spring_layout(roottree), width=2, edge_color='b')
  ##nx.draw_networkx_labels(roottree, pos=nx.spring_layout(roottree), fontsize=2, labelloc='c')
  ###print labels
  edge_labels=dict([((u,v),d['anno']) for u,v,d in roottree.edges(data=True)])
  nx.draw_networkx_edge_labels(roottree, pos, label_pos=.5, font_size=11, edge_labels=edge_labels, rotate=False)
  ##nx.draw(roottree,pos=nx.spring_layout(roottree),labels=True, arrows=False)
  plt.axis('off')
  plt.savefig('taint_tree.png')
  plt.show()
