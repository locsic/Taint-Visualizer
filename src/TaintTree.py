__author__ = 'Loc Nguyen'
__contact__ = 'locvnguy@gmail.com'
import re

class Node(object):
  def __init__(self, uuid):
    self.uuid = uuid
    self.parent = None
    self.typ = None
    self.byte_in = None
    self.thread_id = None
    self.edge_ann = None
    self.children = [] #Legacy

  def add(self, child):
    self.children.append(child)
    child.parent = self

  def extract_data(s):
    #For now, the type isn't split off
    #(P<type>['reg'|'mem']
    pattern = re.compile(r"""
                            \[(?P<uuid>(\d)+)\]
                            (?P<type>(reg|mem))
                            _(?P<name>\w+)
                            \[(?P<byteindex>[\d:-]+)\]
                            \[(?P<threadids>[\d:-]+)\]
                            (\<-(?P<edge>(.*?)?))*
                              """, re.VERBOSE)
#
# insert a node into a tree at a specific depth (tab) level
#
class Inserter(object):
  def __init__(self, node, depth = 0):
    self.node = node
    self.depth = depth

  def __call__(self, uuid, depth):
    newNode = Node(uuid)
    if (depth > self.depth):
      self.node.add(newNode)
      self.depth = depth
    elif (depth == self.depth):
      self.node.parent.add(newNode)
    else:
      parent = self.node.parent
      for i in range(0, self.depth - depth):
          parent = parent.parent
      parent.add(newNode)
      self.depth = depth
    self.node = newNode

def print_tree(node, depth = 0):
  print '%s%s' % (' ' * depth, node.uuid)
  for child in node.children:
    print_tree(child, depth + 1)
