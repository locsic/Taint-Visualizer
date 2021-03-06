__author__ = 'Loc Nguyen'
__contact__ = 'locvnguy@gmail.com'
import re

class Node(object):
  def __init__(self, uuid):
    self.uuid = uuid
    self.parent = None #Legacy - Delete
    self.typ = None #Check and see if type is a reserved word
    self.name = None
    self.byteindex = None
    self.threadids = None
    self.edge_ann = None
    self.children = [] #Legacy

  def add(self, child):
    self.children.append(child)
    child.parent = self

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
