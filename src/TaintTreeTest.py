import re
import TaintTree

with open(r'1.txt', 'r') as f:
  tree = TaintTree.Node(f.readline().rstrip('\n'))
  inserter = TaintTree.Inserter(tree)

  for line in f:
    line = line.rstrip('\n')
    #Count depth as tabs in the beginning of a string
    depth = re.match('\t*', line).group(0).count('\t')
    uuid = line[depth:]
    inserter(uuid, depth)
  TaintTree.print_tree(tree)
