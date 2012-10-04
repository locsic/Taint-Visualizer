from ete2 import Tree

words = [ "reel", "road", "root", "curd", "curl", "whatever","whenever", "wherever"]

#Creates a empty tree
tree = Tree()
tree.name = ""
# Lets keep tree structure indexed
name2node = {}
# Make sure there are no duplicates
words = set(words)
# Populate tree
for wd in words:
  # If no similar words exist, add it to the base of tree
  target = tree

  # Find relatives in the tree
  for pos in xrange(len(wd), -1, -1):
    root = wd[:pos]
    if root in name2node:
      target = name2node[root]
      break

  # Add new nodes as necessary
  fullname = root 
  for letter in wd[pos:]:
    fullname += letter 
    new_node = target.add_child(name=letter, dist=1.0)
    name2node[fullname] = new_node

    target = new_node

# Print structure
print tree.get_ascii()
