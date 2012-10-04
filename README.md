Taint-Visualizer
================

Initially I opted to create my own data structure for internal representation of the taint data. The logic being that we can maintain the internal structure while interchanging visualization software. Particularly because different visualization software have different learning-curves. The logic did not work very well with ETE2 which is highly dependent on using its own internal data structure for tree generation.

Designing my own tree data structure means we can have each line of the log be depth-dependent on the number of tabs

Parsing the data, I created a simple regular expression to capture groups within the line. 

Visualization Library Considerations

ETE2
- Appears to be inflexible with the data that can be represented in a node. We can't have nodes pointing to the custom node structure generated for the exercise.

NetworkX
- Appears to be more flexible and allows for pointing at different objects by not only nodes but their edges. Edge attributes can also point to an object/data value. We can also change edge weights within networkx, and therefore implement costs with certain edges.

Multiple possibilities with generating a tree using the networkx library. Defining a tree, we can state that the root of the tree will be the only node with zero in-degree, no predecessors. Depending on performance considerations, we can build our tree and just perform an nx.topological_sort upon the graph where the root will be the first item. Alternatively we can start at any node and follow the chain of predecessors til we come upon the root.

Todo
  -Export tree to dot file
  -IdaPython implementation

Bugs
  - Creation of a new roottree creates an empty node. Probably because of how inserter is initialized per root

Do we create a list of trees, or attach all trees to a single root
  -Consideration of difficulty for clipping subtree. Not really an issue because we just return the subroot.

Assumptions
  - Sequential read of the taint, meaning the log line exists within the most root of its perimeter

Issues
  - Big issue is finding the interface between the text log data and interal tree structure
