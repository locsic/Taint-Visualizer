from ete2 import PhyloTree, faces, layouts
# Loads tree and array 
gtree = PhyloTree("./genetree.nw", alignment="./genetree_alg.fasta")

# Roots the gene tree
gtree.set_outgroup(gtree.search_nodes(name="Ddi0002240")[0])

sptree = PhyloTree("speciestree.nw")
t, events = gtree.reconcile(sptree)


# Creates a set of faces with species images. Pictures were taken from
# the ensembl web page (ensembl.org).
spFaces = {}
for spcode in sptree.get_species():
    spFaces[spcode] = faces.ImgFace("%s.png" %spcode)

# gene duplication image
dupFace = faces.ImgFace("./duplication.png")

# Creates my own layout function that uses previous faces
def mylayout(node):
    # first, Let's apply the default phylogeny layout
    layouts.phylogeny(node)

    # If node is leaf, add a picture with its species.
    if node.is_leaf():
	faces.add_face_to_node(spFaces[node.species], node, 1)

    # If node is internal, check for duplication events
    else:
	if hasattr(node,"evoltype"):
	    # if node is a duplication, add an image to
	    # highlight it
	    if node.evoltype == "D":
		node.img_style["size"]=14
		faces.add_face_to_node(dupFace, node, 0)
		
		# If node represents a human specific
		# duplication, set a different
		# background
		if node.get_species() == set(["Hsa"]):
		    node.img_style["bgcolor"]="#b9bbdd"
		    
# Use my layout to visualize the tree
t.show(mylayout)
