__author__ = 'Loc Nguyen'                                                                                                                                                                   
__contact__ = 'locvnguy@gmail.com'      

import argparse
import TaintTree
import re
from ete2 import Tree

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='TaintAnalyzer')
  parser.add_argument("-t", "--taint",
                    help="input taint FILE", metavar="FILE",
                    required=True)
  args = vars(parser.parse_args())
  print args['taint']
  inFile = open(args['taint'])
  with open(inFile, 'r') as f:
    for line in f:
      line = line.rstrip('\n')
  #No longer necessary VV
  #if len(args) != 1:
  #  parser.error("Wrong amount of args")
