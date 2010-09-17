import os
import sys

try:
    __file__
except NameError:
    __file__ = sys.argv[0]
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
