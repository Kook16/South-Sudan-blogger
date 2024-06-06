import sys
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/path/)

from app import app as applicaion
