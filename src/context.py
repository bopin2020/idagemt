import os
import sys

from typing import override
from contextlib import contextmanager
import networkx as nx
from enum import IntEnum

import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__file__)

@contextmanager
def context_resource(*args,**kwds):
    try:
        pass
    finally:
        pass

class Context():
    def __init__(self,args):
        self.file = args.input_file
        self.idaoption = IdaCommandOptions(auto_analysis=True, new_database=False)

    def __enter__(self) -> Context:
        logger.info('[*] context manager init...')
        return self

    def __exit__(self,exc_type, exc_value, traceback):
        logger.info('[-] context manager uninit...')