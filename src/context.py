from typing import override
import ida_domain
from ida_domain import Database
from ida_domain.database import IdaCommandOptions
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__file__)

class Context():
    pass