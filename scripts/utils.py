import os
import json
from rich import print
from rich.console import Console
from rich.logging import RichHandler
import logging
from dotenv import load_dotenv

load_dotenv()  # read .env

console = Console()
logger = logging.getLogger("cti_pipeline")
logger.setLevel(logging.INFO)
handler = RichHandler()
logger.addHandler(handler)

def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def env(key, default=None):
    return os.environ.get(key, default)
