import logging
from soc_triage.config import LOG_LEVEL

def setup_logging():
	logging.basicConfig(
		level=LOG_LEVEL,
		format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
