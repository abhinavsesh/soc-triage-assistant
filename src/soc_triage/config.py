import os
LOG_LEVEL = os.getenv("LOG_LEVEL","INFO")
DATABASE_URL = os.getenv("DATABASE_URL","sqlite:///./soc_triage.db")
