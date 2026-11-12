import os

from dotenv import load_dotenv

load_dotenv()  # reads .env if present; real environment variables still win

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./soc_triage.db")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
LLM_TIMEOUT_S = int(os.getenv("LLM_TIMEOUT_S", "180"))
