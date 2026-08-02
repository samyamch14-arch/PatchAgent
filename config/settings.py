import os
from dotenv import load_dotenv

load_dotenv()

# OLLAMA settings
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")

# Agent loop settings
AGENT_INTERVAL_HOURS = int(os.getenv("AGENT_INTERVAL_HOURS", "6"))
MONITORING_WINDOW_HOURS = int(os.getenv("MONITORING_WINDOW_HOURS", "24"))
MAX_REMEDIATION_ATTEMPTS = int(os.getenv("MAX_REMEDIATION_ATTEMPTS", "3"))

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(BASE_DIR, "database", "patch_agent.db")

# Risk thresholds
RISK_LEVELS = ["Low", "Medium", "High"]
AUTO_INSTALL_RISK_LEVELS = ["Low", "Medium"]

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(LOGS_DIR, "agent.log")