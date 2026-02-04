"""
config.py
Configuration settings for Classify AI
"""

from enum import Enum

# ==================== DATABASE CONSTANTS ====================
DB_PATH = "school_data.db"
TABLE_NAME = "students"
LOCAL_DB = 'USE_LOCALDB'
MYSQL = 'USE_MYSQL'

# ==================== USER ROLES ====================
USERS = {
    "admin": {
        "password": "admin123",
        "role": "Admin",
        "permissions": ["upload", "chat", "view", "delete", "export"]
    },
    "teacher": {
        "password": "teacher123",
        "role": "Teacher",
        "permissions": ["chat", "view"]
    },
    "data_entry": {
        "password": "data123",
        "role": "Data Entry",
        "permissions": ["upload", "view", "export"]
    },
    "viewer": {
        "password": "view123",
        "role": "Viewer",
        "permissions": ["chat"]
    }
}

# ==================== ROLE PERMISSIONS ====================
ROLE_PERMISSIONS = {
    "Admin": {
        "sql_operations": ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"],
        "table_access": "all",
        "restrictions": "none"
    },
    "Teacher": {
        "sql_operations": ["SELECT", "UPDATE"],
        "table_access": "student_tables",
        "restrictions": "no_deletions, no_system_tables, requires_where_clause"
    },
    "Data Entry": {
        "sql_operations": ["SELECT", "INSERT", "UPDATE"],
        "table_access": "authorized_only",
        "restrictions": "no_structural_changes, single_table_ops, requires_limit"
    },
    "Viewer": {
        "sql_operations": ["SELECT"],
        "table_access": "limited",
        "restrictions": "no_aggregations, requires_limit, no_select_star"
    }
}

# ==================== SENSITIVE TABLES ====================
SENSITIVE_TABLES = ["users", "admin", "credentials", "passwords", "config", "salary", "payments"]

# ==================== LLM CONFIGURATION ====================
SAFETY_MODEL_NAME = "meta-llama/llama-guard-4-12b"
QUERY_GENERATION_MODEL = "llama-3.1-8b-instant"
SUMMARIZATION_MODEL = "llama-3.1-8b-instant"

# ==================== UI CONFIGURATION ====================
HEADER_CLASSES = 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white'
PRIMARY_BUTTON_CLASSES = 'bg-indigo-600 text-white'
SUCCESS_BUTTON_CLASSES = 'bg-green-600 text-white'
DANGER_BUTTON_CLASSES = 'bg-red-600 text-white'
INFO_BUTTON_CLASSES = 'bg-blue-600 text-white'

# ==================== MESSAGES ====================
WELCOME_MESSAGE = """Hello! I'm Classify AI. Ask me anything about your school data in plain English, and I'll help you retrieve the information you need."""

EXAMPLE_QUERIES = [
    "Show me all students",
    "How many students are there?",
    "List students by grade",
    "Find students with GPA > 3.5"
]

# ==================== FILE UPLOAD ====================
ALLOWED_FILE_EXTENSIONS = ['.xlsx', '.xls']
MAX_FILE_SIZE_MB = 100

# ==================== DATABASE QUERY ====================
DEFAULT_QUERY_LIMIT = 1000
PREVIEW_ROWS = 20

# ==================== TIMEOUTS ====================
QUERY_TIMEOUT_SECONDS = 30
UPLOAD_TIMEOUT_SECONDS = 60