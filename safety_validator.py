"""
safety_validator.py
-------------------
Modular validation module for checking user NL queries and generated SQL queries
against defined safety policies using a selected LLM (e.g., Llama Guard or GPT OSS Safeguard).
Uses .format() for clean f-string-style prompt filling.
"""

from langchain_groq import ChatGroq


class SafetyValidator:
    def __init__(self, groq_api_key: str, model_name: str, llama_guard_prompt: str = "", gpt_safeguard_prompt: str = ""):
        """
        Initialize the safety validation model.

        Args:
            groq_api_key (str): Groq API key for authentication.
            model_name (str): Model name used for safety validation (e.g., "llama-guard-3-8b").
            llama_guard_prompt (str): Prompt template for Llama Guard validation (use {role}, {user_query}, {generated_sql} placeholders).
            gpt_safeguard_prompt (str): Prompt template for GPT OSS Safeguard validation (same placeholders).
        """
        self.groq_api_key = groq_api_key
        self.model_name = model_name
        self.llama_guard_prompt = llama_guard_prompt
        self.gpt_safeguard_prompt = gpt_safeguard_prompt

        # Initialize the LLM
        self.llm = ChatGroq(
            groq_api_key=self.groq_api_key,
            model_name=self.model_name,
            streaming=False
        )

    def _select_prompt(self) -> str:
        """Selects the appropriate prompt template based on model name."""
        if self.model_name.lower() == "meta-llama/llama-guard-4-12b":
            return self.llama_guard_prompt
        return self.gpt_safeguard_prompt

    def _check_role_permissions(self, role: str, sql_query: str) -> tuple:
        """Pre-check role permissions against SQL operations."""
        sql_upper = sql_query.upper()
        
        # Define role-based permissions
        role_permissions = {
            "Admin": ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"],
            "Teacher": ["SELECT", "UPDATE"],  # Only on student-related tables
            "Data Entry": ["SELECT", "INSERT", "UPDATE"],  # No DELETE/structural changes
            "Viewer": ["SELECT"]  # Read-only access
        }
        
        # Check if role exists
        if role not in role_permissions:
            return False, f"Invalid role: {role}"
            
        allowed_operations = role_permissions[role]
        
        # Check SQL operation against allowed operations
        for op in ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"]:
            if op in sql_upper and op not in allowed_operations:
                return False, f"Operation {op} not allowed for role {role}"
                
        # Additional checks for specific roles
        if role == "Viewer" and "SELECT *" in sql_upper:
            return False, "Viewer role cannot use SELECT * queries"
            
        if role != "Admin":
            sensitive_tables = ["users", "admin", "credentials", "passwords", "config"]
            for table in sensitive_tables:
                if table.upper() in sql_upper:
                    return False, f"Access to table '{table}' not allowed for role {role}"
        
        return True, "Operation allowed for role"

    def validate_request(self, role: str, user_query: str, generated_sql: str = None) -> dict:
        """
        Validate the user's NL query and optionally the generated SQL.

        Args:
            role (str): Role of the user (Admin, Teacher, Data Entry, Viewer).
            user_query (str): The user's natural language request.
            generated_sql (str): The generated SQL query (optional for 2nd-stage validation).

        Returns:
            dict: {
                "status": "safe" | "unsafe" | "error",
                "reason": str (if unsafe)
            }
        """
        try:
            # First do a quick role-permission check
            if generated_sql:
                is_allowed, reason = self._check_role_permissions(role, generated_sql)
                if not is_allowed:
                    return {
                        "status": "unsafe",
                        "reason": reason
                    }
            
            # Then do the full LLM-based validation
            prompt_template = self._select_prompt()
            prompt_filled = prompt_template.format(
                role=role,
                user_query=user_query,
                generated_sql=generated_sql if generated_sql else "N/A"
            )

            messages = [
                ("system", prompt_filled),
                ("human", "Provide your safety assessment now.")
            ]

            response = self.llm.invoke(messages).content.strip().lower()

            # Determine outcome
            if "unsafe" in response or "invalid" in response:
                return {
                    "status": "unsafe",
                    "reason": response
                }
            return {"status": "safe", "reason": "Complies with safety policy."}

        except Exception as e:
            return {"status": "error", "reason": f"Validation failed: {str(e)}"}