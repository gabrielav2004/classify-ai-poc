"""
database_helpers.py
Database utility functions for Classify AI
"""

from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from langchain_groq import ChatGroq
from langchain_community.utilities import SQLDatabase
from decimal import Decimal
import pandas as pd
import sqlite3
from sqlite3 import Connection
import numpy as np

# ==================== CONSTANTS ====================
DB_PATH = "school_data.db"
TABLE_NAME = "students"

# ==================== SQLITE HELPER FUNCTIONS ====================
def get_conn(path: str = DB_PATH) -> Connection:
    """Get SQLite database connection"""
    conn = sqlite3.connect(path, check_same_thread=False)
    return conn

def create_table_if_not_exists(conn: Connection, sample_df: pd.DataFrame):
    """Create table if it doesn't exist based on dataframe schema"""
    dtype_map = {
        'int64': 'INTEGER',
        'float64': 'REAL',
        'object': 'TEXT',
        'bool': 'INTEGER'
    }
    cols = []
    has_student_id = False
    for col, dtype in sample_df.dtypes.items():
        sql_type = dtype_map.get(str(dtype), 'TEXT')
        if col.lower() == "student_id":
            cols.append(f'"{col}" {sql_type} PRIMARY KEY')
            has_student_id = True
        else:
            cols.append(f'"{col}" {sql_type}')
    if not has_student_id:
        cols.insert(0, '"id" INTEGER PRIMARY KEY AUTOINCREMENT')
    cols_sql = ", ".join(cols)
    create_sql = f'CREATE TABLE IF NOT EXISTS "{TABLE_NAME}" ({cols_sql});'
    conn.execute(create_sql)
    conn.commit()

def get_all_rows(conn: Connection, limit: int = 1000) -> pd.DataFrame:
    """Get all rows from the table with optional limit"""
    try:
        return pd.read_sql_query(f'SELECT * FROM "{TABLE_NAME}" LIMIT {limit}', conn)
    except Exception:
        return pd.DataFrame()

def clear_table(conn: Connection):
    """Clear all rows from the table"""
    conn.execute(f'DELETE FROM "{TABLE_NAME}"')
    conn.commit()

def insert_dataframe(conn: Connection, df: pd.DataFrame):
    """Insert dataframe into database table"""
    cur = conn.cursor()
    cols = list(df.columns)
    placeholders = ", ".join(["?"] * len(cols))
    cols_quoted = ", ".join([f'"{c}"' for c in cols])
    insert_sql = f'INSERT OR REPLACE INTO "{TABLE_NAME}" ({cols_quoted}) VALUES ({placeholders})'
    
    def _convert_value(v):
        """Convert various data types to SQLite compatible types"""
        try:
            if pd.isna(v):
                return None
        except Exception:
            pass
        if isinstance(v, pd.Timestamp):
            return v.to_pydatetime()
        if isinstance(v, np.datetime64):
            try:
                return pd.to_datetime(v).to_pydatetime()
            except Exception:
                return str(v)
        if isinstance(v, np.generic):
            return v.item()
        return v
    
    values = []
    for row in df.itertuples(index=False, name=None):
        values.append(tuple(_convert_value(v) for v in row))
    cur.executemany(insert_sql, values)
    conn.commit()

# ==================== LANGCHAIN DATABASE FUNCTIONS ====================
def langchain_db(db_url: str) -> SQLDatabase:
    """Create SQLDatabase instance from URL"""
    engine = create_engine(db_url)
    return SQLDatabase(engine)

def infer_schema(langchain_db: SQLDatabase) -> str:
    """Get database schema information"""
    return langchain_db.get_table_info()

def run_query(query: str, db_url: str):
    """Execute SQL query and return results"""
    try:
        engine = create_engine(db_url)
        with engine.connect() as connection:
            result = connection.execute(text(query))
            
            # Check if it's a modification query
            is_modification = any(keyword in query.upper() for keyword in ['INSERT', 'UPDATE', 'DELETE'])
            
            if is_modification:
                # For modification queries, return rowcount
                affected_rows = result.rowcount
                connection.commit()  # Ensure changes are committed
                return f"Query executed successfully. {affected_rows} rows affected."
            else:
                # For SELECT queries, return results as before
                rows = [
                    {key: (float(value) if isinstance(value, Decimal) else value) for key, value in row._mapping.items()}
                    for row in result
                ]
                return rows
    except SQLAlchemyError as e:
        return f"An error occurred: {e}"

def generate_sql_query(llm, user_query, schema):
    """Generate SQL query from natural language using LLM"""
    system_message = (
        f"Generate a query suitable for both MySQL and SQLite for the given Natural language request: {user_query}, "
        f"only query should be given in correct syntax with no extra content. Imagine you are entering this query in a SQL client, "
        f"so no extra content should be given, especially no code blocks, just the query in correct syntax and in plain text. "
        f"Don't forget to add a semicolon at the end of the query. Read the schema carefully and generate the query. "
        f"Please use the table names and column names as they are in the schema. The schema is: {schema}"
    )
    messages = [
        ("system", system_message),
        ("human", user_query)
    ]
    ai_msg = llm.invoke(messages)
    return ai_msg.content.strip()

def summarize_result(llm, user_query, sql_query, result):
    """Generate natural language summary of query results"""
    if not result:
        return "No results found for your query."
    preview = result[:10]
    summary_prompt = (
        f"You are Classify AI, a helpful assistant for school data management. The user asked: '{user_query}'. "
        f"The following SQL was run: {sql_query}. "
        f"Here are the first rows of the result: {preview}. "
        f"Provide a clear, concise summary of the results in natural language that a school administrator would understand. "
        f"Focus on the key findings and present the information in a friendly, professional manner."
    )
    messages = [
        ("system", summary_prompt),
        ("human", "Summarize the result.")
    ]
    ai_msg = llm.invoke(messages)
    return ai_msg.content.strip()