import streamlit as st
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from langchain_groq import ChatGroq
from langchain.sql_database import SQLDatabase
import json
from decimal import Decimal
from dotenv import load_dotenv
import pandas as pd
import sqlite3
from sqlite3 import Connection
import io
import numpy as np
import os

# Load environment variables
load_dotenv()

# Get Groq API key from environment
GROQ_API_KEY = os.getenv('GROQ_API_KEY')

# Page config
st.set_page_config(page_title="Classify AI - School Data Management", page_icon='🎓', layout="wide")

# Constants
LOCAL_DB = 'USE_LOCALDB'
MYSQL = 'USE_MYSQL'
DB_PATH = "school_data.db"
TABLE_NAME = "students"

# ==================== SESSION STATE INITIALIZATION ====================
# Initialize all session state variables
if 'page' not in st.session_state:
    st.session_state.page = "Home"

if 'uploaded_df' not in st.session_state:
    st.session_state.uploaded_df = None

if 'db_uri' not in st.session_state:
    st.session_state.db_uri = LOCAL_DB

if 'mysql_host' not in st.session_state:
    st.session_state.mysql_host = ''

if 'mysql_user' not in st.session_state:
    st.session_state.mysql_user = ''

if 'mysql_pass' not in st.session_state:
    st.session_state.mysql_pass = ''

if 'mysql_db' not in st.session_state:
    st.session_state.mysql_db = ''

if 'chat_messages' not in st.session_state:
    st.session_state.chat_messages = [{'role': 'assistant','content':'Hello! I\'m Classify AI. Ask me anything about your school data in plain English, and I\'ll help you retrieve the information you need.'}]

if 'db_preview_shown' not in st.session_state:
    st.session_state.db_preview_shown = False

if 'db_preview_data' not in st.session_state:
    st.session_state.db_preview_data = None

if 'show_details' not in st.session_state:
    st.session_state.show_details = False

# ==================== HELPER FUNCTIONS ====================

# SQLite Helper Functions
def get_conn(path: str = DB_PATH) -> Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    return conn

def create_table_if_not_exists(conn: Connection, sample_df: pd.DataFrame):
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
    try:
        return pd.read_sql_query(f'SELECT * FROM "{TABLE_NAME}" LIMIT {limit}', conn)
    except Exception:
        return pd.DataFrame()

def clear_table(conn: Connection):
    conn.execute(f'DELETE FROM "{TABLE_NAME}"')
    conn.commit()

def insert_dataframe(conn: Connection, df: pd.DataFrame):
    cur = conn.cursor()
    cols = list(df.columns)
    placeholders = ", ".join(["?"] * len(cols))
    cols_quoted = ", ".join([f'"{c}"' for c in cols])
    insert_sql = f'INSERT OR REPLACE INTO "{TABLE_NAME}" ({cols_quoted}) VALUES ({placeholders})'
    
    def _convert_value(v):
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

# Chat with DB Helper Functions
def langchain_db(db_url: str) -> SQLDatabase:
    engine = create_engine(db_url)
    return SQLDatabase(engine)

def infer_schema(langchain_db: SQLDatabase) -> str:
    return langchain_db.get_table_info()

def run_query(query: str, db_url: str):
    try:
        engine = create_engine(db_url)
        with engine.connect() as connection:
            result = connection.execute(text(query))
            rows = [
                {key: (float(value) if isinstance(value, Decimal) else value) for key, value in row._mapping.items()}
                for row in result
            ]
            return rows
    except SQLAlchemyError as e:
        return f"An error occurred: {e}"

def generate_sql_query(llm, user_query, schema):
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

# ==================== SIDEBAR NAVIGATION ====================
st.sidebar.title("🎓 Classify AI")
st.sidebar.markdown("*Easy School Data Management*")
st.sidebar.markdown("---")

# Use buttons for navigation with session state
col1, col2, col3 = st.sidebar.columns(3)
with col1:
    if st.button("🏠", use_container_width=True, help="Home"):
        st.session_state.page = "Home"
with col2:
    if st.button("📊", use_container_width=True, help="Upload Data"):
        st.session_state.page = "Upload Excel to SQLite"
with col3:
    if st.button("💬", use_container_width=True, help="Chat with Data"):
        st.session_state.page = "Chat with Database"

st.sidebar.markdown(f"**📍 {st.session_state.page}**")
st.sidebar.markdown("---")

page = st.session_state.page

# ==================== PAGE 1: HOME ====================
if page == "Home":
    st.title("🎓 Welcome to Classify AI")
    st.markdown("### *Your Intelligent School Data Management Assistant*")
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ## What is Classify AI?
        
        Classify AI is an intelligent platform designed to simplify school data management through **Natural Language to SQL (NL2SQL)** technology. 
        No more complex queries or technical jargon – just ask what you need in plain English!
        
        ### 🚀 Key Features
        
        **📊 Smart Data Upload**
        - Import Excel files with automatic validation
        - Intelligent schema detection
        - Secure data storage in SQLite
        - Preview and verify before saving
        
        **💬 Conversational Data Retrieval**
        - Ask questions in natural language
        - AI-powered SQL generation
        - Instant, accurate results
        - Clear, understandable summaries
        
        **🔒 Flexible Database Support**
        - Local SQLite database (built-in)
        - MySQL database connectivity
        - Secure credential management
        """)
    
    with col2:
        st.info("""
        ### 💡 Quick Start
        
        1️⃣ **Upload Data**  
        Import your Excel files
        
        2️⃣ **Ask Questions**  
        Use natural language
        
        3️⃣ **Get Insights**  
        Receive instant answers
        """)
        
        st.success("""
        ### 📝 Example Queries
        
        - "Show me all students"
        - "How many students are there?"
        - "List students by grade"
        - "Find students with GPA > 3.5"
        """)
    
    st.markdown("---")
    st.markdown("""
    ### 🎯 Perfect For
    - School Administrators
    - Teachers
    - Data Analysts
    - Anyone managing student information
    """)
    
    st.markdown("---")
    st.info("👆 **Get started by clicking the navigation buttons above!**")

# ==================== PAGE 2: UPLOAD EXCEL ====================
elif page == "Upload Excel to SQLite":
    st.title("📊 Upload School Data")
    st.markdown("*Import your Excel files and manage your school database*")
    st.markdown("---")
    
    uploaded_file = st.file_uploader("Choose an Excel file (.xlsx, .xls)", type=["xlsx","xls"], key="excel_uploader")
    
    if uploaded_file is not None:
        try:
            # Store in session state to persist across reruns
            if st.session_state.uploaded_df is None or uploaded_file.name != getattr(st.session_state, 'last_uploaded_file', ''):
                st.session_state.uploaded_df = pd.read_excel(uploaded_file)
                st.session_state.last_uploaded_file = uploaded_file.name
            
            df = st.session_state.uploaded_df
        except Exception as e:
            st.error(f"❌ Could not read the Excel file: {e}")
            st.stop()
        
        st.success(f"✅ File loaded successfully: **{uploaded_file.name}** ({len(df)} rows, {len(df.columns)} columns)")
        
        with st.expander("📋 Preview Data (first 50 rows)", expanded=True):
            st.dataframe(df.head(50), use_container_width=True)
        
        with st.expander("🔍 Data Validation", expanded=True):
            problems = []
            if "student_id" not in df.columns:
                problems.append("⚠️ Missing recommended column: **student_id**")
            if "email" not in df.columns:
                problems.append("⚠️ Missing recommended column: **email**")
            if df.shape[0] == 0:
                problems.append("❌ Uploaded file has 0 rows")
            
            if problems:
                for p in problems:
                    st.warning(p)
            else:
                st.success("✅ All validation checks passed!")
            
            st.write("**Column Information:**")
            col_types = pd.DataFrame({"Column Name": df.columns, "Data Type": df.dtypes.astype(str)})
            st.table(col_types)
        
        st.markdown("---")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("💾 Save to Database", type="primary", use_container_width=True):
                with st.spinner("Saving data..."):
                    conn = get_conn()
                    create_table_if_not_exists(conn, df)
                    insert_dataframe(conn, df)
                    conn.close()
                    st.session_state.db_preview_shown = False
                st.success(f"✅ Successfully saved **{len(df)} rows** to database!")
                st.balloons()
        
        st.markdown("---")
        st.subheader("🛠️ Database Utilities")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("👁️ View Database", use_container_width=True):
                conn = get_conn()
                st.session_state.db_preview_data = get_all_rows(conn)
                st.session_state.db_preview_shown = True
                conn.close()
        
        with col2:
            if st.button("🗑️ Clear Database", use_container_width=True):
                st.session_state.show_clear_confirm = True
        
        with col3:
            buffer = io.BytesIO()
            df.to_csv(buffer, index=False)
            buffer.seek(0)
            st.download_button("⬇️ Download CSV", data=buffer, file_name="school_data_export.csv", 
                             mime="text/csv", use_container_width=True)
        
        # Show DB preview if flag is set
        if st.session_state.db_preview_shown and st.session_state.db_preview_data is not None:
            st.markdown("---")
            if st.session_state.db_preview_data.empty:
                st.info("📭 Database is currently empty.")
            else:
                st.success(f"📊 Database contains **{len(st.session_state.db_preview_data)} rows**")
                st.dataframe(st.session_state.db_preview_data, use_container_width=True)
        
        # Clear confirmation
        if getattr(st.session_state, 'show_clear_confirm', False):
            st.markdown("---")
            st.warning("⚠️ **Warning: This action cannot be undone!**")
            if st.checkbox("I understand - delete all rows from the students table"):
                if st.button("🗑️ Confirm Deletion", type="primary"):
                    conn = get_conn()
                    clear_table(conn)
                    conn.close()
                    st.success("✅ All rows have been deleted from the database.")
                    st.session_state.show_clear_confirm = False
                    st.session_state.db_preview_shown = False
                    st.rerun()
    else:
        st.info("📤 **Upload an Excel file to get started**")
        st.markdown("""
        ### 📋 Requirements:
        - File format: `.xlsx` or `.xls`
        - Recommended columns: `student_id`, `email`
        - Ensure data is clean and properly formatted
        """)

# ==================== PAGE 3: CHAT WITH DATABASE ====================
elif page == "Chat with Database":
    st.title('💬 Chat with Your Data')
    st.markdown("*Ask questions in plain English - Classify AI will handle the rest*")
    st.markdown("---")
    
    # Database selection in sidebar
    st.sidebar.subheader("⚙️ Configuration")
    radio_opt = ['📁 Local Database (school_data.db)', '🔗 MySQL Database']
    selected_opt = st.sidebar.radio(label='Database Source', options=radio_opt, key="db_selection")
    
    if radio_opt.index(selected_opt) == 1:
        st.session_state.db_uri = MYSQL
        st.sidebar.markdown("**MySQL Connection:**")
        st.session_state.mysql_host = st.sidebar.text_input('Host', value=st.session_state.mysql_host, key="mysql_host_input", placeholder="localhost")
        st.session_state.mysql_user = st.sidebar.text_input('Username', value=st.session_state.mysql_user, key="mysql_user_input", placeholder="root")
        st.session_state.mysql_pass = st.sidebar.text_input('Password', value=st.session_state.mysql_pass, type='password', key="mysql_pass_input")
        st.session_state.mysql_db = st.sidebar.text_input('Database', value=st.session_state.mysql_db, key="mysql_db_input", placeholder="school_db")
    else:
        st.session_state.db_uri = LOCAL_DB
    
    st.sidebar.markdown("---")
    
    # Show technical details toggle
    st.session_state.show_details = st.sidebar.checkbox("🔧 Show Technical Details", value=st.session_state.show_details, key="show_details_toggle")
    
    if st.sidebar.button('🗑️ Clear Chat', use_container_width=True):
        st.session_state.chat_messages = [{'role': 'assistant','content':'Hello! I\'m Classify AI. Ask me anything about your school data in plain English, and I\'ll help you retrieve the information you need.'}]
        st.rerun()
    
    # Check if API key is available
    if not GROQ_API_KEY:
        st.error('❌ **Groq API Key not found in environment variables**')
        st.info("""
        ### Configuration Error:
        Please add `GROQ_API_KEY` to your `.env` file
        
        Example:
        ```
        GROQ_API_KEY=your_api_key_here
        ```
        """)
        st.stop()
    
    # Set up db_url
    if st.session_state.db_uri == LOCAL_DB:
        dbfilepath = (Path(__file__).parent / 'school_data.db').absolute()
        db_url = f'sqlite:///{dbfilepath}'
        st.success("✅ Connected to local database")
    elif st.session_state.db_uri == MYSQL:
        if not (st.session_state.mysql_host and st.session_state.mysql_user and st.session_state.mysql_pass and st.session_state.mysql_db):
            st.error('⚠️ **Please provide complete MySQL database credentials in the sidebar**')
            st.stop()
        db_url = f'mysql+mysqlconnector://{st.session_state.mysql_user}:{st.session_state.mysql_pass}@{st.session_state.mysql_host}/{st.session_state.mysql_db}'
        st.success(f"✅ Connected to MySQL: {st.session_state.mysql_db}")
    
    # Define the LLM
    try:
        llm = ChatGroq(groq_api_key=GROQ_API_KEY, model_name='llama-3.1-8b-instant', streaming=True)
    except Exception as e:
        st.error(f"❌ Failed to initialize Groq AI: {e}")
        st.stop()
    
    # Display chat messages
    for msg in st.session_state.chat_messages:
        with st.chat_message(msg['role']):
            st.write(msg['content'])
            # Show dataframe if it exists in the message
            if 'dataframe' in msg:
                st.dataframe(msg['dataframe'], use_container_width=True)
    
    user_query = st.chat_input(placeholder='e.g., "Show me all students with GPA above 3.5"', key="chat_input")
    
    if user_query:
        st.session_state.chat_messages.append({'role':'user','content':user_query})
        st.chat_message('user').write(user_query)
        
        with st.chat_message('assistant'):
            with st.spinner('🤔 Processing your query...'):
                try:
                    # Step 1: Get schema
                    langchain_db_instance = langchain_db(db_url)
                    schema = infer_schema(langchain_db_instance)
                    
                    # Step 2: Generate SQL query using LLM
                    sql_query = generate_sql_query(llm, user_query, schema)
                    
                    # Step 3: Execute SQL query
                    result = run_query(sql_query, db_url)
                    
                    # Show technical details if enabled
                    if st.session_state.show_details:
                        with st.expander("🔧 Technical Details"):
                            st.code(f"Generated SQL:\n{sql_query}", language="sql")
                            st.write(f"**Schema:**\n{schema}")
                    
                    if isinstance(result, str):
                        # Error occurred
                        error_msg = f"I encountered an issue while processing your query: {result}"
                        st.error(error_msg)
                        st.session_state.chat_messages.append({'role':'assistant','content':error_msg})
                    elif result:
                        # Success with results
                        summary = summarize_result(llm, user_query, sql_query, result)
                        st.write(summary)
                        
                        # Show results table
                        if len(result) > 0:
                            with st.expander(f"📊 View Data ({len(result)} rows)", expanded=len(result) <= 10):
                                result_df = pd.DataFrame(result)
                                st.dataframe(result_df, use_container_width=True)
                        
                        st.session_state.chat_messages.append({
                            'role':'assistant',
                            'content':summary,
                            'dataframe': pd.DataFrame(result[:10]) if len(result) > 0 else None
                        })
                    else:
                        # No results found
                        no_result_msg = "I couldn't find any data matching your query. Please try rephrasing or check if the data exists in the database."
                        st.info(no_result_msg)
                        st.session_state.chat_messages.append({'role':'assistant','content':no_result_msg})
                
                except Exception as e:
                    error_msg = f"An unexpected error occurred: {str(e)}"
                    st.error(error_msg)
                    st.session_state.chat_messages.append({'role':'assistant','content':error_msg})