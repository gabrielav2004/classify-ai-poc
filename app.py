"""
Classify AI - NiceGUI Version
School Data Management System with Natural Language to SQL

Installation:
pip install nicegui pandas sqlalchemy langchain-groq python-dotenv openpyxl

Usage:
python app_nicegui.py
"""

from nicegui import ui, app
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from langchain_groq import ChatGroq
from langchain.sql_database import SQLDatabase
import pandas as pd
import sqlite3
import io
import os
from dotenv import load_dotenv
from safety_validator import SafetyValidator

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv('GROQ_API_KEY')

# Constants
DB_PATH = "school_data.db"
TABLE_NAME = "students"

# RBAC Configuration
USERS = {
    "admin": {"password": "admin123", "role": "Admin", "permissions": ["upload", "chat", "view", "delete", "export"]},
    "teacher": {"password": "teacher123", "role": "Teacher", "permissions": ["chat", "view"]},
    "data_entry": {"password": "data123", "role": "Data Entry", "permissions": ["upload", "view", "export"]},
    "viewer": {"password": "view123", "role": "Viewer", "permissions": ["chat"]}
}

# Safety prompts (same as original)
LLAMA_GUARD_PROMPT = """..."""  # Your original prompt
SAFEGUARD_PROMPT = """..."""     # Your original prompt
SAFETY_MODEL_NAME = "meta-llama/llama-guard-4-12b"

# Initialize safety validator
safety_validator = SafetyValidator(
    groq_api_key=GROQ_API_KEY,
    model_name=SAFETY_MODEL_NAME,
    llama_guard_prompt=LLAMA_GUARD_PROMPT,
    gpt_safeguard_prompt=SAFEGUARD_PROMPT
)

# Database helper functions
def get_conn(path: str = DB_PATH):
    return sqlite3.connect(path, check_same_thread=False)

def create_table_if_not_exists(conn, sample_df: pd.DataFrame):
    dtype_map = {'int64': 'INTEGER', 'float64': 'REAL', 'object': 'TEXT', 'bool': 'INTEGER'}
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

def insert_dataframe(conn, df: pd.DataFrame):
    df.to_sql(TABLE_NAME, conn, if_exists='replace', index=False)
    conn.commit()

def get_all_rows(conn, limit: int = 1000):
    try:
        return pd.read_sql_query(f'SELECT * FROM "{TABLE_NAME}" LIMIT {limit}', conn)
    except Exception:
        return pd.DataFrame()

def clear_table(conn):
    conn.execute(f'DELETE FROM "{TABLE_NAME}"')
    conn.commit()

# Query functions
def langchain_db(db_url: str):
    engine = create_engine(db_url)
    return SQLDatabase(engine)

def run_query(query: str, db_url: str):
    try:
        engine = create_engine(db_url)
        with engine.connect() as connection:
            result = connection.execute(text(query))
            is_modification = any(keyword in query.upper() for keyword in ['INSERT', 'UPDATE', 'DELETE'])
            if is_modification:
                affected_rows = result.rowcount
                connection.commit()
                return f"Query executed successfully. {affected_rows} rows affected."
            else:
                rows = [dict(row._mapping) for row in result]
                return rows
    except SQLAlchemyError as e:
        return f"An error occurred: {e}"

def generate_sql_query(llm, user_query, schema):
    system_message = (
        f"Generate a query suitable for both MySQL and SQLite for: {user_query}. "
        f"Only provide the query in correct syntax with no extra content. "
        f"Schema: {schema}"
    )
    messages = [("system", system_message), ("human", user_query)]
    ai_msg = llm.invoke(messages)
    return ai_msg.content.strip()

def summarize_result(llm, user_query, sql_query, result):
    if not result:
        return "No results found for your query."
    preview = result[:10] if isinstance(result, list) else str(result)
    summary_prompt = (
        f"User asked: '{user_query}'. SQL run: {sql_query}. "
        f"Result preview: {preview}. Provide a clear summary."
    )
    messages = [("system", summary_prompt), ("human", "Summarize the result.")]
    ai_msg = llm.invoke(messages)
    return ai_msg.content.strip()


# =============================================================================
# NICEGUI APPLICATION
# =============================================================================

class ClassifyAI:
    def __init__(self):
        self.current_user = None
        self.uploaded_df = None
        self.chat_messages = []
        self.db_type = 'sqlite'
        self.mysql_config = {'host': '', 'user': '', 'password': '', 'database': ''}
        
    def check_permission(self, permission):
        if not self.current_user:
            return False
        return permission in self.current_user['permissions']
    
    def logout(self):
        self.current_user = None
        ui.navigate.to('/')
        ui.notify('Logged out successfully', type='positive')


# Global instance
classify_ai = ClassifyAI()


# =============================================================================
# LOGIN PAGE
# =============================================================================

@ui.page('/')
def login_page():
    if classify_ai.current_user:
        ui.navigate.to('/home')
        return
    
    with ui.column().classes('absolute-center items-center'):
        ui.label('🎓 Classify AI').classes('text-4xl font-bold text-primary')
        ui.label('School Data Management System').classes('text-xl text-gray-600 mb-8')
        
        with ui.card().classes('w-96 p-6'):
            ui.label('Login').classes('text-2xl font-bold mb-4')
            
            username = ui.input('Username', placeholder='Enter username').classes('w-full')
            password = ui.input('Password', placeholder='Enter password', password=True).classes('w-full')
            
            def do_login():
                if username.value in USERS and USERS[username.value]['password'] == password.value:
                    classify_ai.current_user = {
                        'username': username.value,
                        'role': USERS[username.value]['role'],
                        'permissions': USERS[username.value]['permissions']
                    }
                    ui.notify(f'Welcome, {classify_ai.current_user["role"]}!', type='positive')
                    ui.navigate.to('/home')
                else:
                    ui.notify('Invalid credentials', type='negative')
            
            ui.button('Login', on_click=do_login).classes('w-full').props('color=primary')
        
        # Test credentials info
        with ui.expansion('Test Credentials', icon='info').classes('w-96 mt-4'):
            ui.markdown('''
            **Admin**: admin / admin123  
            **Teacher**: teacher / teacher123  
            **Data Entry**: data_entry / data123  
            **Viewer**: viewer / view123
            ''')


# =============================================================================
# HOME PAGE
# =============================================================================

@ui.page('/home')
def home_page():
    if not classify_ai.current_user:
        ui.navigate.to('/')
        return
    
    def create_menu():
        with ui.header().classes('items-center justify-between'):
            ui.label('🎓 Classify AI').classes('text-xl font-bold')
            with ui.row():
                ui.label(f"👤 {classify_ai.current_user['username']} ({classify_ai.current_user['role']})").classes('mr-4')
                ui.button('Logout', on_click=classify_ai.logout, icon='logout').props('flat')
    
    with ui.column().classes('w-full'):
        create_menu()
        
        with ui.tabs().classes('w-full') as tabs:
            home_tab = ui.tab('Home', icon='home')
            if classify_ai.check_permission('upload'):
                upload_tab = ui.tab('Upload Data', icon='upload')
            if classify_ai.check_permission('chat'):
                chat_tab = ui.tab('Chat', icon='chat')
        
        with ui.tab_panels(tabs, value=home_tab).classes('w-full'):
            # Home Tab
            with ui.tab_panel(home_tab):
                with ui.column().classes('p-8'):
                    ui.label('Welcome to Classify AI').classes('text-3xl font-bold mb-4')
                    ui.markdown('''
                    ### Your Intelligent School Data Management Assistant
                    
                    **What is Classify AI?**
                    
                    An intelligent platform that simplifies school data management through Natural Language to SQL (NL2SQL) technology.
                    
                    **Key Features:**
                    - 📊 Smart Data Upload
                    - 💬 Conversational Data Retrieval
                    - 🔒 Role-Based Access Control
                    - 🗄️ Flexible Database Support
                    ''')
                    
                    with ui.card().classes('p-4'):
                        ui.label(f'Your Role: {classify_ai.current_user["role"]}').classes('text-lg font-bold')
                        ui.label('Permissions:').classes('mt-2')
                        for perm in classify_ai.current_user['permissions']:
                            ui.label(f'✅ {perm.capitalize()}')
            
            # Upload Tab
            if classify_ai.check_permission('upload'):
                with ui.tab_panel(upload_tab):
                    upload_data_panel()
            
            # Chat Tab
            if classify_ai.check_permission('chat'):
                with ui.tab_panel(chat_tab):
                    chat_panel()


# =============================================================================
# UPLOAD DATA PANEL
# =============================================================================

def upload_data_panel():
    with ui.column().classes('w-full p-4'):
        ui.label('📊 Upload School Data').classes('text-2xl font-bold mb-4')
        
        upload_result = ui.label()
        
        async def handle_upload(e):
            content = e.content.read()
            try:
                classify_ai.uploaded_df = pd.read_excel(io.BytesIO(content))
                upload_result.text = f'✅ File loaded: {len(classify_ai.uploaded_df)} rows, {len(classify_ai.uploaded_df.columns)} columns'
                preview_table.visible = True
                preview_table.set_columns([{'name': col, 'label': col, 'field': col} for col in classify_ai.uploaded_df.columns])
                preview_table.set_rows(classify_ai.uploaded_df.head(50).to_dict('records'))
                save_btn.visible = True
            except Exception as ex:
                ui.notify(f'Error reading file: {ex}', type='negative')
        
        ui.upload(label='Upload Excel File', on_upload=handle_upload, auto_upload=True).props('accept=".xlsx,.xls"').classes('mb-4')
        
        preview_table = ui.table(columns=[], rows=[]).classes('w-full')
        preview_table.visible = False
        
        def save_to_db():
            if classify_ai.uploaded_df is not None:
                conn = get_conn()
                create_table_if_not_exists(conn, classify_ai.uploaded_df)
                insert_dataframe(conn, classify_ai.uploaded_df)
                conn.close()
                ui.notify(f'✅ Saved {len(classify_ai.uploaded_df)} rows to database!', type='positive')
        
        save_btn = ui.button('💾 Save to Database', on_click=save_to_db, icon='save').props('color=primary')
        save_btn.visible = False
        
        # Database utilities
        ui.separator().classes('my-4')
        ui.label('Database Utilities').classes('text-xl font-bold mb-2')
        
        with ui.row():
            if classify_ai.check_permission('view'):
                def view_db():
                    conn = get_conn()
                    df = get_all_rows(conn)
                    conn.close()
                    if not df.empty:
                        db_table.set_columns([{'name': col, 'label': col, 'field': col} for col in df.columns])
                        db_table.set_rows(df.to_dict('records'))
                        db_table.visible = True
                        ui.notify(f'📊 Database: {len(df)} rows', type='info')
                    else:
                        ui.notify('Database is empty', type='warning')
                
                ui.button('👁️ View Database', on_click=view_db, icon='visibility')
            
            if classify_ai.check_permission('delete'):
                def clear_db():
                    conn = get_conn()
                    clear_table(conn)
                    conn.close()
                    ui.notify('🗑️ Database cleared!', type='positive')
                
                ui.button('🗑️ Clear Database', on_click=clear_db, icon='delete').props('color=negative')
        
        db_table = ui.table(columns=[], rows=[]).classes('w-full mt-4')
        db_table.visible = False


# =============================================================================
# CHAT PANEL
# =============================================================================

def chat_panel():
    with ui.column().classes('w-full p-4'):
        ui.label('💬 Chat with Your Data').classes('text-2xl font-bold mb-4')
        
        # Database selection
        with ui.card().classes('p-4 mb-4'):
            ui.label('Database Configuration').classes('font-bold mb-2')
            db_select = ui.select(
                ['SQLite (Local)', 'MySQL'],
                value='SQLite (Local)',
                label='Database Type'
            ).classes('w-64')
            
            mysql_inputs = ui.column().classes('mt-2')
            mysql_inputs.visible = False
            
            def on_db_change():
                mysql_inputs.visible = db_select.value == 'MySQL'
            
            db_select.on('update:model-value', on_db_change)
            
            with mysql_inputs:
                mysql_host = ui.input('Host', placeholder='localhost').classes('w-full')
                mysql_user = ui.input('Username', placeholder='root').classes('w-full')
                mysql_pass = ui.input('Password', password=True).classes('w-full')
                mysql_db = ui.input('Database', placeholder='school_db').classes('w-full')
        
        # Chat messages
        chat_container = ui.column().classes('w-full border rounded p-4 mb-4').style('height: 400px; overflow-y: auto')
        
        # Add initial message
        if not classify_ai.chat_messages:
            classify_ai.chat_messages.append({
                'role': 'assistant',
                'content': "Hello! I'm Classify AI. Ask me anything about your school data in plain English."
            })
        
        def render_messages():
            chat_container.clear()
            with chat_container:
                for msg in classify_ai.chat_messages:
                    with ui.chat_message(text=msg['content'], name=msg['role'].capitalize(), avatar=f'https://robohash.org/{msg["role"]}'):
                        if 'dataframe' in msg and msg['dataframe'] is not None:
                            ui.table(
                                columns=[{'name': col, 'label': col, 'field': col} for col in msg['dataframe'].columns],
                                rows=msg['dataframe'].to_dict('records')
                            )
        
        render_messages()
        
        # Chat input
        query_input = ui.input('Ask a question...', placeholder='e.g., Show me all students with GPA above 3.5').classes('w-full').on('keydown.enter', lambda: process_query())
        
        ui.button('Send', on_click=lambda: process_query(), icon='send').props('color=primary')
        
        def process_query():
            user_query = query_input.value
            if not user_query:
                return
            
            # Add user message
            classify_ai.chat_messages.append({'role': 'user', 'content': user_query})
            query_input.value = ''
            render_messages()
            
            # Get DB URL
            if db_select.value == 'SQLite (Local)':
                dbfilepath = (Path(__file__).parent / DB_PATH).absolute()
                db_url = f'sqlite:///{dbfilepath}'
            else:
                if not all([mysql_host.value, mysql_user.value, mysql_pass.value, mysql_db.value]):
                    ui.notify('Please provide complete MySQL credentials', type='negative')
                    return
                db_url = f'mysql+mysqlconnector://{mysql_user.value}:{mysql_pass.value}@{mysql_host.value}/{mysql_db.value}'
            
            try:
                # Initialize LLM
                llm = ChatGroq(groq_api_key=GROQ_API_KEY, model_name='llama-3.1-8b-instant', streaming=True)
                
                # Get schema
                db = langchain_db(db_url)
                schema = db.get_table_info()
                
                # Generate SQL
                sql_query = generate_sql_query(llm, user_query, schema)
                
                # Validate safety
                user_role = classify_ai.current_user['role']
                validation_result = safety_validator.validate_request(
                    role=user_role,
                    user_query=user_query,
                    generated_sql=sql_query
                )
                
                if validation_result['status'] != 'safe':
                    response = f"⚠️ Safety check failed: {validation_result['reason']}"
                    classify_ai.chat_messages.append({'role': 'assistant', 'content': response})
                    render_messages()
                    return
                
                # Execute query
                result = run_query(sql_query, db_url)
                
                # Generate summary
                is_modification = any(keyword in sql_query.upper() for keyword in ['INSERT', 'UPDATE', 'DELETE'])
                
                if is_modification:
                    summary = f"✅ Operation completed successfully. {result}"
                elif isinstance(result, str) and "error" in result.lower():
                    summary = f"❌ Query failed: {result}"
                else:
                    summary = summarize_result(llm, user_query, sql_query, result)
                
                # Add response
                response_msg = {'role': 'assistant', 'content': summary}
                if isinstance(result, list) and len(result) > 0:
                    response_msg['dataframe'] = pd.DataFrame(result[:10])
                
                classify_ai.chat_messages.append(response_msg)
                render_messages()
                
            except Exception as e:
                error_msg = f"❌ Error: {str(e)}"
                classify_ai.chat_messages.append({'role': 'assistant', 'content': error_msg})
                render_messages()


# =============================================================================
# RUN APPLICATION
# =============================================================================

if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title='Classify AI - School Data Management',
        port=8080,
        reload=True,
        show=True
    )