# Classify AI - School Data Management System (NiceGUI Version)

A modern web application for intelligent school data management using Natural Language to SQL (NL2SQL) technology. This is a complete port from Streamlit to NiceGUI with embedded FastAPI backend.

## 🎯 Overview

**Classify AI** is an intelligent platform that simplifies school data management by allowing users to query databases using natural English language instead of complex SQL syntax.

### Key Features

- **🔐 Role-Based Access Control (RBAC)** - 4 user roles with different permission levels
- **💬 Natural Language Queries** - Ask questions in plain English, AI converts to SQL
- **📊 Data Upload & Management** - Import Excel files with validation
- **🛡️ Dual-Layer Security** - NL intent validation + SQL safety checks
- **🗄️ Multi-Database Support** - Local SQLite + MySQL connectivity
- **⚡ FastAPI Backend** - Modern async API with proper error handling
- **🎨 NiceGUI Frontend** - Modern, responsive web interface

## 🏗️ Architecture

```
Classify AI (NiceGUI)
├── Frontend (NiceGUI UI)
│   ├── Login Page
│   ├── Home Page
│   ├── Upload Page
│   └── Chat Page
├── FastAPI Backend
│   ├── Authentication Routes
│   ├── Upload Routes
│   ├── Database Routes
│   └── Chat Routes
└── Backend Services
    ├── Database Helpers
    ├── Safety Validator
    └── LLM Integration (Groq)
```

## 📋 User Roles & Permissions

### Admin
- **Permissions**: upload, chat, view, delete, export
- **SQL**: All operations (SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER)
- **Access**: All tables and system objects

### Teacher
- **Permissions**: chat, view
- **SQL**: SELECT, UPDATE (with WHERE clauses)
- **Restrictions**: No deletions, no system tables

### Data Entry
- **Permissions**: upload, view, export
- **SQL**: SELECT (with LIMIT), INSERT, UPDATE
- **Restrictions**: No structural changes, single table ops only

### Viewer
- **Permissions**: chat only
- **SQL**: SELECT with LIMIT only
- **Restrictions**: Read-only, no aggregations

### Test Credentials

```
Admin:       admin / admin123
Teacher:     teacher / teacher123
Data Entry:  data_entry / data123
Viewer:      viewer / view123
```

## 🚀 Installation

### Prerequisites
- Python 3.9+
- pip or conda
- Groq API Key (from https://console.groq.com)

### Setup Steps

1. **Clone and navigate to project directory**
   ```bash
   cd classify-ai-nicegui
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your Groq API key:
   ```
   GROQ_API_KEY=your_actual_api_key_here
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

   The application will be available at `http://localhost:8000`

## 📁 Project Structure

```
.
├── main.py                 # Main NiceGUI + FastAPI application
├── database_helpers.py     # Database utility functions
├── safety_validator.py     # Security validation module
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variables template
└── school_data.db         # SQLite database (auto-created)
```

## 🔧 Configuration

### Database Configuration

#### Local SQLite (Default)
- No configuration needed
- Data stored in `school_data.db`
- Perfect for development and testing

#### MySQL Database
1. Update MySQL settings in the Chat page sidebar:
   - Host: `localhost` (or your server)
   - Username: `your_mysql_user`
   - Password: `your_password`
   - Database: `school_db`

Or set in `.env`:
```
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=password
MYSQL_DATABASE=school_db
```

### Groq API Configuration

1. Get your API key from https://console.groq.com
2. Add to `.env` file:
   ```
   GROQ_API_KEY=your_key_here
   ```

## 📖 Usage Guide

### 1. Login
- Navigate to `http://localhost:8000`
- Enter credentials (use test credentials above)
- Click "Login"

### 2. Home Page
- View your role and permissions
- See example queries
- Navigate to available features

### 3. Upload Data (Admin & Data Entry)
- Click "📊 Upload Data"
- Select an Excel file (.xlsx or .xls)
- Review data preview
- Check validation results
- Click "💾 Save to Database"

### 4. Chat with Data (All authenticated users)
- Click "💬 Chat with Data"
- Ask questions in natural English:
  - "Show me all students"
  - "How many students have GPA > 3.5?"
  - "List students by grade"
- View AI-generated summaries
- Optional: Toggle "🔧 Show Technical Details" to see SQL queries

## 🔒 Security Features

### Dual-Layer Validation

1. **Natural Language Intent Validation**
   - Detects prompt injection attempts
   - Checks for unauthorized action requests
   - Prevents policy bypass attempts

2. **SQL Query Validation**
   - Validates generated SQL syntax
   - Checks table access restrictions
   - Prevents unauthorized operations
   - Enforces role-based limits

3. **Role-Based Access Control**
   - Per-user permission checks
   - Operation type restrictions
   - Sensitive table protection

## 🛠️ Development

### Adding New Features

#### New Page
```python
@ui.page('/newpage')
def new_page():
    check_authenticated()
    # Your page code here
```

#### New API Endpoint
```python
@nicegui_app.get('/api/endpoint')
async def api_endpoint():
    # Your API code here
    return {"result": "data"}
```

### Running Tests
```bash
pytest tests/ -v
```

## 📊 Database Schema

The application creates a `students` table with the following structure:

| Column | Type | Notes |
|--------|------|-------|
| student_id | INTEGER | Primary Key (recommended) |
| id | INTEGER | Auto-increment (if no student_id) |
| name | TEXT | Student name |
| email | TEXT | Email address |
| grade | TEXT | Grade level |
| gpa | REAL | GPA value |
| ... | ... | Custom columns based on upload |

## 🤖 AI Models Used

- **Query Generation**: Llama 3.1 8B Instant (via Groq)
- **Safety Validation**: Llama Guard 4 (via Groq)
- **Result Summarization**: Llama 3.1 8B Instant (via Groq)

## 🐛 Troubleshooting

### Issue: API key not found
**Solution**: Ensure `.env` file is in the same directory as `main.py` and contains `GROQ_API_KEY`

### Issue: Database connection error
**Solution**: Check that `school_data.db` file is writable, or verify MySQL credentials

### Issue: File upload fails
**Solution**: Ensure Excel file is properly formatted with headers in the first row

### Issue: Chat response is slow
**Solution**: This is normal for first request. Groq caches models for faster subsequent requests.

## 📝 API Endpoints

### Authentication
- `POST /api/login` - User login

### File Operations
- `POST /api/upload-excel` - Upload Excel file
- `POST /api/save-to-db` - Save data to database
- `GET /api/preview-db` - Preview database contents
- `POST /api/clear-db` - Clear database

### Database Configuration
- `POST /api/set-mysql-config` - Configure MySQL
- `POST /api/set-local-db` - Switch to local database

### Chat Operations
- `POST /api/chat` - Send query to AI

## 🔄 Data Flow

```
User Input (NL Query)
    ↓
LangChain LLM (Generate SQL)
    ↓
Safety Validator (Check NL intent)
    ↓
Safety Validator (Check SQL)
    ↓
Execute Query (SQLite/MySQL)
    ↓
LLM Summarization (Generate Response)
    ↓
Display Results
```

## 📈 Performance

- Login: < 100ms
- File upload: < 2s (depending on file size)
- Query execution: 1-5s (including AI processing)
- Chat response: 2-10s (first request slower due to model loading)

## 🔐 Security Best Practices

1. **Change test credentials** before deploying to production
2. **Use strong passwords** for database accounts
3. **Enable HTTPS** when deploying to production
4. **Validate user inputs** on both client and server
5. **Regularly audit logs** for suspicious activity
6. **Keep dependencies updated** for security patches

## 📚 Documentation References

- [NiceGUI Documentation](https://nicegui.io)
- [FastAPI Documentation](https://fastapi.tiangolo.com)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org)
- [LangChain Documentation](https://python.langchain.com)
- [Groq API Documentation](https://console.groq.com/docs)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and development purposes.

## 🙋 Support

For issues and questions:
1. Check the Troubleshooting section
2. Review the documentation
3. Check existing issues
4. Create a new issue with detailed information

## 🎯 Future Enhancements

- [ ] User authentication with database storage
- [ ] Query history and favorites
- [ ] Data export to CSV/PDF
- [ ] Advanced analytics and visualizations
- [ ] Multi-language support
- [ ] Performance metrics dashboard
- [ ] API rate limiting
- [ ] Audit logging

## ✅ Changelog

### Version 1.0.0 (Current)
- Initial release
- Full port from Streamlit to NiceGUI
- FastAPI backend integration
- RBAC implementation
- Dual-layer security validation
- Multi-database support

---

**Made with ❤️ using NiceGUI, FastAPI, and LangChain**