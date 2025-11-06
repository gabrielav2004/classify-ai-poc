# 🎓 Classify AI - School Data Management System

Classify AI is an intelligent school data management platform that leverages **Natural Language to SQL (NL2SQL)** technology to simplify data retrieval and operations. Ask questions in plain English and get instant, accurate results from your school database.

## ✨ Features

### 📊 Smart Data Upload
- Import Excel files (.xlsx, .xls) with automatic validation
- Intelligent schema detection and data type mapping
- Secure storage in SQLite or MySQL databases
- Preview and verify data before saving
- Export cleaned data to CSV

### 💬 Conversational Data Retrieval
- Ask questions in natural language
- AI-powered SQL query generation using Groq LLM
- Instant query execution with clear, understandable summaries
- Chat history preservation across sessions
- Optional technical details view (SQL queries, schema)

### 🔒 Role-Based Access Control (RBAC)
- Secure login system with session management
- Four predefined user roles with granular permissions
- Permission-based feature access
- Logout functionality

### 🗄️ Flexible Database Support
- Local SQLite database (default: `school_data.db`)
- MySQL database connectivity
- Easy database switching

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Groq API key ([Get one here](https://console.groq.com))

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd classify-ai
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables**

Create a `.env` file in the project root:
```env
GROQ_API_KEY=your_groq_api_key_here
```

4. **Run the application**
```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

## 👥 User Roles & Permissions

Classify AI includes four predefined user roles for testing:

| Role | Username | Password | Permissions |
|------|----------|----------|-------------|
| **Admin** | `admin` | `admin123` | Full access: Upload, Chat, View, Delete, Export |
| **Teacher** | `teacher` | `teacher123` | Read-only: Chat, View |
| **Data Entry** | `data_entry` | `data123` | Limited: Upload, View, Export |
| **Viewer** | `viewer` | `view123` | Minimal: Chat only |

### Permission Details

- **Upload**: Import Excel files and save to database
- **Chat**: Ask natural language queries
- **View**: Preview database contents
- **Delete**: Clear all data from database
- **Export**: Download data as CSV

## 📖 How to Use

### 1. Login
- Navigate to the app URL
- Select a user role from the test credentials
- Enter username and password
- Click "Login"

### 2. Upload Data (Admin/Data Entry only)
- Click the "📊" button in the sidebar
- Upload an Excel file (.xlsx or .xls)
- Review the data preview and validation checks
- Click "Save to Database"
- Use database utilities to view or manage data

### 3. Chat with Database (Admin/Teacher/Viewer)
- Click the "💬" button in the sidebar
- Choose your database source (SQLite or MySQL)
- Type questions in plain English
- View AI-generated responses with data results

### Example Queries
```
- "Show me all students"
- "How many students are enrolled?"
- "List students by grade level"
- "Find students with GPA above 3.5"
- "What's the average age of students?"
- "Show me students in grade 10"
```

## 🗂️ Project Structure

```
classify-ai/
├── app.py                  # Main application file
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (create this)
├── school_data.db          # SQLite database (auto-generated)
└── README.md              # This file
```

## ⚙️ Configuration

### Database Configuration

**SQLite (Default)**
- Automatically uses `school_data.db` in the project directory
- No additional configuration needed

**MySQL**
- Select "🔗 MySQL Database" in the Chat page
- Enter connection details in the sidebar:
  - Host (e.g., `localhost`)
  - Username (e.g., `root`)
  - Password
  - Database name

### Environment Variables

Create a `.env` file with the following:

```env
GROQ_API_KEY=your_groq_api_key_here
```

## 🔧 Technical Details

### Technology Stack
- **Frontend**: Streamlit
- **AI/LLM**: Groq (Llama 3.1 8B Instant)
- **Database**: SQLite, MySQL
- **ORM**: SQLAlchemy
- **Data Processing**: Pandas, NumPy
- **Excel Support**: openpyxl, xlrd

### NL2SQL Pipeline
1. User inputs natural language query
2. Schema is retrieved from the database
3. Groq LLM generates SQL query from natural language + schema
4. SQL query is executed against the database
5. Results are summarized by LLM into natural language
6. User receives clear, understandable response

## 🛡️ Security Considerations

- Passwords are currently stored in plain text for testing purposes
- In production, implement proper password hashing (e.g., bcrypt)
- Use environment variables for all sensitive data
- Implement SQL injection prevention measures
- Add rate limiting for API calls
- Enable HTTPS in production

## 🐛 Troubleshooting

### Common Issues

**"Groq API Key not found"**
- Ensure `.env` file exists in the project root
- Verify `GROQ_API_KEY` is set correctly in `.env`
- Restart the Streamlit app after adding the key

**"Could not read Excel file"**
- Ensure file is in .xlsx or .xls format
- Check that the file is not corrupted
- Try re-saving the Excel file and uploading again

**"Database connection failed" (MySQL)**
- Verify MySQL server is running
- Check connection credentials
- Ensure the database exists
- Check firewall settings

**"No results found"**
- Verify data exists in the database
- Try rephrasing your query
- Check database contents using "View Database" button

## 📝 Excel File Requirements

For best results, your Excel files should:
- Have clear column headers in the first row
- Include recommended columns: `student_id`, `email`
- Use consistent data types in each column
- Avoid merged cells or complex formatting
- Be free of empty rows/columns

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Powered by [Groq](https://groq.com/)
- Uses [LangChain](https://langchain.com/) framework

## 📧 Support

For issues, questions, or feedback, please open an issue on the repository.

---

**Made with ❤️ for simplifying school data management**
