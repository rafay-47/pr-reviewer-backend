# AI AppSec PR Reviewer - Backend

FastAPI backend service for AI-powered security review of pull requests.

## 📋 Database Setup

Before running the backend, you need to set up the database schema in Supabase.

### Running Migrations

Navigate to your Supabase project's **SQL Editor** and run the migration files in order:

1. `migrations/001_initial_schema.sql` - Core tables (organizations, tokens, reviews, findings)
2. `migrations/002_seed_mock_org.sql` - Optional: seed mock organization for testing
3. `migrations/003_seed_api_token.sql` - Optional: seed test API token
4. `migrations/004_github_installations.sql` - GitHub workflow and OAuth tables
5. `migrations/005_security_hardening.sql` - Token usage tracking, audit logs, metadata

**Important**: Run migrations in order as each builds on the previous one.

### Migration 5: Security Hardening

The latest migration (`005_security_hardening.sql`) adds:
- **Token usage tracking** (`usage_count` column in `api_tokens`)
- **Token creation metadata** (`created_ip`, `created_user_agent` columns)
- **Comprehensive audit logging** (`audit_logs` table)
- **Helper function** (`log_audit_event`)

This migration is required for the security features implemented in the backend.

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- API key for Claude (Anthropic), OpenAI, Google Gemini, or Groq

### Installation

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the `backend/` directory:

```bash
# LLM Configuration
# Options: claude, openai, gemini, groq
LLM_PROVIDER=claude
LLM_API_KEY=your_api_key_here

# Optional: Specify model
# Claude: claude-sonnet-4-20250514, claude-3-haiku-20240307
# OpenAI: gpt-4o, gpt-4o-mini
# Gemini: gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash
# Groq: llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768
# LLM_MODEL=claude-sonnet-4-20250514

# Server Configuration
PORT=8000
HOST=0.0.0.0

# API Authentication (recommended for production)
API_AUTH_TOKEN=your_secure_token_here

# Logging
LOG_LEVEL=INFO
```

### Running the Server

```bash
# Development mode with auto-reload
uvicorn app.main:app --reload --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### API Documentation

Once running, access the API docs at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 📂 Project Structure

```
backend/
├── app/
│   ├── __init__.py         # Package initialization
│   ├── main.py             # FastAPI application & endpoints
│   ├── models.py           # Pydantic request/response models
│   ├── config.py           # Configuration management
│   ├── llm_client.py       # LLM API integration
│   ├── diff_parser.py      # Git diff parsing utilities
│   └── security_rules.py   # Security context & rules
├── tests/
│   ├── __init__.py
│   └── test_api.py         # API endpoint tests
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## 🔌 API Endpoints

### POST /review-pr

Analyze a pull request diff for security vulnerabilities.

**Request:**
```json
{
  "repo": "org/reponame",
  "pr_number": 123,
  "language": "nodejs",
  "framework": "express",
  "diff": "diff --git a/... (git diff output)"
}
```

**Response:**
```json
{
  "summary": "Found 1 high risk issue in this PR.",
  "findings": [
    {
      "title": "SQL Injection in user query",
      "risk": "HIGH",
      "file": "src/controllers/user.js",
      "line_range": "45-50",
      "description": "User input concatenated into SQL query",
      "impact": "Attacker can execute arbitrary SQL",
      "recommendation": "Use parameterized queries",
      "example_fix": "db.query('SELECT * FROM users WHERE id = ?', [id])",
      "owasp": "A03:2021 Injection",
      "cwe": "CWE-89"
    }
  ],
  "findings_markdown": "## 🔒 AI Security Review\n\n..."
}
```

### GET /health

Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "service": "AI AppSec PR Reviewer",
  "version": "0.1.0",
  "llm_provider": "claude",
  "llm_configured": true,
  "auth_enabled": true
}
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Run specific test file
pytest tests/test_api.py -v
```

## 🛠️ Development

### Code Formatting

```bash
# Format code
black app/ tests/

# Sort imports
isort app/ tests/

# Type checking
mypy app/
```

### Adding New Security Rules

1. Add vulnerability patterns to `security_rules.py`
2. Update the system prompt in `llm_client.py` if needed
3. Add test cases to `tests/test_api.py`

## 🐳 Docker (Optional)

Build and run with Docker:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t ai-appsec-reviewer .
docker run -p 8000:8000 -e LLM_API_KEY=your_key ai-appsec-reviewer
```

## 📊 Monitoring

### Health Checks

The `/health` endpoint returns:
- Service status (`healthy` or `degraded`)
- Configuration validation results
- LLM provider configuration status

### Logging

Logs are output in structured format. Configure level with `LOG_LEVEL` environment variable:
- `DEBUG`: Detailed debugging information
- `INFO`: General operational information (default)
- `WARNING`: Warning messages
- `ERROR`: Error messages only

## 🔐 Security

1. **API Authentication**: Set `API_AUTH_TOKEN` to require Bearer token authentication
2. **HTTPS**: Deploy behind a reverse proxy with TLS
3. **Input Validation**: All inputs are validated via Pydantic models
4. **Error Handling**: Errors don't expose sensitive information

## 📝 License

MIT License
