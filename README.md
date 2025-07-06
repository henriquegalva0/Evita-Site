# Evita WebAPP

Web application for email and website analysis using AI.

## ⚠️ **IMPORTANT: Security Configuration**

Before using this application, you **MUST** configure environment variables to protect sensitive information.

### 1. Configure Environment Variables

Copy the `env.example` file to `.env` and configure your credentials:

```bash
cp env.example .env
```

Edit the `.env` file with your real credentials:

```env
# Redis Configuration
REDIS_URL=rediss://default:your_password_here@your-server.upstash.io:6379

# Flask Configuration
FLASK_SECRET_KEY=your_secret_key_here

# OpenAI API Configuration
OPENAI_API_KEY=your_api_key_here

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here

# Environment Configuration
ENV=development
FLASK_ENV=development
DEBUG=true
```

### 2. Sensitive Files

The following files contain sensitive information and **SHOULD NOT** be committed:

- `data/keys/` - Directory with API keys
- `.env` - Environment variables file
- `data/keys/credentials.json` - Google OAuth credentials

### 3. Installation

```bash
pip install -r requirements.txt
```

### 4. Execution

```bash
python app.py
```

## 🔒 **Security**

- ✅ Credentials moved to environment variables
- ✅ `.gitignore` file configured
- ✅ Production URLs protected
- ⚠️ **IMPORTANT**: Regenerate Redis credentials after deployment

## 📝 **Notes**

- The application uses Redis for server-side sessions
- Google OAuth integration for email access
- Website and email analysis using OpenAI GPT 