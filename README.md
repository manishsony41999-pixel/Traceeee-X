# TRACE-X

**AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**

A comprehensive cybersecurity platform for analyzing suspicious emails, detecting threats, and conducting forensic investigations. Built for the Smart India Hackathon 2024.

---

## 🎯 Overview

TRACE-X is a production-ready email security analysis platform that combines:

- **Email Parsing & Header Analysis** - RFC 822/MIME parsing, routing path reconstruction
- **Authentication Analysis** - SPF, DKIM, DMARC verification and forensic explanation
- **Threat Detection** - Rule-based phishing, spoofing, malware, and BEC detection
- **Threat Intelligence** - IP geolocation, domain reputation, URL scanning, file hash lookups
- **AI-Powered Analysis** - LLM-based threat classification with structured output validation
- **Risk Scoring** - Explainable, reproducible risk scores with factor breakdown
- **Forensic Evidence Ledger** - Tamper-evident hash-chain evidence system
- **Investigation Case Management** - Complete SOC workflow with timeline and alerts
- **Real-Time Dashboard** - Live threat monitoring and analytics

---

## 🏗️ Architecture

### Backend
- **Python 3.11+** with FastAPI
- **PostgreSQL** for structured data storage
- **Redis** for caching and background jobs
- **SQLAlchemy 2.0** with async support
- **Alembic** for database migrations

### Frontend
- **React 18** with TypeScript
- **Vite** for fast development and optimized builds
- **Tailwind CSS** for styling
- **Recharts** for data visualization

### Intelligence Providers
- **VirusTotal** - File, URL, domain, IP reputation
- **AbuseIPDB** - IP abuse confidence scoring
- **IP-API** - Geolocation and network information
- **Demo Provider** - Fallback intelligence for testing

### AI Providers
- **OpenAI GPT-4** - Primary LLM for threat analysis
- **Anthropic Claude** - Alternative LLM provider
- **Rule-Based Fallback** - Works without AI APIs

---

## 📂 Project Structure

```
tracex-pro/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI application
│   │   ├── config.py                  # Configuration management
│   │   ├── database.py                # Database connection
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── emails.py          # Email analysis endpoints
│   │   │       ├── cases.py           # Case management
│   │   │       ├── evidence.py        # Evidence ledger
│   │   │       ├── intelligence.py    # Threat intelligence
│   │   │       └── dashboard.py       # Dashboard stats
│   │   ├── models/                    # SQLAlchemy models
│   │   ├── schemas/                   # Pydantic schemas
│   │   ├── services/
│   │   │   ├── email_parser.py        # RFC 822 parser
│   │   │   ├── authentication_analyzer.py  # SPF/DKIM/DMARC
│   │   │   ├── header_analyzer.py     # Header forensics
│   │   │   ├── threat_detector.py     # Rule-based detection
│   │   │   ├── risk_scorer.py         # Risk calculation
│   │   │   ├── ai_analyzer.py         # LLM analysis
│   │   │   ├── forensic_ledger.py     # Hash-chain evidence
│   │   │   └── email_analysis_orchestrator.py
│   │   ├── intelligence/
│   │   │   ├── base.py                # Provider interface
│   │   │   ├── virustotal_provider.py
│   │   │   ├── abuseipdb_provider.py
│   │   │   ├── ipinfo_provider.py
│   │   │   ├── demo_provider.py
│   │   │   └── manager.py             # Intelligence coordinator
│   │   └── utils/
│   ├── alembic/                       # Database migrations
│   ├── tests/                         # Unit tests
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── types/
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
├── sample-emails/                     # Test .eml files
│   ├── phishing-paypal-spoof.eml
│   ├── bec-ceo-spoofing.eml
│   ├── invoice-macro-malware.eml
│   └── clean-legitimate-email.eml
├── docs/
├── docker-compose.yml
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **PostgreSQL 14+**
- **Redis 6+**
- **Git**

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/tracex-pro.git
cd tracex-pro
```

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration
```

### 3. Database Setup

```bash
# Start PostgreSQL (if not already running)
# Create database
createdb tracex_db

# Run migrations
alembic upgrade head
```

### 4. Start Backend

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API will be available at: `http://localhost:8000`
Interactive docs: `http://localhost:8000/docs`

### 5. Frontend Setup

```bash
cd ../frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend will be available at: `http://localhost:5173`

---

## 🐳 Docker Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Services:
- **Backend**: http://localhost:8000
- **Frontend**: http://localhost:3000
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

---

## 🔧 Configuration

### Environment Variables

See `backend/.env.example` for all configuration options.

Key configurations:

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/tracex_db

# AI Provider
AI_PROVIDER=openai
AI_API_KEY=sk-your-openai-api-key

# Threat Intelligence
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# Fallback Mode
USE_DEMO_INTELLIGENCE=true
```

### API Keys

Optional but recommended for production:

1. **OpenAI**: https://platform.openai.com/api-keys
2. **VirusTotal**: https://www.virustotal.com/gui/my-apikey
3. **AbuseIPDB**: https://www.abuseipdb.com/account/api

**Note**: The platform works without API keys using demo/fallback providers, clearly marked as such.

---

## 📊 Features

### Email Analysis Pipeline

1. **Parse Email** - Extract headers, body, URLs, attachments
2. **Authenticate** - Verify SPF, DKIM, DMARC
3. **Analyze Headers** - Reconstruct routing path, detect anomalies
4. **Detect Threats** - Rule-based phishing/malware/spoofing detection
5. **Query Intelligence** - IP geolocation, domain reputation, URL scanning
6. **Calculate Risk** - Explainable risk score with factor breakdown
7. **AI Analysis** - LLM-powered threat classification
8. **Generate Evidence** - Tamper-evident forensic ledger
9. **Create Alerts** - Automatic alert generation for high-risk emails
10. **Build Timeline** - Investigation chronology

### Forensic Evidence Ledger

- **Hash-Chain Integrity** - Each evidence record cryptographically links to previous
- **SHA-256 Hashing** - Tamper-evident evidence storage
- **Integrity Verification** - Verify entire chain with one API call
- **Immutable Audit Trail** - Cannot modify past evidence without detection

### Threat Intelligence

- **IP Intelligence** - Geolocation, ASN, ISP, reputation, abuse confidence
- **Domain Intelligence** - Age, registrar, lookalike detection, reputation
- **URL Analysis** - Reputation, shortener detection, redirect analysis
- **File Reputation** - Hash-based malware detection

### Risk Scoring

Explainable risk scores (0-100) based on:
- Authentication failures (SPF/DKIM/DMARC)
- Header anomalies
- Phishing indicators
- Threat intelligence
- Malicious infrastructure
- Attachment characteristics

### Dashboard

- Total emails analyzed
- Threats detected
- Critical alerts
- High-risk emails
- Active cases
- Real-time activity feed

---

## 🧪 Testing

### Run Unit Tests

```bash
cd backend
pytest tests/ -v
```

### Test with Sample Emails

```bash
# Upload sample phishing email
curl -X POST http://localhost:8000/api/v1/emails/upload \
  -F "file=@sample-emails/phishing-paypal-spoof.eml"

# Analyze raw email
curl -X POST http://localhost:8000/api/v1/emails/analyze \
  -H "Content-Type: application/json" \
  -d '{"raw_content": "From: test@example.com\nTo: user@example.com\n\nTest"}'
```

### Test Evidence Integrity

```bash
# Verify case evidence chain
curl http://localhost:8000/api/v1/evidence/verify/CASE-20240918-ABC123
```

---

## 📖 API Documentation

### Email Analysis

```http
POST /api/v1/emails/analyze
Content-Type: application/json

{
  "raw_content": "<email content>",
  "source": "manual_upload"
}
```

### File Upload

```http
POST /api/v1/emails/upload
Content-Type: multipart/form-data

file: <.eml file>
```

### Threat Intelligence

```http
GET /api/v1/threat-intelligence/ip/8.8.8.8
GET /api/v1/threat-intelligence/domain/example.com
GET /api/v1/threat-intelligence/url?url=https://suspicious.com
GET /api/v1/threat-intelligence/hash/abc123...
```

### Evidence Verification

```http
POST /api/v1/evidence/verify/{case_id}
```

Full API documentation: `http://localhost:8000/docs`

---

## 🔒 Security Considerations

### Input Validation
- All uploads validated for file type and size
- Email content sanitized before processing
- SQL injection prevention via SQLAlchemy ORM
- XSS protection in API responses

### File Handling
- **Attachments never executed**
- Hash-based analysis only
- Secure temporary storage
- Automatic cleanup

### Authentication
- JWT token-based authentication
- Role-based access control (Admin, Analyst, Viewer)
- Secure password hashing (bcrypt)

### API Security
- Rate limiting
- CORS configuration
- Secure headers
- Input validation via Pydantic

### Secrets Management
- Environment variables for API keys
- `.env` excluded from version control
- Example configuration provided separately

---

## 🚨 Important Forensic Principles

### Geolocation Context

**Geolocation intelligence is contextual, not attribution.**

IP geolocation indicates network infrastructure location, not the physical location of an attacker. Always displayed with explicit context note.

### Evidence Chain

- Evidence integrity verified via cryptographic hash chain
- Any modification breaks the chain and is detected
- Verification results clearly state VERIFIED or COMPROMISED

### AI Analysis

- AI classification is one input among many
- Rule-based detection runs independently
- Fallback analysis available without AI
- AI responses validated against schema

---

## 🤝 Contributing

This is a Smart India Hackathon 2024 project. Contributions welcome!

### Development Setup

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Style

- Backend: Black formatter, type hints
- Frontend: ESLint, Prettier
- Commit messages: Conventional Commits

---

## 📝 License

This project is created for Smart India Hackathon 2024.

---

## 👥 Team

**Smart India Hackathon 2024**

---

## 📞 Support

- **Documentation**: `/docs` directory
- **API Docs**: http://localhost:8000/docs
- **Issues**: GitHub Issues

---

## 🎯 Roadmap

- [ ] Real-time email monitoring via IMAP
- [ ] Advanced ML models for classification
- [ ] Report generation (PDF/JSON)
- [ ] Investigation graph visualization
- [ ] Automated response workflows
- [ ] Multi-tenant support
- [ ] Advanced search and filtering
- [ ] Integration with SIEM platforms

---

## ⚠️ Disclaimer

This platform is designed for legitimate cybersecurity investigation and education. Always obtain proper authorization before analyzing emails. Respect privacy laws and regulations in your jurisdiction.

**Demo intelligence data is clearly marked and should not be used for real security decisions.**

---

Built with ❤️ for Smart India Hackathon 2024
