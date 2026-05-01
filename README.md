## Cybersecurity Demo Web App (Flask + SQLite)

This project contains **two versions** of the same workflow:

- **Insecure**: intentionally vulnerable to **SQL injection** and **stored XSS** (for education).
- **Secure**: uses **bcrypt**, **prepared statements**, **input validation**, and **output escaping**, plus an **attack logging + Chart.js dashboard**.

### Run

From the project root:

```bash
pip install -r requirements.txt
python backend/app.py
```

Then open:

- `http://127.0.0.1:5000/` (index)
- `http://127.0.0.1:5000/insecure.html`
- `http://127.0.0.1:5000/secure.html`

SQLite file will be created at `backend/database.db` automatically on first run.

### API Endpoints

- **INSECURE**
  - `POST /api/insecure/login` (SQLi-vulnerable string concatenation)
  - `POST /api/insecure/comment` (stored XSS: no sanitization)

- **SECURE**
  - `POST /api/secure/register` (bcrypt hash + parameterised insert)
  - `POST /api/secure/login` (parameterised select + bcrypt check)
  - `POST /api/secure/comment` (server validation + HTML-escaped output)

- **ADMIN (attack telemetry)**
  - `GET /api/admin/logs`
  - `GET /api/admin/stats`

