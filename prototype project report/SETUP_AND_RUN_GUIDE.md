# Setup & Execution Guide

## Prerequisites
- Python 3.11 or 3.12
- Node.js 18+ and npm
- Windows PowerShell / Bash

## Step-by-step Setup Instructions

### 1. Backend Setup
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m scratch.seed_sih_demo
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```

### 3. Verification
Open browser to `http://localhost:5173`. Log in using `admin_demo` / `password`.
