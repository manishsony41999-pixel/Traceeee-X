# 🚀 How to Open and Run TRACE-X

## ⚡ Quick Start (Easiest Way - One Click)

Double-click either of these files in the `D:\tracex pro` folder:

1. **[`TRACE-X.exe`](file:///D:/tracex%20pro/TRACE-X.exe)** - Native Windows Graphical Manager (Start, Stop, Live Status, One-Click Browser Launch)
2. **[`START-TRACEX.bat`](file:///D:/tracex%20pro/START-TRACEX.bat)** - Instant One-Click Launcher

Both will automatically start the backend API and frontend UI and open your browser at **http://localhost:5173**.

---

### First-Time Installation (Automated)

If you are setting up on a fresh computer, run:
- **[`INSTALL-TRACEX.bat`](file:///D:/tracex%20pro/INSTALL-TRACEX.bat)** - Automatically installs Python 3.11, sets up virtualenv, and installs all dependencies.

---

## 🎯 What You'll See

The TRACE-X dashboard will open showing:
- ✅ Email Threat Analyzer
- ✅ Investigation Dashboard
- ✅ Threat Intelligence Lookup
- ✅ Forensic Evidence Ledger

---

## 🧪 Try It Out

1. **Click "Analyze Email"** in the sidebar
2. **Click "Phishing & Spoofing"** quick-load button
3. **Click "Execute Deep Forensic Analysis"**
4. **See the complete threat breakdown!**

---

## 💡 Note

- The frontend works immediately (you're seeing it now!)
- For **full backend functionality** (real email analysis), follow the backend setup in the main README.md
- For now, you can explore the UI and see sample data

---

## 🔧 Full Backend Setup (Optional - for complete functionality)

After Python is installed:

```powershell
# Navigate to backend
cd "D:\tracex pro\backend"

# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment config
copy .env.example .env

# Start backend
uvicorn app.main:app --reload
```

Backend will run at: http://localhost:8000

---

## 🆘 Troubleshooting

### "Python not found"
- Make sure you installed Python from Microsoft Store
- Restart PowerShell after installation

### "npm not found"
- Node.js is already installed (you have v24.21.0)
- If frontend doesn't start, run: `npm install` in the frontend folder

### "Permission denied" when running START-TRACEX.ps1
Run this first:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## 📞 Need Help?

Check the main **README.md** file in this folder for detailed documentation.

---

**Built for Smart India Hackathon 2024** 🏆
