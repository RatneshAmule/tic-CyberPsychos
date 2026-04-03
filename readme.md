🛡️ JURI-X
Autonomous Digital Forensic Intelligence Platform

JURI-X is a production-grade DFIR (Digital Forensics & Incident Response) platform built for real-world forensic analysis on Kali Linux. It performs actual forensic investigations using native CLI tools, not mock data.

🚀 Features
🔍 Real Forensic Analysis (NO MOCK DATA)
Disk images (.dd, .img, .E01)
Memory dumps (.dmp, .vmem)
Network captures (.pcap)
Logs, browser data, registry hives
Images, PDFs, archives

All analysis is executed using:

sleuthkit, volatility3, tshark
binwalk, exiftool, sqlite3
strings, file, pdfinfo, etc.
⚡ Core Capabilities
🔬 Deep File Analysis (entropy, magic bytes, hashes)
🧠 Timeline Reconstruction
🎥 Rewind Mode (event playback like video)
🌐 Network & IOC Extraction
📊 Interactive Dashboard & Heatmaps
🧩 Entity Correlation Graph
🚨 Suspicious Activity Detection
🔎 Keyword Intelligence Engine
🤖 AI Investigator (NVIDIA NIM Integration)
📄 Court-Ready Report Generation
🔗 Chain of Custody Tracking
🏗️ Architecture
⚠️ Critical Design Principles
❌ NO native Node.js modules (C++ addons)
⚙️ All analysis runs in external worker process
🧰 Only CLI forensic tools used
📁 File-based storage (/tmp/JURI-X/)
🔐 Forensic integrity via SHA-256 hashing
🧠 Architecture Flow
Client (Next.js UI)
        ↓
API Route (Upload Handler)
        ↓
Worker Process (Node.js ESM)
        ↓
Kali CLI Tools (Analysis)
        ↓
JSON Output → UI Dashboard
🛠️ Tech Stack
Frontend
Next.js 16 (App Router)
TypeScript
Tailwind CSS 4
shadcn/ui
Framer Motion
Recharts
Backend
Node.js API Routes
External Worker (child_process.spawn)
CLI-based forensic processing
State & Utilities
Zustand
React Query
date-fns (safeFormat wrapper)
📁 Project Structure
src/
 ├── app/
 │   ├── api/forensic/*
 │   ├── layout.tsx
 │   └── page.tsx
 │
 ├── components/forensic/
 │   ├── Dashboard.tsx
 │   ├── EvidenceUpload.tsx
 │   ├── TimelineView.tsx
 │   ├── RewindPlayer.tsx
 │   ├── EntityGraph.tsx
 │   ├── SuspiciousPanel.tsx
 │   ├── KeywordSearch.tsx
 │   ├── AIInvestigator.tsx
 │   └── ReportGenerator.tsx
 │
 ├── lib/forensic/
 │   ├── engine.ts
 │   ├── detection.ts
 │   ├── correlation.ts
 │   ├── timeline.ts
 │   └── tool-*.ts
 │
scripts/
 └── analyze-worker.mjs

/tmp/JURI-X/
 ├── evidence/
 └── ai-settings.json
⚙️ Installation
1️⃣ Clone Repository
git clone https://github.com/your-username/JURI-X.git
cd JURI-X
2️⃣ Install Dependencies
npm install
3️⃣ Install Forensic Tools (Kali Linux)
chmod +x install-tools.sh
./install-tools.sh
4️⃣ Run Development Server
npm run dev

App runs at:

http://localhost:3000
📦 Build for Production
npm run build
npm start
📂 Evidence Storage

All uploaded evidence is stored in:

/tmp/JURI-X/evidence/<case-id>/
🔐 Forensic Integrity
SHA-256 hash generated for every file
Read-only processing
Chain of custody automatically maintained
🤖 AI Investigator

Supports:

NVIDIA NIM models
Streaming responses (SSE)
Case-aware analysis
Example Queries:
"Analyze attack timeline"
"Extract all IOCs"
"What is the threat level?"
📊 Modules Overview
Module	Description
Dashboard	Case summary + analytics
Evidence	Upload & analysis
Timeline	Event reconstruction
Rewind	Event playback
Graph	Entity relationships
Findings	Threat detection
Search	Keyword intelligence
AI	Investigation assistant
Reports	Export results
⚠️ Constraints
❌ No Prisma / No database
❌ No native modules (better-sqlite3, sharp, etc.)
⚠️ Max file size: 10GB
⚠️ Worker timeout: 10 minutes
🧪 Supported Evidence Types
Disk Images
Memory Dumps
Network Captures
Logs
Browser Databases
Registry Hives
Archives
Documents
Images
📄 Report Formats
TXT (formatted forensic report)
JSON (full analysis data)
DOCX (optional export)
🧩 Future Enhancements
Live monitoring agents
Multi-case management
Distributed worker nodes
Advanced ML detection
👨‍💻 Author

Developed for real-world DFIR, CTFs, and forensic investigations.

⚡ Final Note

JURI-X is not a demo tool.

It is designed to behave like a real forensic lab system, leveraging actual Kali Linux tooling for authentic investigation workflows.
