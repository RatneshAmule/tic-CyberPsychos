<div align="center">
🛡️ JURI-X
Autonomous Forensic Intelligence Platform
A complete Digital Forensics & Incident Response (DFIR) workstation — right in your browser.
![Next.js](https://img.shields.io/badge/Next.js-16.1-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?logo=typescript)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.x-38bdf8?logo=tailwindcss)
![React](https://img.shields.io/badge/React-19-61dafb?logo=react)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-557c94?logo=kalilinux)
</div>
---
📖 Overview
JURI-X is a browser-based forensic intelligence platform designed for digital forensic investigators, incident response teams, and cybersecurity analysts. It provides a unified workspace to upload forensic evidence (disk images, RAM dumps, PCAP files, documents, databases, registry hives, and more), run automated multi-tool analysis, visualize timelines, explore entity relationships, search through findings, and generate professional reports — all from a single intuitive interface.
The platform integrates with industry-standard CLI forensic tools running on Kali Linux, including Sleuth Kit, Volatility3, Binwalk, ExifTool, Bulk Extractor, Hivex, and more. JURI-X orchestrates these tools automatically based on the type of evidence uploaded, extracting artifacts, reconstructing timelines, detecting suspicious activities, and presenting everything in an interactive forensic dashboard.
Whether you are investigating a malware infection, analyzing a compromised system, processing a disk image for file recovery, or examining network captures for indicators of compromise, JURI-X streamlines the entire forensic workflow from evidence intake to final report generation.
---
✨ Key Features
🔍 Multi-Format Evidence Analysis
Upload and analyze a wide range of forensic artifact types:
Evidence Type	Supported Formats	Analysis Tools
Disk Images	`.raw`, `.img`, `.dd`, `.E01`	Sleuth Kit (mmls, fls, icat), Bulk Extractor
RAM Dumps	`.vmem`, `.dmp`, `.mem`	Volatility3 (pslist, netscan, hivelist)
Images	`.jpg`, `.png`, `.gif`, `.bmp`, `.tiff`	ExifTool, ImageMagick (identify)
Databases	`.db`, `.sqlite`, `.sqlite3`	SQLite CLI (tables, schema dump)
Registry Hives	`.hiv`, `.reg`, `.dat`	Hivex (hivexsh, hivexget)
Network Captures	`.pcap`, `.pcapng`	Strings extraction, keyword analysis
Documents	`.pdf`, `.docx`, `.xlsx`, `.pptx`	PDF parser, string extraction, metadata
Archives	`.zip`, `.gz`, `.7z`, `.tar`	Archive extraction, embedded file scanning
Executables	`.exe`, `.dll`, `.elf`	Binwalk, strings, file identification
Text / Logs	`.txt`, `.csv`, `.xml`, `.json`, `.log`	Log parsing, keyword search, string extraction
🧠 AI-Powered Investigation
Built-in AI Investigator that can answer questions about your forensic findings, explain suspicious activities, summarize timeline events, and provide investigative recommendations — all powered by on-demand AI analysis.
⏪ Forensic Rewind Mode
A unique timeline playback system that lets you step through forensic events chronologically. Play forward or rewind through the sequence of activities detected in your evidence, with speed control and event-by-event navigation. Each event shows the timestamp, action type, involved entity, source, user, process, and confidence level.
📊 Interactive Dashboard
A comprehensive forensic dashboard with:
Evidence overview cards with file metadata and hash verification
Activity summary with action type breakdown
Timeline event distribution and heatmaps
Risk assessment scoring
Suspicious finding highlights
🔗 Entity Graph Visualization
Visual relationship mapping between entities found in evidence — showing connections between users, processes, files, network connections, and registry changes as an interactive graph.
🔎 Keyword Search
Full-text keyword search across all extracted forensic data. Search for specific strings, IPs, domains, file paths, usernames, or any artifact found during analysis.
📝 Professional Report Generation
Generate comprehensive forensic analysis reports in DOCX format with one click. Reports include executive summary, evidence details, timeline of events, suspicious findings, AI analysis, and recommendations.
🎯 Chain of Custody
Built-in chain of custody tracking for every evidence file — recording who uploaded it, when it was analyzed, and the full provenance of forensic findings.
---
🖥️ Platform Tabs
JURI-X provides a tabbed single-page interface with the following forensic workspaces:
Tab	Description
Dashboard	Overview of analyzed evidence with stats, summaries, and risk scoring
Evidence	Upload forensic files and initiate automated multi-tool analysis
Timeline	Chronological visualization of all detected forensic events
Rewind Mode	Interactive event-by-event playback with speed controls
Graph	Entity relationship visualization from extracted data
Findings	Suspicious activity detection and risk assessment panel
Search	Keyword search across all extracted forensic artifacts
AI Investigator	AI-powered forensic analysis and Q&A
Reports	Professional forensic report generation and download
---
🛠️ Tech Stack
Layer	Technology
Framework	Next.js 16 (App Router)
Language	TypeScript 5 (Strict Mode)
UI Library	React 19
Styling	Tailwind CSS 4 + shadcn/ui
Animations	Framer Motion
Icons	Lucide React
Charts	Recharts
Database	SQLite via Prisma ORM
AI Integration	z-ai-web-dev-sdk
Report Generation	docx (npm)
State Management	Zustand
Date Handling	date-fns
Markdown	react-markdown + @mdxeditor/editor
Forensic CLI Tools (Kali Linux)
Sleuth Kit — Disk image partition analysis and file system forensics
Volatility3 — RAM dump analysis (process listing, network connections, registry)
Binwalk — Firmware/binary analysis and embedded file extraction
ExifTool — Image and document metadata extraction
Bulk Extractor — Bulk data extraction (URLs, emails, domains, phone numbers)
Hivex Tools — Windows registry hive parsing
SQLite CLI — Database structure and content extraction
ImageMagick — Image identification and detailed metadata
file — File type identification
strings — Readable string extraction from binaries
openssl — Hash computation (MD5, SHA256) for evidence integrity
---
📁 Project Structure
```
juri-x/
├── src/
│   ├── app/
│   │   ├── layout.tsx                    # Root layout with theme provider
│   │   ├── page.tsx                      # Main app — tabbed forensic workspace
│   │   ├── globals.css                   # Global styles + forensic theme
│   │   └── api/
│   │       └── forensic/
│   │           ├── analyze/route.ts      # POST — Start forensic analysis
│   │           ├── evidence/route.ts     # POST — Upload evidence files
│   │           ├── timeline/route.ts     # GET — Fetch timeline data
│   │           ├── rewind/route.ts       # GET — Fetch rewind sequence
│   │           ├── search/route.ts       # GET — Keyword search
│   │           ├── ai/route.ts           # POST — AI investigation queries
│   │           ├── ai-settings/route.ts  # GET/POST — AI configuration
│   │           ├── report/route.ts       # POST — Generate forensic report
│   │           ├── custody/route.ts      # GET — Chain of custody
│   │           └── geoip/route.ts        # GET — GeoIP lookup
│   ├── components/
│   │   ├── ui/                           # shadcn/ui base components
│   │   └── forensic/
│   │       ├── Dashboard.tsx             # Forensic dashboard view
│   │       ├── EvidenceUpload.tsx        # Drag & drop evidence upload
│   │       ├── TimelineView.tsx          # Event timeline visualization
│   │       ├── RewindPlayer.tsx          # Timeline playback with controls
│   │       ├── EntityGraph.tsx           # Entity relationship graph
│   │       ├── SuspiciousPanel.tsx       # Suspicious findings panel
│   │       ├── KeywordSearch.tsx         # Full-text keyword search
│   │       ├── AIInvestigator.tsx        # AI-powered Q&A interface
│   │       ├── ReportGenerator.tsx       # Forensic report builder
│   │       └── ActivityHeatmap.tsx       # Activity timeline heatmap
│   └── lib/
│       ├── db.ts                         # Database connection (SQLite/Prisma)
│       └── forensic/
│           ├── engine.ts                 # Main forensic analysis engine
│           ├── types.ts                  # TypeScript type definitions
│           ├── real-file-analyzer.ts     # File type detection & routing
│           ├── real-processor.ts         # Evidence processing pipeline
│           ├── real-string-extractor.ts  # Strings extraction engine
│           ├── real-sqlite-parser.ts     # SQLite database parser
│           ├── real-hash.ts              # Hash computation utilities
│           ├── real-image-analyzer.ts    # Image metadata analysis
│           ├── real-log-parser.ts        # Log file parser
│           ├── real-keyword-engine.ts    # Keyword search engine
│           ├── timeline.ts               # Timeline construction logic
│           ├── rewind.ts                 # Rewind sequence builder
│           ├── correlation.ts            # Entity correlation engine
│           ├── detection.ts              # Suspicious activity detection
│           ├── keyword.ts                # Keyword extraction
│           ├── reporting.ts              # Report generation logic
│           ├── tool-binwalk.ts           # Binwalk integration
│           ├── tool-exif-analyzer.ts     # ExifTool integration
│           ├── tool-disk-image.ts        # Sleuth Kit integration
│           ├── tool-memory-analyzer.ts   # Volatility3 integration
│           ├── tool-pcap-analyzer.ts     # PCAP analysis
│           ├── tool-pdf-analyzer.ts      # PDF document parser
│           ├── tool-registry-analyzer.ts # Registry hive parser
│           ├── tool-archive-extractor.ts # Archive extraction
│           └── sample-data.ts            # Demo data generator
├── scripts/
│   └── analyze-worker.mjs               # Standalone forensic analysis worker
├── install-tools.sh                      # Kali Linux forensic tools installer
├── package.json
├── next.config.ts
├── tsconfig.json
├── tailwind.config.ts
└── postcss.config.mjs
```
---
🚀 Quick Start
Prerequisites
Kali Linux (recommended) or any Debian-based Linux distribution
Node.js 18+ or Bun runtime
npm or bun package manager
Installation
```bash
# 1. Clone/extract the project
unzip JURI-X.zip
cd juri-x

# 2. Install dependencies
npm install
# OR
bun install

# 3. Install forensic CLI tools
sudo bash install-tools.sh

# 4. Start the development server
npm run dev
# OR
bun dev
```
Access
Open your browser and navigate to:
```
http://localhost:3000
```
---
🔧 Forensic Tools Setup
The `install-tools.sh` script automatically installs all required CLI tools on Kali Linux:
```bash
sudo bash install-tools.sh
```
This installs:
sleuthkit — Disk image analysis (mmls, fls, icat)
binwalk — Binary/firmware analysis
libhivex-bin — Registry hive parsing
libimage-exiftool-perl — EXIF metadata extraction
imagemagick — Image identification
sqlite3 — SQLite database analysis
bulk-extractor — Bulk artifact extraction
volatility3 (via pip) — RAM dump analysis
openssl — Hash computation for evidence integrity
After installation, the script verifies each tool and creates compatibility symlinks where needed.
Manual Tool Check
You can verify tool availability through the application or manually:
```bash
# Check if tools are installed
which mmls fls icat binwalk exiftool identify sqlite3 \
      bulk_extractor vol.py hivexsh hivexget strings file openssl
```
---
📋 How to Use
1. Upload Evidence
Navigate to the Evidence tab and drag-and-drop your forensic files or click to browse. JURI-X accepts disk images, RAM dumps, PCAPs, images, databases, registry hives, documents, archives, executables, and text/log files.
2. Run Analysis
Click the Analyze button to start automated forensic analysis. JURI-X automatically detects the file type and runs the appropriate combination of forensic tools. Progress is shown in real-time.
3. Explore Results
Once analysis completes, navigate through the tabs to explore:
Dashboard — Overview of findings, stats, and risk assessment
Timeline — Chronological event visualization
Rewind Mode — Step through events like a video player
Graph — Entity relationship visualization
Findings — Suspicious activity highlights
Search — Search for specific keywords across all artifacts
4. Ask AI
Use the AI Investigator tab to ask questions about your evidence. The AI can explain suspicious activities, summarize findings, identify attack patterns, and provide investigative recommendations.
5. Generate Report
Go to the Reports tab to generate a comprehensive forensic analysis report in DOCX format. The report includes all evidence details, timeline, findings, AI analysis, and recommendations.
---
🔒 Evidence Integrity
JURI-X computes cryptographic hashes (MD5 and SHA256) for every uploaded file using the `openssl` CLI tool. These hashes are stored alongside evidence records and can be used to verify file integrity throughout the forensic chain of custody. The Chain of Custody API tracks every action performed on evidence from upload through analysis to report generation.
---
🎨 Theme
JURI-X uses a professional dark forensic theme designed for extended analysis sessions:
Background: Deep dark (#0a0e17)
Cards: Dark glass (#111827) with subtle borders
Primary Accent: Cyan (#06b6d4) for active elements
Secondary Accent: Emerald green for success states
Danger: Red for critical findings and errors
Typography: Inter for body text, JetBrains Mono for forensic data
Effects: Glassmorphism, scan-line animations, pulse glows
---
🤝 Contributing
Contributions to JURI-X are welcome. To contribute:
Fork the repository
Create a feature branch: `git checkout -b feature/your-feature`
Commit your changes: `git commit -m 'Add your feature'`
Push to the branch: `git push origin feature/your-feature`
Open a Pull Request
---
📄 License
This project is for educational and authorized forensic investigation purposes only. Always ensure you have proper legal authorization before analyzing any evidence.
---
<div align="center">
Built with 🔥 for Digital Forensics & Incident Response
</div>
