#!/bin/bash
# ============================================================
# JURI-X Forensic Tools Installation Script
# For Kali Linux / Debian-based systems
# ============================================================
# Usage: chmod +x install-tools.sh && sudo ./install-tools.sh
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║       JURI-X Forensic Tools Installer           ║"
echo "  ║       Autonomous Forensic Intelligence Platform  ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root: sudo ./install-tools.sh${NC}"
  exit 1
fi

echo -e "${YELLOW}[*] Updating package lists...${NC}"
apt-get update -y

echo ""
echo -e "${CYAN}[*] Installing core forensic tools...${NC}"

# === DISK FORENSICS ===
echo -e "${YELLOW}  → Sleuth Kit (mmls, fls, icat, ils, sigfind)...${NC}"
apt-get install -y sleuthkit 2>/dev/null || echo -e "${RED}  [-] sleuthkit failed${NC}"

echo -e "${YELLOW}  → TestDisk / PhotoRec (partition recovery)...${NC}"
apt-get install -y testdisk 2>/dev/null || echo -e "${RED}  [-] testdisk failed${NC}"

echo -e "${YELLOW}  → Foremost (file carving)...${NC}"
apt-get install -y foremost 2>/dev/null || echo -e "${RED}  [-] foremost failed${NC}"

echo -e "${YELLOW}  → Binwalk (firmware/binary analysis)...${NC}"
apt-get install -y binwalk 2>/dev/null || echo -e "${RED}  [-] binwalk failed${NC}"

echo -e "${YELLOW}  → Bulk Extractor (data extraction)...${NC}"
apt-get install -y bulk-extractor 2>/dev/null || echo -e "${RED}  [-] bulk-extractor failed${NC}"

echo -e "${YELLOW}  → Gdisk, fdisk, sfdisk, parted...${NC}"
# fdisk/sfdisk come with util-linux (pre-installed on Kali)
# gdisk is provided by gptfdisk package
apt-get install -y gptfdisk parted 2>/dev/null || {
  # Fallback: try individual packages
  apt-get install -y gdisk parted 2>/dev/null || true
  apt-get install -y gptfdisk 2>/dev/null || true
}
# Verify fdisk/sfdisk exist (they come from util-linux)
if command -v fdisk &> /dev/null && command -v gdisk &> /dev/null; then
  echo -e "${GREEN}  [+] disk tools installed${NC}"
else
  echo -e "${RED}  [-] disk tools partially missing${NC}"
fi

# === MEMORY FORENSICS ===
echo -e "${YELLOW}  → Volatility3...${NC}"
apt-get install -y volatility3 2>/dev/null || {
  echo -e "${YELLOW}  → Installing volatility3 from pip...${NC}"
  pip3 install volatility3 2>/dev/null || {
    echo -e "${YELLOW}  → Installing volatility3 from GitHub...${NC}"
    if [ -d "/opt/volatility3" ]; then
      cd /opt/volatility3 && git pull
    else
      cd /opt && git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git
    fi
    ln -sf /opt/volatility3/vol.py /usr/local/bin/vol 2>/dev/null || true
    ln -sf /opt/volatility3/vol.py /usr/local/bin/volatility3 2>/dev/null || true
  }
}

# === NETWORK FORENSICS ===
echo -e "${YELLOW}  → Wireshark / TShark...${NC}"
apt-get install -y tshark wireshark 2>/dev/null || echo -e "${RED}  [-] wireshark failed${NC}"

echo -e "${YELLOW}  → Network tools...${NC}"
apt-get install -y net-tools macchanger nmap tcpdump 2>/dev/null || true

# === IMAGE / EXIF FORENSICS ===
echo -e "${YELLOW}  → ExifTool (comprehensive metadata)...${NC}"
apt-get install -y libimage-exiftool-perl 2>/dev/null || echo -e "${RED}  [-] exiftool failed${NC}"

echo -e "${YELLOW}  → Sharp (image processing)...${NC}"
# npm install -g sharp-cli 2>/dev/null || true  # Already in project

# === PDF FORENSICS ===
echo -e "${YELLOW}  → pdf-parser, pdfid...${NC}"
apt-get install -y libfile-mmagic-perl 2>/dev/null || true

# Python PDF tools
pip3 install pdfid oletools 2>/dev/null || true

# pdf-parser
if ! command -v pdf-parser.py &> /dev/null; then
  if [ ! -f "/usr/local/bin/pdf-parser.py" ]; then
    echo -e "${YELLOW}  → Installing pdf-parser.py...${NC}"
    curl -sL "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py" -o /usr/local/bin/pdf-parser.py 2>/dev/null
    chmod +x /usr/local/bin/pdf-parser.py 2>/dev/null || true
  fi
fi

# === REGISTRY FORENSICS ===
echo -e "${YELLOW}  → Registry tools (RegRipper, hivex)...${NC}"
# Try multiple package names for hivex (varies across Kali versions)
apt-get install -y hivex-tools 2>/dev/null || \
apt-get install -y hivex 2>/dev/null || \
apt-get install -y libhivex-dev hivex-sh 2>/dev/null || {
  # Build from source if no package available
  if ! command -v hivexsh &> /dev/null; then
    echo -e "${YELLOW}  → Building hivex from source...${NC}"
    apt-get install -y libxml2-dev 2>/dev/null || true
    cd /tmp && git clone --depth 1 https://github.com/libguestfs/hivex.git 2>/dev/null && \
    cd hivex && autoreconf -i && ./configure && make -j$(nproc) && make install 2>/dev/null || true
  fi
}
if command -v hivexsh &> /dev/null || command -v hivexget &> /dev/null; then
  echo -e "${GREEN}  [+] hivex installed${NC}"
else
  echo -e "${YELLOW}  [!] hivex not available — registry parsing limited${NC}"
fi

# RegRipper
if ! command -v regripper &> /dev/null; then
  if [ ! -d "/opt/RegRipper3.0" ]; then
    echo -e "${YELLOW}  → Installing RegRipper3 from GitHub...${NC}"
    apt-get install -y libunicode-string-perl libdatetime-perl libparse-datetime-perl libjson-perl libcpanel-json-xs-perl 2>/dev/null || true
    cd /opt && git clone --depth 1 https://github.com/keydet89/RegRipper3.0.git 2>/dev/null || true
    ln -sf /opt/RegRipper3.0/rr.py /usr/local/bin/regripper 2>/dev/null || true
  fi
fi

# === ARCHIVE TOOLS ===
echo -e "${YELLOW}  → 7-Zip, unrar, unzip...${NC}"
# p7zip-full is deprecated on newer Kali — use '7zip' package
apt-get install -y 7zip unrar unzip 2>/dev/null || \
apt-get install -y p7zip-full p7zip-rar unrar unzip 2>/dev/null || \
apt-get install -y p7zip unrar unzip 2>/dev/null || true
if command -v 7z &> /dev/null || command -v 7zz &> /dev/null; then
  echo -e "${GREEN}  [+] archive tools installed${NC}"
else
  echo -e "${RED}  [-] archive tools failed${NC}"
fi

# === HASH / INTEGRITY ===
echo -e "${YELLOW}  → HashDeep...${NC}"
apt-get install -y hashdeep md5deep 2>/dev/null || echo -e "${RED}  [-] hashdeep failed${NC}"

# === PYTHON FORENSIC LIBRARIES ===
echo -e "${YELLOW}  → Python forensic packages...${NC}"
pip3 install python-magic pyshark 2>/dev/null || true

# === STRING TOOLS ===
echo -e "${YELLOW}  → Strings, file, grep...${NC}"
apt-get install -y binutils file ripgrep 2>/dev/null || true

# ============================================================
echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════╗"
echo -e "║              TOOL VERIFICATION                       ║"
echo -e "╚═══════════════════════════════════════════════════╝${NC}"
echo ""

TOOLS=(
  "mmls:Sleuth Kit (mmls)"
  "fls:Sleuth Kit (fls)"
  "icat:Sleuth Kit (icat)"
  "vol:Volatility3"
  "volatility3:Volatility3 (alt)"
  "tshark:TShark (Wireshark)"
  "exiftool:ExifTool"
  "binwalk:Binwalk"
  "bulk_extractor:Bulk Extractor"
  "hashdeep:HashDeep"
  "7z|7zz:7-Zip"
  "pdfid.py:PDFiD"
  "regripper:RegRipper"
  "hivexsh|hivexget:Hivex Tools"
  "file:File Command"
  "strings:Strings"
  "rg:Ripgrep"
  "foremost:Foremost"
  "testdisk:TestDisk"
  "unrar:UnRAR"
  "gdisk:GPT fdisk"
)

INSTALLED=0
MISSING=0

for tool_info in "${TOOLS[@]}"; do
  IFS=':' read -r tool_name description <<< "$tool_info"
  FOUND=0
  # Support alternates with |
  IFS='|' read -ra alt_names <<< "$tool_name"
  for alt in "${alt_names[@]}"; do
    if command -v "$alt" &> /dev/null; then
      FOUND=1
      break
    fi
  done
  if [ $FOUND -eq 1 ]; then
    echo -e "  ${GREEN}[+]${NC} ${description}"
    ((INSTALLED++))
  else
    echo -e "  ${RED}[-]${NC} ${description} — NOT FOUND"
    ((MISSING++))
  fi
done

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "  Installed: ${GREEN}${INSTALLED}${NC}  |  Missing: ${RED}${MISSING}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"

if [ $MISSING -gt 0 ]; then
  echo -e "${YELLOW}[!] Some tools are missing. JURI-X will still work — missing tools are skipped gracefully.${NC}"
fi

echo ""
echo -e "${GREEN}[✓] JURI-X tool installation complete!${NC}"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "  1. cd /home/z/my-project"
echo -e "  2. npm run dev"
echo -e "  3. Open browser and upload evidence files"
echo ""
