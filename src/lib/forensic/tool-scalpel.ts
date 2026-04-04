/**
 * tool-scalpel.ts — File Carving / Recovery
 *
 * Uses: scalpel for file carving and data recovery from disk images,
 * memory dumps, and other binary files.
 *
 * Extracts: embedded files (JPEG, PNG, PDF, ZIP, EXE, DOC, XLS, etc.)
 * from binary containers using file signature-based carving.
 *
 * Creates a default config if /etc/scalpel/scalpel.conf is not available.
 * Detects suspicious: executables in non-executable files, documents
 * inside binaries, hidden archives.
 *
 * Falls back gracefully if scalpel is not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync, mkdirSync, writeFileSync, readdirSync } from 'fs';
import { basename, join } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CarvedFile {
  name: string;
  size: number;
  type: string;
  sourceOffset: string;
  hash: string;
}

export interface ScalpelSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface ScalpelResult {
  available: boolean;
  filePath: string;
  carvedFiles: CarvedFile[];
  totalCarved: number;
  totalRecoveredSize: number;
  suspiciousFindings: ScalpelSuspiciousFinding[];
  toolUsed: string;
  errors: string[];
}

// ─── Constants ───────────────────────────────────────────────────────────────

const CARVED_OUTPUT_DIR = '/tmp/juri-x/carved';
const FALLBACK_CONFIG_PATH = '/tmp/juri-x/scalpel.conf';

/** Minimal default scalpel configuration with common file signatures. */
const DEFAULT_SCALPEL_CONFIG = `# ─── JURI-X Default Scalpel Configuration ───────────────────────────────
# File carving signatures for common file types

# ─── Images ───────────────────────────────────────────────────────────────
jpg     y     5000000     \\xff\\xd8\\xff\\xe0\\x00\\x10   \\x00\\xff\\xd9    JPG JPEG
png     y     5000000     \\x89PNG\\r\\n\\x1a\\n            \\x00\\x00\\x00\\x00IEND   PNG image
gif     y     5000000     GIF87a                           \\x00\\x3b    GIF image
gif2    y     5000000     GIF89a                           \\x00\\x3b    GIF image
bmp     y     5000000     BM                               \\x00\\x00\\x00  BMP image

# ─── Documents ─────────────────────────────────────────────────────────────
pdf     y     10000000    %PDF                             %%EOF       PDF document
doc     n     5000000     \\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1   \\x00\\x00\\x00\\x00  MS Word DOC
docx    y     10000000    PK\\x03\\x04                       \\x00\\x00\\x00\\x00  ZIP-based Office
xls     n     5000000     \\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1   \\x00\\x00\\x00\\x00  MS Excel XLS
ppt     n     5000000     \\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1   \\x00\\x00\\x00\\x00  MS PowerPoint PPT

# ─── Archives ──────────────────────────────────────────────────────────────
zip     y     50000000    PK\\x03\\x04                       \\x00\\x00\\x00\\x00  ZIP archive
rar     y     50000000    Rar!\\x1a\\x07\\x00                \\x00\\x00\\x00\\x00  RAR archive
7z      y     50000000    7z\\xbc\\xaf\\x27\\x1c             \\x00\\x00\\x00\\x00  7-Zip archive
gz      y     50000000    \\x1f\\x8b\\x08                    \\x00\\x00\\x00\\x00  GZIP archive
bz2     y     50000000    BZ                               \\x00\\x00\\x00\\x00  BZIP2 archive
tar     y     50000000    ustar\\x00                        \\x00\\x00\\x00\\x00  TAR archive

# ─── Executables ───────────────────────────────────────────────────────────
exe     y     10000000    MZ                               \\x00\\x00\\x00\\x00  Windows PE executable
elf     y     10000000    \\x7fELF                          \\x00\\x00\\x00\\x00  ELF binary
dll     n     10000000    MZ                               \\x00\\x00\\x00\\x00  Windows DLL

# ─── Databases ─────────────────────────────────────────────────────────────
sqlite  y     50000000    SQLite format 3\\x00              \\x00\\x00\\x00\\x00  SQLite database

# ─── Network / Forensic ────────────────────────────────────────────────────
pcap    y     50000000    \\xd4\\xc3\\xb2\\xa1               \\x00\\x00\\x00\\x00  PCAP capture
pcapng  y     50000000    \\x0a\\x0d\\x0d\\x0a               \\x00\\x00\\x00\\x00  PCAPNG capture
evtx    y     50000000    \\x45\\x6c\\x66\\x46\\x69\\x6c\\x65\\x00\\x00\\x01\\x00   \\x00\\x00\\x00\\x00  Windows Event Log

# ─── Other ─────────────────────────────────────────────────────────────────
html    y     5000000     \\x3c\\x68\\x74\\x6d\\x6c           \\x3c\\x2f\\x68\\x74\\x6d\\x6c\\x3e  HTML file
xml     y     5000000     \\x3c\\x3f\\x78\\x6d\\x6c           \\x3c\\x2f\\x73\\x76\\x67\\x3e  XML file
txt     y     1000000     [PRINTABLE]                       \\x00\\x00\\x00\\x00  Text file (heuristic)
`;

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 120_000,
};

function runTool(cmd: string): string | null {
  try {
    const out = execSync(cmd, EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found')) {
      console.warn(`[JURI-X Scalpel] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X Scalpel] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Check if scalpel is installed. */
function isScalpelAvailable(): boolean {
  const output = runTool('scalpel --help 2>&1 | head -1');
  return output !== null;
}

/** Ensure output directory exists. */
function ensureOutputDir(): boolean {
  try {
    if (!existsSync(CARVED_OUTPUT_DIR)) {
      mkdirSync(CARVED_OUTPUT_DIR, { recursive: true });
    }
    return true;
  } catch (err: any) {
    console.warn(`[JURI-X Scalpel] Failed to create output dir: ${err?.message}`);
    return false;
  }
}

/** Write fallback scalpel config if system config doesn't exist. */
function ensureScalpelConfig(): string | null {
  // Check for system config first
  if (existsSync('/etc/scalpel/scalpel.conf')) {
    return '/etc/scalpel/scalpel.conf';
  }

  console.log('[JURI-X Scalpel] System config not found, creating fallback config');
  try {
    const configDir = join(FALLBACK_CONFIG_PATH, '..');
    if (!existsSync(configDir)) {
      mkdirSync(configDir, { recursive: true });
    }
    writeFileSync(FALLBACK_CONFIG_PATH, DEFAULT_SCALPEL_CONFIG, 'utf-8');
    console.log(`[JURI-X Scalpel] Wrote fallback config to ${FALLBACK_CONFIG_PATH}`);
    return FALLBACK_CONFIG_PATH;
  } catch (err: any) {
    console.warn(`[JURI-X Scalpel] Failed to write config: ${err?.message}`);
    return null;
  }
}

/** Compute SHA256 hash of a file. */
function computeFileHash(filePath: string): string {
  const output = runTool(`sha256sum "${filePath}" 2>/dev/null | cut -d' ' -f1`);
  return output || '';
}

/** Get file type via `file` command. */
function getFileType(filePath: string): string {
  const output = runTool(`file -b "${filePath}" 2>/dev/null`);
  return output || 'unknown';
}

// ─── Scalpel Execution ──────────────────────────────────────────────────────

/** Run scalpel to carve files from the input. */
function runScalpelCarve(filePath: string, configPath: string): { output: string; outputDir: string } | null {
  if (!ensureOutputDir()) return null;

  // Clean the output directory before carving
  try {
    const entries = readdirSync(CARVED_OUTPUT_DIR);
    if (entries.length > 0) {
      runTool(`rm -rf "${CARVED_OUTPUT_DIR}"/*`);
    }
  } catch {
    // Ignore cleanup errors
  }

  const outputPath = runTool(
    `scalpel -c "${configPath}" -o "${CARVED_OUTPUT_DIR}" "${filePath}" 2>&1`
  );

  return {
    output: outputPath || '',
    outputDir: CARVED_OUTPUT_DIR,
  };
}

/** Parse carved files from output directory. */
function parseCarvedFiles(outputDir: string, inputFileName: string): CarvedFile[] {
  const carvedFiles: CarvedFile[] = [];

  try {
    if (!existsSync(outputDir)) return carvedFiles;

    // scalpel creates subdirectories named after the input file
    const entries = readdirSync(outputDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const subDir = join(outputDir, entry.name);
      const subEntries = readdirSync(subDir, { withFileTypes: true });

      for (const subEntry of subEntries) {
        if (!subEntry.isFile()) continue;

        const filePath = join(subDir, subEntry.name);
        try {
          const fileStat = statSync(filePath);
          const fileType = getFileType(filePath);
          const fileHash = computeFileHash(filePath);

          // Try to extract offset from filename (scalpel sometimes encodes it)
          let sourceOffset = 'unknown';
          const offsetMatch = subEntry.name.match(/(\d+)-(?:\d+)/);
          if (offsetMatch) {
            sourceOffset = `0x${parseInt(offsetMatch[1], 10).toString(16)}`;
          }

          carvedFiles.push({
            name: subEntry.name,
            size: fileStat.size,
            type: fileType,
            sourceOffset,
            hash: fileHash,
          });
        } catch {
          // Skip files we can't read
        }
      }
    }
  } catch {
    // Directory doesn't exist or other error
  }

  return carvedFiles;
}

// ─── Fallback: Custom Signature Carver ──────────────────────────────────────

/** Fallback carver using `dd` and file signatures. */
function fallbackCarve(filePath: string): CarvedFile[] {
  const carvedFiles: CarvedFile[] = [];

  console.log('[JURI-X Scalpel] Using fallback custom carver');

  // Common file signatures to look for
  const signatures: { header: Buffer; footer: Buffer | null; name: string; maxSize: number }[] = [
    { header: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), footer: Buffer.from([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]), name: 'carved_png', maxSize: 10_000_000 },
    { header: Buffer.from([0xFF, 0xD8, 0xFF]), footer: Buffer.from([0xFF, 0xD9]), name: 'carved_jpg', maxSize: 10_000_000 },
    { header: Buffer.from([0x25, 0x50, 0x44, 0x46]), footer: Buffer.from([0x25, 0x25, 0x45, 0x4F, 0x46]), name: 'carved_pdf', maxSize: 50_000_000 },
    { header: Buffer.from([0x50, 0x4B, 0x03, 0x04]), footer: null, name: 'carved_zip', maxSize: 50_000_000 },
    { header: Buffer.from([0x7F, 0x45, 0x4C, 0x46]), footer: null, name: 'carved_elf', maxSize: 50_000_000 },
    { header: Buffer.from([0x4D, 0x5A]), footer: null, name: 'carved_exe', maxSize: 50_000_000 },
  ];

  if (!ensureOutputDir()) return carvedFiles;

  const fileStat = statSync(filePath);
  const fileSize = fileStat.size;
  const readSize = Math.min(fileSize, 100 * 1024 * 1024); // Read up to 100MB

  // Use strings + offset detection as a simpler fallback
  const output = runTool(`strings -t d -n 8 "${filePath}" 2>/dev/null | head -1000`);
  if (!output) return carvedFiles;

  // Look for embedded file signatures in the strings output
  for (const line of output.split('\n')) {
    const match = line.match(/^\s*(\d+)\s+(%PDF|PK|\\x89PNG|MZ|\.EXE)/i);
    if (match) {
      const offset = parseInt(match[1], 10);
      const sigType = match[2].toUpperCase();

      let type = 'unknown';
      if (sigType === '%PDF') type = 'PDF document';
      else if (sigType === 'PK') type = 'ZIP/Office archive';
      else if (sigType.includes('PNG')) type = 'PNG image';
      else if (sigType === 'MZ') type = 'PE/EXE binary';

      carvedFiles.push({
        name: `sig_at_${offset}.${type.split(' ')[0].toLowerCase()}`,
        size: 0,
        type,
        sourceOffset: `0x${offset.toString(16)}`,
        hash: '',
      });
    }
  }

  // Deduplicate by offset
  const seenOffsets = new Set<string>();
  return carvedFiles.filter(f => {
    if (seenOffsets.has(f.sourceOffset)) return false;
    seenOffsets.add(f.sourceOffset);
    return true;
  });
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousCarved(
  carvedFiles: CarvedFile[],
  inputFileType: string,
  inputFileSize: number,
): ScalpelSuspiciousFinding[] {
  const findings: ScalpelSuspiciousFinding[] = [];

  if (carvedFiles.length === 0) return findings;

  // 1. Executables carved from non-executable files — critical
  const executableTypes = ['ELF', 'PE/EXE', 'executable', 'Windows DLL'];
  const executables = carvedFiles.filter(f =>
    executableTypes.some(t => f.type.toUpperCase().includes(t.toUpperCase()))
  );

  const isInputNonExecutable = !executableTypes.some(t =>
    inputFileType.toUpperCase().includes(t.toUpperCase())
  );

  if (executables.length > 0 && isInputNonExecutable) {
    findings.push({
      category: 'hidden_executable',
      severity: 'critical',
      title: `Hidden executables found (${executables.length} file${executables.length > 1 ? 's' : ''})`,
      description: `Executable files were carved from a non-executable container. This is a strong indicator of malicious payload embedding or trojanized files.`,
      evidence: executables.map(f =>
        `${f.name} (${f.type}, offset: ${f.sourceOffset}, size: ${f.size} bytes)${f.hash ? ` [${f.hash.substring(0, 16)}...]` : ''}`
      ).join('\n'),
    });
  }

  // 2. Documents carved from binary files — highly suspicious
  const documentTypes = ['PDF', 'Microsoft Word', 'Microsoft Excel', 'Microsoft PowerPoint', 'Rich Text', 'HTML document'];
  const documents = carvedFiles.filter(f =>
    documentTypes.some(t => f.type.includes(t))
  );

  const isInputBinary = /binary|executable|ELF|PE|firmware|disk image/i.test(inputFileType);

  if (documents.length > 0 && isInputBinary) {
    findings.push({
      category: 'embedded_documents',
      severity: 'highly_suspicious',
      title: `Documents embedded in binary file (${documents.length} file${documents.length > 1 ? 's' : ''})`,
      description: `Document files were found embedded inside a binary container. This may indicate document-based malware delivery or data exfiltration staging.`,
      evidence: documents.map(f =>
        `${f.name} (${f.type}, offset: ${f.sourceOffset}, size: ${f.size} bytes)`
      ).join('\n'),
    });
  }

  // 3. Archives carved from other files — suspicious
  const archiveTypes = ['ZIP', 'RAR', '7-Zip', 'gzip', 'bzip2', 'tar archive', 'compound'];
  const archives = carvedFiles.filter(f =>
    archiveTypes.some(t => f.type.toLowerCase().includes(t.toLowerCase()))
  );

  if (archives.length > 0) {
    findings.push({
      category: 'embedded_archives',
      severity: 'suspicious',
      title: `Archives embedded in file (${archives.length} file${archives.length > 1 ? 's' : ''})`,
      description: `Archive files were carved from the input. Nested archives can indicate staged payloads or compressed malicious content.`,
      evidence: archives.map(f =>
        `${f.name} (${f.type}, offset: ${f.sourceOffset}, size: ${f.size} bytes)`
      ).join('\n'),
    });
  }

  // 4. PCAP/Network captures embedded — suspicious
  const pcapFiles = carvedFiles.filter(f =>
    /pcap|network|capture/i.test(f.type)
  );

  if (pcapFiles.length > 0) {
    findings.push({
      category: 'embedded_pcap',
      severity: 'highly_suspicious',
      title: `Network captures embedded in file (${pcapFiles.length} file${pcapFiles.length > 1 ? 's' : ''})`,
      description: `PCAP network capture files were found embedded in the input. This may indicate stolen network data or packet capture staging.`,
      evidence: pcapFiles.map(f =>
        `${f.name} (${f.type}, offset: ${f.sourceOffset}, size: ${f.size} bytes)`
      ).join('\n'),
    });
  }

  // 5. Large carved files (potential data exfiltration staging)
  const largeFiles = carvedFiles.filter(f => f.size > 10 * 1024 * 1024); // > 10MB
  if (largeFiles.length > 0) {
    const totalLargeSize = largeFiles.reduce((sum, f) => sum + f.size, 0);
    findings.push({
      category: 'large_carved_files',
      severity: 'suspicious',
      title: `Large carved files detected (${largeFiles.length} files, ${formatSize(totalLargeSize)} total)`,
      description: `Several large files were carved from the input, which may indicate staged data for exfiltration.`,
      evidence: largeFiles.map(f =>
        `${f.name} (${f.type}, ${formatSize(f.size)}, offset: ${f.sourceOffset})`
      ).join('\n'),
    });
  }

  // 6. High number of carved files — suspicious
  if (carvedFiles.length > 50) {
    findings.push({
      category: 'high_carve_count',
      severity: 'suspicious',
      title: `Unusually high number of carved files (${carvedFiles.length})`,
      description: `A large number of files were successfully carved from the input, suggesting a complex binary container or a packed/stegged file.`,
      evidence: `Total carved: ${carvedFiles.length} files, Input size: ${formatSize(inputFileSize)}`,
    });
  }

  return findings;
}

/** Format file size for display. */
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function carveWithScalpel(filePath: string): ScalpelResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      carvedFiles: [],
      totalCarved: 0,
      totalRecoveredSize: 0,
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];
  let toolUsed = 'none';
  let carvedFiles: CarvedFile[] = [];

  console.log(`[JURI-X Scalpel] Analyzing ${fileName} (${fileStat.size} bytes)`);

  // Get input file type for suspicious detection
  const inputFileType = getFileType(filePath);
  console.log(`[JURI-X Scalpel] Input file type: ${inputFileType}`);

  if (isScalpelAvailable()) {
    console.log('[JURI-X Scalpel] scalpel is available, running carve...');

    // Get or create config
    const configPath = ensureScalpelConfig();
    if (!configPath) {
      errors.push('Failed to create scalpel configuration');
      carvedFiles = fallbackCarve(filePath);
      if (carvedFiles.length > 0) toolUsed = 'fallback_carver';
    } else {
      // Run scalpel
      const result = runScalpelCarve(filePath, configPath);
      if (result) {
        if (result.output) {
          console.log(`[JURI-X Scalpel] scalpel output: ${result.output.substring(0, 300)}`);
        }

        // Parse carved files
        carvedFiles = parseCarvedFiles(result.outputDir, fileName);
        if (carvedFiles.length > 0) {
          toolUsed = 'scalpel';
          console.log(`[JURI-X Scalpel] Carved: ${carvedFiles.length} files`);
        } else {
          console.log('[JURI-X Scalpel] scalpel: no files carved');
          // If scalpel didn't find anything, still mark as used
          toolUsed = 'scalpel';
        }
      }
    }
  } else {
    console.log('[JURI-X Scalpel] scalpel not available, using fallback carver');
    carvedFiles = fallbackCarve(filePath);
    if (carvedFiles.length > 0) {
      toolUsed = 'fallback_carver';
      console.log(`[JURI-X Scalpel] Fallback carved: ${carvedFiles.length} files`);
    }
  }

  // Calculate total recovered size
  const totalRecoveredSize = carvedFiles.reduce((sum, f) => sum + f.size, 0);

  // Detect suspicious findings
  const suspiciousFindings = detectSuspiciousCarved(carvedFiles, inputFileType, fileStat.size);

  console.log(`[JURI-X Scalpel] Analysis complete: ${carvedFiles.length} files carved (${formatSize(totalRecoveredSize)}), ${suspiciousFindings.length} findings`);

  return {
    available: toolUsed !== 'none',
    filePath,
    carvedFiles,
    totalCarved: carvedFiles.length,
    totalRecoveredSize,
    suspiciousFindings,
    toolUsed,
    errors,
  };
}
