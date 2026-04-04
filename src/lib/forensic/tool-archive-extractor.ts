/**
 * tool-archive-extractor.ts — Archive Analysis
 *
 * Uses: 7z, unzip, tar, gzip, unrar for archive extraction and analysis.
 * Supports: .zip, .7z, .tar.gz, .tar, .rar, .gz
 *
 * Extracts archives to /tmp/recon-x/extracted/{caseId}/,
 * hashes each file, detects suspicious contents.
 */

import { execSync } from 'child_process';
import { existsSync, statSync, readdirSync } from 'fs';
import { join, extname, basename } from 'path';
import { createHash } from 'crypto';
import { mkdirSync, readFileSync } from 'fs';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ExtractedFile {
  name: string;
  relativePath: string;
  fullPath: string;
  size: number;
  hash: string;
  type: string;
  suspicious: boolean;
  suspiciousReasons: string[];
  extractedAt: string;
}

export interface ArchiveSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface ArchiveAnalysisResult {
  available: boolean;
  archivePath: string;
  archiveType: string;
  archiveSize: number;
  archiveHash: string;
  extractedFiles: ExtractedFile[];
  totalExtracted: number;
  totalSize: number;
  suspiciousCount: number;
  suspiciousFindings: ArchiveSuspiciousFinding[];
  errors: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 60_000,
};

const EXTRACT_BASE = '/tmp/recon-x/extracted';

function runTool(cmd: string): string | null {
  try {
    const out = execSync(cmd, EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found')) {
      console.warn(`[JURI-X Archive] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X Archive] Command failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Calculate SHA-256 hash of a file. */
function hashFile(filePath: string): string {
  try {
    const data = readFileSync(filePath);
    return `sha256:${createHash('sha256').update(data).digest('hex')}`;
  } catch {
    return 'error';
  }
}

/** Detect archive type from file extension. */
function detectArchiveType(fileName: string): string {
  const ext = extname(fileName).toLowerCase();
  const name = fileName.toLowerCase();

  if (ext === '.zip') return 'zip';
  if (ext === '.7z') return '7z';
  if (ext === '.rar' || ext === '.r00') return 'rar';
  if (ext === '.gz' && name.endsWith('.tar.gz')) return 'tar.gz';
  if (ext === '.tgz') return 'tar.gz';
  if (ext === '.tar') return 'tar';
  if (ext === '.gz') return 'gz';
  if (ext === '.bz2' && name.endsWith('.tar.bz2')) return 'tar.bz2';
  if (ext === '.tbz2') return 'tar.bz2';
  if (ext === '.xz' && name.endsWith('.tar.xz')) return 'tar.xz';
  if (ext === '.txz') return 'tar.xz';
  if (ext === '.lzma') return 'tar.lzma';
  if (ext === '.cab') return 'cab';
  if (ext === '.iso') return 'iso';

  return 'unknown';
}

/** Classify a file as suspicious based on name and extension. */
function classifySuspicious(fileName: string): { suspicious: boolean; reasons: string[] } {
  const lower = fileName.toLowerCase();
  const reasons: string[] = [];

  // Executable extensions
  const exeExts = ['.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.wsf', '.hta', '.scr', '.msi', '.com', '.pif'];
  const scriptExts = ['.sh', '.py', '.rb', '.pl', '.php', '.jsp', '.asp', '.aspx'];
  const dangerousExts = ['.jar', '.class', '.war', '.apk', '.elf', '.so', '.dylib'];

  if (exeExts.some(e => lower.endsWith(e))) {
    reasons.push('Windows executable');
  }
  if (scriptExts.some(e => lower.endsWith(e))) {
    reasons.push('Script file');
  }
  if (dangerousExts.some(e => lower.endsWith(e))) {
    reasons.push('Binary/library file');
  }

  // Suspicious names
  const suspiciousNames = [
    /password/i, /credential/i, /key/i, /secret/i, /token/i,
    /shadow/i, /sam/i, /ntds/i, /hives/i,
    /backdoor/i, /shell/i, /rootkit/i, /keylog/i, /inject/i,
    /payload/i, /exploit/i, /malware/i, /trojan/i, /ransom/i,
    /miner/i, /crypt/i,
    /\.ssh\//i, /id_rsa/i, /id_dsa/i,
  ];

  for (const pattern of suspiciousNames) {
    if (pattern.test(fileName)) {
      reasons.push(`Suspicious filename pattern: ${pattern.source}`);
    }
  }

  // Hidden files
  if (fileName.startsWith('.') && !['.gitignore', '.env.example', '.htaccess'].includes(lower)) {
    reasons.push('Hidden file');
  }

  // Double extensions (e.g., document.pdf.exe)
  const parts = fileName.split('.');
  const extensions = parts.slice(1);
  if (extensions.length >= 2) {
    const lastTwo = extensions.slice(-2);
    if (lastTwo[0] !== lastTwo[1] && exeExts.includes(`.${lastTwo[1]}`)) {
      reasons.push(`Double extension detected: ${lastTwo[0]}.${lastTwo[1]}`);
    }
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
  };
}

/** Detect file type using the `file` command. */
function detectFileType(filePath: string): string {
  const output = runTool(`file -b "${filePath}"`);
  return output || 'unknown';
}

/** Recursively walk a directory and collect all files. */
function walkDirectory(dir: string, relativeBase: string = ''): { fullPath: string; relativePath: string }[] {
  const results: { fullPath: string; relativePath: string }[] = [];

  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      const relativePath = relativeBase ? `${relativeBase}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        results.push(...walkDirectory(fullPath, relativePath));
      } else {
        results.push({ fullPath, relativePath });
      }
    }
  } catch {
    /* permission denied or other error */
  }

  return results;
}

// ─── Extraction Functions ───────────────────────────────────────────────────

function extractWith7z(archivePath: string, outputDir: string): boolean {
  const output = runTool(`7z x -y -o"${outputDir}" "${archivePath}" 2>&1`);
  return output !== null;
}

function extractWithUnzip(archivePath: string, outputDir: string): boolean {
  const output = runTool(`unzip -o -q "${archivePath}" -d "${outputDir}" 2>&1`);
  return output !== null;
}

function extractWithTar(archivePath: string, outputDir: string): boolean {
  const output = runTool(`tar xf "${archivePath}" -C "${outputDir}" 2>&1`);
  return output !== null;
}

function extractWithGunzip(archivePath: string, outputDir: string): boolean {
  const output = runTool(`gunzip -k -c "${archivePath}" > "${outputDir}/${basename(archivePath).replace(/\.gz$/, '')}" 2>&1`);
  return output !== null;
}

function extractWithUnrar(archivePath: string, outputDir: string): boolean {
  const output = runTool(`unrar x -y -o+ "${archivePath}" "${outputDir}/" 2>&1`);
  return output !== null;
}

/** Extract an archive using the best available tool. */
function extractArchive(archivePath: string, outputDir: string, archiveType: string): boolean {
  // Create output directory
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  // Try 7z first (handles most formats: zip, 7z, rar, tar, gz, etc.)
  if (extractWith7z(archivePath, outputDir)) {
    console.log(`[JURI-X Archive] Extracted with 7z`);
    return true;
  }

  // Try format-specific tools
  switch (archiveType) {
    case 'zip':
      if (extractWithUnzip(archivePath, outputDir)) {
        console.log(`[JURI-X Archive] Extracted with unzip`);
        return true;
      }
      break;

    case 'rar':
      if (extractWithUnrar(archivePath, outputDir)) {
        console.log(`[JURI-X Archive] Extracted with unrar`);
        return true;
      }
      // unrar failed, 7z already tried
      break;

    case 'tar':
    case 'tar.gz':
    case 'tar.bz2':
    case 'tar.xz':
      if (extractWithTar(archivePath, outputDir)) {
        console.log(`[JURI-X Archive] Extracted with tar`);
        return true;
      }
      break;

    case 'gz':
      if (extractWithGunzip(archivePath, outputDir)) {
        console.log(`[JURI-X Archive] Extracted with gunzip`);
        return true;
      }
      break;
  }

  // If 7z wasn't tried yet (it should have been), try it now
  if (archiveType !== 'unknown') {
    console.warn(`[JURI-X Archive] All extraction methods failed for ${basename(archivePath)}`);
  }

  return false;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function extractAndAnalyzeArchive(
  filePath: string,
  caseId: string,
): ArchiveAnalysisResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      archivePath: filePath,
      archiveType: 'unknown',
      archiveSize: 0,
      archiveHash: 'error',
      extractedFiles: [],
      totalExtracted: 0,
      totalSize: 0,
      suspiciousCount: 0,
      suspiciousFindings: [],
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const archiveName = basename(filePath);
  const archiveType = detectArchiveType(archiveName);
  const archiveHash = hashFile(filePath);
  const outputDir = join(EXTRACT_BASE, caseId, archiveName.replace(/[^\w.-]/g, '_'));

  console.log(`[JURI-X Archive] Analyzing ${archiveName} (${fileStat.size} bytes, type: ${archiveType})`);

  if (archiveType === 'unknown') {
    return {
      available: false,
      archivePath: filePath,
      archiveType: 'unknown',
      archiveSize: fileStat.size,
      archiveHash,
      extractedFiles: [],
      totalExtracted: 0,
      totalSize: 0,
      suspiciousCount: 0,
      suspiciousFindings: [],
      errors: [`Unsupported archive format: ${extname(archiveName)}`],
    };
  }

  // Check if any extraction tools are available
  const toolsAvailable = [
    runTool('which 7z 2>/dev/null'),
    runTool('which unzip 2>/dev/null'),
    runTool('which tar 2>/dev/null'),
    runTool('which gunzip 2>/dev/null'),
    runTool('which unrar 2>/dev/null'),
  ].some(t => t !== null);

  if (!toolsAvailable) {
    return {
      available: false,
      archivePath: filePath,
      archiveType,
      archiveSize: fileStat.size,
      archiveHash,
      extractedFiles: [],
      totalExtracted: 0,
      totalSize: 0,
      suspiciousCount: 0,
      suspiciousFindings: [],
      errors: ['No archive extraction tools found. Install p7zip-full, unzip, or tar.'],
    };
  }

  // Extract
  const success = extractArchive(filePath, outputDir, archiveType);
  if (!success) {
    return {
      available: false,
      archivePath: filePath,
      archiveType,
      archiveSize: fileStat.size,
      archiveHash,
      extractedFiles: [],
      totalExtracted: 0,
      totalSize: 0,
      suspiciousCount: 0,
      suspiciousFindings: [],
      errors: ['Extraction failed. The archive may be corrupted or password-protected.'],
    };
  }

  // Walk extracted directory and analyze each file
  const allFiles = walkDirectory(outputDir);
  const extractedFiles: ExtractedFile[] = [];
  let totalSize = 0;
  let suspiciousCount = 0;
  const suspiciousFindings: ArchiveSuspiciousFinding[] = [];
  let fileId = 0;

  for (const { fullPath, relativePath } of allFiles) {
    try {
      const fileStat = statSync(fullPath);
      if (fileStat.size === 0 && !relativePath.includes('.')) continue; // skip empty files without extensions

      const fileName = basename(fullPath);
      const hash = hashFile(fullPath);
      const fileType = detectFileType(fullPath);
      const { suspicious, reasons } = classifySuspicious(relativePath);

      const extractedFile: ExtractedFile = {
        name: fileName,
        relativePath,
        fullPath,
        size: fileStat.size,
        hash,
        type: fileType,
        suspicious,
        suspiciousReasons: reasons,
        extractedAt: new Date().toISOString(),
      };

      extractedFiles.push(extractedFile);
      totalSize += fileStat.size;

      if (suspicious) {
        suspiciousCount++;
        const severity = reasons.some(r =>
          r.includes('executable') || r.includes('backdoor') || r.includes('rootkit') || r.includes('keylog') || r.includes('Double extension')
        ) ? 'critical' as const
          : reasons.some(r =>
            r.includes('Script') || r.includes('password') || r.includes('credential') || r.includes('secret') || r.includes('Hidden')
          ) ? 'highly_suspicious' as const
            : 'suspicious' as const;

        suspiciousFindings.push({
          category: 'suspicious_archive_content',
          severity,
          title: `Suspicious file in archive: ${relativePath}`,
          description: `File ${relativePath} in archive ${archiveName} appears suspicious. Reasons: ${reasons.join('; ')}. Type: ${fileType}. Size: ${fileStat.size} bytes.`,
          evidence: `${relativePath} (${fileType})`,
        });
      }
    } catch {
      console.warn(`[JURI-X Archive] Error processing extracted file: ${relativePath}`);
    }
  }

  // Check for nested archives
  const nestedArchives = extractedFiles.filter(f => {
    const ext = extname(f.name).toLowerCase();
    return ['.zip', '.7z', '.rar', '.tar', '.gz', '.bz2'].includes(ext);
  });
  if (nestedArchives.length > 0) {
    suspiciousFindings.push({
      category: 'nested_archive',
      severity: 'suspicious',
      title: `Nested archives detected (${nestedArchives.length})`,
      description: `Archive ${archiveName} contains ${nestedArchives.length} nested archives: ${nestedArchives.map(f => f.relativePath).join(', ')}. This is commonly used in malware delivery or obfuscation.`,
      evidence: nestedArchives.map(f => f.relativePath).join(', '),
    });
  }

  // Check for password-protected content indicators
  const passwordIndicators = extractedFiles.filter(f =>
    f.name.toLowerCase().includes('password') || f.name.toLowerCase().includes('readme') || f.name.toLowerCase().includes('decrypt')
  );
  if (passwordIndicators.length > 0 && archiveType === 'zip') {
    suspiciousFindings.push({
      category: 'possible_encryption',
      severity: 'suspicious',
      title: 'Archive may contain password-protected content',
      description: `Found ${passwordIndicators.length} files with names suggesting encryption instructions or password files.`,
      evidence: passwordIndicators.map(f => f.relativePath).join(', '),
    });
  }

  console.log(`[JURI-X Archive] Analysis complete: ${extractedFiles.length} files extracted (${totalSize} bytes), ${suspiciousCount} suspicious`);

  return {
    available: true,
    archivePath: filePath,
    archiveType,
    archiveSize: fileStat.size,
    archiveHash,
    extractedFiles,
    totalExtracted: extractedFiles.length,
    totalSize,
    suspiciousCount,
    suspiciousFindings,
    errors: [],
  };
}
