/**
 * tool-binwalk.ts — Binary/Firmware Analysis
 *
 * Uses: binwalk for firmware and binary analysis.
 * Extracts embedded file signatures, detects entropy anomalies,
 * and identifies embedded filesystems, compressed sections, and more.
 *
 * Falls back to `file` command and manual signature scanning if binwalk is not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync, openSync, readSync, closeSync, readdirSync } from 'fs';
import { basename, join } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface BinwalkSignature {
  offset: number;
  description: string;
  hexSignature: string;
  length: number;
  extractedSize: string;
  isValid: boolean;
}

export interface BinwalkEntropyEntry {
  offset: number;
  blockSize: number;
  entropy: number;
  level: 'low' | 'medium' | 'high' | 'very_high';
}

export interface BinwalkEmbeddedFile {
  offset: number;
  size: string;
  description: string;
  name: string;
  type: string;
}

export interface BinwalkSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface BinwalkResult {
  available: boolean;
  filePath: string;
  signatures: BinwalkSignature[];
  embeddedFiles: BinwalkEmbeddedFile[];
  entropyAnalysis: {
    average: number;
    level: 'low' | 'medium' | 'high' | 'very_high';
    blocks: BinwalkEntropyEntry[];
    highEntropyRegions: BinwalkEntropyEntry[];
  };
  firmwareMetadata: {
    model: string;
    vendor: string;
    architecture: string;
    endian: string;
    bootloader: string;
  };
  suspiciousFindings: BinwalkSuspiciousFinding[];
  toolUsed: string;
  errors: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 60_000,
};

const LONG_EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 120_000,
};

function runTool(cmd: string, longTimeout = false): string | null {
  try {
    const out = execSync(cmd, longTimeout ? LONG_EXEC_OPTIONS : EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found')) {
      console.warn(`[JURI-X Binwalk] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X Binwalk] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Calculate Shannon entropy of a buffer. */
function calculateEntropy(buffer: Buffer): number {
  const freq = new Map<number, number>();
  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    freq.set(byte, (freq.get(byte) || 0) + 1);
  }
  let entropy = 0;
  const len = buffer.length;
  if (len === 0) return 0;
  const values = Array.from(freq.values());
  for (const count of values) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

function classifyEntropy(entropy: number): 'low' | 'medium' | 'high' | 'very_high' {
  if (entropy < 5) return 'low';
  if (entropy < 6.5) return 'medium';
  if (entropy < 7.5) return 'high';
  return 'very_high';
}

// ─── binwalk Integration ────────────────────────────────────────────────────

function runBinwalkScan(filePath: string): { signatures: BinwalkSignature[]; output: string } {
  const signatures: BinwalkSignature[] = [];

  const output = runTool(`binwalk "${filePath}" 2>/dev/null`, true);
  if (!output) return { signatures, output: '' };

  for (const line of output.split('\n')) {
    // binwalk output format:
    // DECIMAL       HEX         DESCRIPTION
    // 0             0x0         DLOB firmware header, header size: 28 bytes, CRC32 "0x00000000" checksum
    // 1024          0x400       gzip compressed data, default compression
    const match = line.match(/^(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+)$/);
    if (match) {
      const decimalOffset = parseInt(match[1], 10);
      const hexOffset = match[2];
      const description = match[3].trim();

      // Extract hex signature if present
      let hexSignature = '';
      const sigMatch = description.match(/signature\s+["']?([0-9A-Fa-f]+)["']?/);
      if (sigMatch) hexSignature = sigMatch[1];

      // Extract size if present
      let extractedSize = '';
      const sizeMatch = description.match(/(\d+)\s*bytes/);
      if (sizeMatch) extractedSize = `${sizeMatch[1]} bytes`;

      signatures.push({
        offset: decimalOffset,
        description,
        hexSignature,
        length: description.length,
        extractedSize,
        isValid: true,
      });
    }
  }

  return { signatures, output };
}

/** Run binwalk entropy analysis. */
function runBinwalkEntropy(filePath: string): BinwalkEntropyEntry[] {
  const entries: BinwalkEntropyEntry[] = [];

  const output = runTool(`binwalk -E "${filePath}" 2>/dev/null`, true);
  if (!output) return entries;

  // Parse entropy chart output (binwalk -E produces ASCII chart)
  // We'll also do our own entropy calculation
  return entries;
}

/** Run binwalk extraction. */
function runBinwalkExtract(filePath: string, outputDir: string): BinwalkEmbeddedFile[] {
  const files: BinwalkEmbeddedFile[] = [];

  const output = runTool(`binwalk -e -C "${outputDir}" "${filePath}" 2>&1`, true);
  if (!output) return files;

  // Parse extraction output
  try {
    const extractedDir = outputDir.replace(/\/$/, '') + '_' + basename(filePath);
    const entries = readdirSync(extractedDir, { withFileTypes: true, recursive: true }) as any[];

    for (const entry of entries) {
      if (entry.isFile()) {
        const entryPath = entry.path || entry.name;
        const name = basename(entryPath);
        const type = runTool(`file -b "${entryPath}" 2>/dev/null`) || 'unknown';
        const fileStat = statSync(entryPath);

        files.push({
          offset: 0,
          size: `${fileStat.size} bytes`,
          description: type,
          name,
          type: type.split(',')[0].trim(),
        });
      }
    }
  } catch {
    // Directory doesn't exist or extraction failed
  }

  return files;
}

// ─── Custom Entropy Analysis ────────────────────────────────────────────────

function analyzeEntropy(filePath: string): {
  average: number;
  level: 'low' | 'medium' | 'high' | 'very_high';
  blocks: BinwalkEntropyEntry[];
  highEntropyRegions: BinwalkEntropyEntry[];
} {
  const BLOCK_SIZE = 1024; // 1KB blocks
  const MAX_BLOCKS = 10000; // Limit analysis

  const fd = openSync(filePath, 'r');
  try {
    const fileStat = statSync(filePath);
    const totalBlocks = Math.min(Math.ceil(fileStat.size / BLOCK_SIZE), MAX_BLOCKS);
    const blocks: BinwalkEntropyEntry[] = [];
    let totalEntropy = 0;

    const buffer = Buffer.alloc(BLOCK_SIZE);

    for (let i = 0; i < totalBlocks; i++) {
      const bytesRead = readSync(fd, buffer, 0, BLOCK_SIZE, null);
      if (bytesRead === 0) break;

      const dataSlice = bytesRead < BLOCK_SIZE ? buffer.subarray(0, bytesRead) : buffer;
      const entropy = calculateEntropy(dataSlice);
      const level = classifyEntropy(entropy);

      blocks.push({
        offset: i * BLOCK_SIZE,
        blockSize: bytesRead,
        entropy: Math.round(entropy * 1000) / 1000,
        level,
      });

      totalEntropy += entropy;
    }

    const average = blocks.length > 0 ? totalEntropy / blocks.length : 0;
    const highEntropyRegions = blocks.filter(b => b.entropy > 7.0);

    return {
      average: Math.round(average * 1000) / 1000,
      level: classifyEntropy(average),
      blocks,
      highEntropyRegions,
    };
  } finally {
    closeSync(fd);
  }
}

// ─── Custom Signature Scan (fallback) ───────────────────────────────────────

function scanKnownSignatures(filePath: string): BinwalkSignature[] {
  const signatures: BinwalkSignature[] = [];

  // Common binary/firmware signatures
  const knownSigs: { bytes: Buffer; description: string }[] = [
    { bytes: Buffer.from([0x1F, 0x8B, 0x08]), description: 'gzip compressed data' },
    { bytes: Buffer.from([0x42, 0x5A, 0x68]), description: 'bzip2 compressed data' },
    { bytes: Buffer.from([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]), description: 'xz compressed data' },
    { bytes: Buffer.from([0x50, 0x4B, 0x03, 0x04]), description: 'ZIP archive / JAR / APK' },
    { bytes: Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]), description: '7-Zip archive' },
    { bytes: Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]), description: 'RAR archive' },
    { bytes: Buffer.from([0x25, 0x50, 0x44, 0x46]), description: 'PDF document' },
    { bytes: Buffer.from([0x7F, 0x45, 0x4C, 0x46]), description: 'ELF binary' },
    { bytes: Buffer.from([0x4D, 0x5A]), description: 'PE/EXE binary (Windows)' },
    { bytes: Buffer.from([0x89, 0x50, 0x4E, 0x47]), description: 'PNG image' },
    { bytes: Buffer.from([0xFF, 0xD8, 0xFF]), description: 'JPEG image' },
    { bytes: Buffer.from([0x47, 0x49, 0x46, 0x38]), description: 'GIF image' },
    { bytes: Buffer.from([0x53, 0x51, 0x4C, 0x69]), description: 'SQLite database' },
    { bytes: Buffer.from([0xD4, 0xC3, 0xB2, 0xA1]), description: 'PCAP network capture' },
    { bytes: Buffer.from([0xD0, 0xCF, 0x11, 0xE0]), description: 'MS Compound Document (OLE)' },
    { bytes: Buffer.from([0xED, 0xAB, 0xEE, 0xDB]), description: 'Linux kernel image (uImage)' },
    { bytes: Buffer.from([0x27, 0x05, 0x19, 0x56]), description: 'u-boot legacy image' },
    { bytes: Buffer.from([0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70]), description: 'MP4 video (offset 4)' },
    { bytes: Buffer.from([0x52, 0x49, 0x46, 0x46]), description: 'WebP/RIFF container' },
    { bytes: Buffer.from([0x1A, 0x45, 0xDF, 0xA3]), description: 'MKV/WebM/Matroska container' },
    { bytes: Buffer.from([0x49, 0x44, 0x33]), description: 'MP3 audio (ID3 tag)' },
    { bytes: Buffer.from([0x52, 0x49, 0x46, 0x46]), description: 'WAV/AVI container' },
    { bytes: Buffer.from([0x43, 0x52, 0x46, 0x49]), description: 'Cisco firmware header' },
    { bytes: Buffer.from([0xD0, 0x0D, 0xFE, 0xED]), description: 'Android boot image' },
    { bytes: Buffer.from([0x3A, 0x29, 0x06, 0x18, 0x56, 0xE4, 0x8F, 0x85]), description: 'Intel ME firmware' },
  ];

  const fd = openSync(filePath, 'r');
  try {
    const fileStat = statSync(filePath);
    const bufferSize = Math.min(fileStat.size, 10 * 1024 * 1024); // Read up to 10MB
    const buffer = Buffer.alloc(bufferSize);
    const bytesRead = readSync(fd, buffer, 0, bufferSize, 0);
    const data = buffer.subarray(0, bytesRead);

    for (const sig of knownSigs) {
      const offset = data.indexOf(sig.bytes);
      if (offset !== -1) {
        signatures.push({
          offset,
          description: sig.description,
          hexSignature: sig.bytes.toString('hex'),
          length: sig.bytes.length,
          extractedSize: '',
          isValid: true,
        });
      }
    }

    // Also scan for signatures every 512 bytes (for firmware with multiple sections)
    const SCAN_STEP = 512;
    for (let pos = SCAN_STEP; pos < bytesRead; pos += SCAN_STEP) {
      for (const sig of knownSigs) {
        const slice = data.subarray(pos, Math.min(pos + sig.bytes.length + 32, bytesRead));
        const offset = slice.indexOf(sig.bytes);
        if (offset !== -1) {
          const absOffset = pos + offset;
          // Only add if not too close to existing signature
          if (!signatures.some(s => Math.abs(s.offset - absOffset) < sig.bytes.length)) {
            signatures.push({
              offset: absOffset,
              description: sig.description,
              hexSignature: sig.bytes.toString('hex'),
              length: sig.bytes.length,
              extractedSize: '',
              isValid: true,
            });
          }
        }
      }
    }

  } finally {
    closeSync(fd);
  }

  // Sort by offset
  signatures.sort((a, b) => a.offset - b.offset);

  return signatures;
}

// ─── Firmware Metadata Extraction ───────────────────────────────────────────

function extractFirmwareMetadata(filePath: string): BinwalkResult['firmwareMetadata'] {
  const metadata: BinwalkResult['firmwareMetadata'] = {
    model: '',
    vendor: '',
    architecture: '',
    endian: '',
    bootloader: '',
  };

  // Try to extract firmware info from strings
  const stringsOutput = runTool(`strings -n 8 "${filePath}" 2>/dev/null | head -200`);

  if (stringsOutput) {
    // Look for common firmware strings
    const vendorPatterns = [
      { pattern: /Cisco/i, vendor: 'Cisco' },
      { pattern: /Linksys/i, vendor: 'Linksys' },
      { pattern: /Netgear/i, vendor: 'Netgear' },
      { pattern: /TP-Link/i, vendor: 'TP-Link' },
      { pattern: /D-Link/i, vendor: 'D-Link' },
      { pattern: /Asus/i, vendor: 'ASUS' },
      { pattern: /Belkin/i, vendor: 'Belkin' },
      { pattern: /Ubiquiti/i, vendor: 'Ubiquiti' },
      { pattern: /MikroTik/i, vendor: 'MikroTik' },
      { pattern: /OpenWrt/i, vendor: 'OpenWrt' },
      { pattern: /DD-WRT/i, vendor: 'DD-WRT' },
      { pattern: /BusyBox/i, vendor: 'BusyBox' },
      { pattern: /Linux kernel/i, vendor: 'Linux' },
      { pattern: /Android/i, vendor: 'Android' },
      { pattern: /Qualcomm/i, vendor: 'Qualcomm' },
      { pattern: /Broadcom/i, vendor: 'Broadcom' },
      { pattern: /Marvell/i, vendor: 'Marvell' },
      { pattern: /Realtek/i, vendor: 'Realtek' },
      { pattern: /Intel/i, vendor: 'Intel' },
      { pattern: /ARM/i, vendor: 'ARM' },
      { pattern: /MIPS/i, vendor: 'MIPS' },
    ];

    for (const vp of vendorPatterns) {
      if (vp.pattern.test(stringsOutput)) {
        metadata.vendor = vp.vendor;
        break;
      }
    }

    // Architecture detection
    const archPatterns = [
      { pattern: /ARM(?:v[789])/i, arch: 'ARM' },
      { pattern: /MIPS(?:24K|34K|74K)?/i, arch: 'MIPS' },
      { pattern: /x86|i[36]86/i, arch: 'x86' },
      { pattern: /x86_64|x64|amd64/i, arch: 'x86_64' },
      { pattern: /aarch64|arm64/i, arch: 'ARM64' },
      { pattern: /PowerPC|PPC/i, arch: 'PowerPC' },
      { pattern: /AVR/i, arch: 'AVR' },
    ];

    for (const ap of archPatterns) {
      if (ap.pattern.test(stringsOutput)) {
        metadata.architecture = ap.arch;
        break;
      }
    }

    // Endian detection
    if (/big endian|BE\b/i.test(stringsOutput)) metadata.endian = 'big';
    else if (/little endian|LE\b/i.test(stringsOutput)) metadata.endian = 'little';

    // Bootloader detection
    if (/U-Boot|u-boot/i.test(stringsOutput)) metadata.bootloader = 'U-Boot';
    else if (/RedBoot/i.test(stringsOutput)) metadata.bootloader = 'RedBoot';
    else if (/CFE|Common Firmware/i.test(stringsOutput)) metadata.bootloader = 'CFE';
    else if (/GRUB/i.test(stringsOutput)) metadata.bootloader = 'GRUB';

    // Model detection
    const modelPatterns = [
      /model\s*[:=]\s*["']?([A-Za-z0-9_\- .]+)["']?/i,
      /product\s*[:=]\s*["']?([A-Za-z0-9_\- .]+)["']?/i,
      /machine\s*[:=]\s*["']?([A-Za-z0-9_\- .]+)["']?/i,
    ];
    for (const mp of modelPatterns) {
      const match = stringsOutput.match(mp);
      if (match && match[1].length > 3 && match[1].length < 60) {
        metadata.model = match[1].trim();
        break;
      }
    }
  }

  // Also use file command
  const fileOutput = runTool(`file -b "${filePath}" 2>/dev/null`);
  if (fileOutput) {
    if (!metadata.vendor && /ARM|MIPS|x86|PowerPC/i.test(fileOutput)) {
      if (/ARM/i.test(fileOutput)) metadata.architecture = metadata.architecture || 'ARM';
    }
    if (!metadata.endian) {
      if (/little endian/i.test(fileOutput)) metadata.endian = 'little';
      else if (/big endian/i.test(fileOutput)) metadata.endian = 'big';
    }
  }

  return metadata;
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousBinwalk(
  signatures: BinwalkSignature[],
  entropyResult: BinwalkResult['entropyAnalysis'],
  firmwareMeta: BinwalkResult['firmwareMetadata'],
  fileSize: number,
): BinwalkSuspiciousFinding[] {
  const findings: BinwalkSuspiciousFinding[] = [];

  // 1. High entropy regions (packed/encrypted sections)
  if (entropyResult.highEntropyRegions.length > 0) {
    const highEntropyTotal = entropyResult.highEntropyRegions.reduce((sum, b) => sum + b.blockSize, 0);
    const percentage = (highEntropyTotal / fileSize) * 100;

    if (percentage > 50) {
      findings.push({
        category: 'encrypted_content',
        severity: 'highly_suspicious',
        title: `Large encrypted/packed section detected (${percentage.toFixed(1)}%)`,
        description: `${entropyResult.highEntropyRegions.length} blocks with very high entropy detected, covering ${percentage.toFixed(1)}% of the file. This strongly suggests encrypted or packed content that cannot be analyzed.`,
        evidence: `Average entropy: ${entropyResult.average}, High entropy blocks: ${entropyResult.highEntropyRegions.length}/${entropyResult.blocks.length}`,
      });
    } else if (percentage > 10) {
      findings.push({
        category: 'packed_content',
        severity: 'suspicious',
        title: `Packed section detected (${percentage.toFixed(1)}% of file)`,
        description: `${entropyResult.highEntropyRegions.length} high-entropy blocks covering ${percentage.toFixed(1)}% of the file. May contain packed or compressed sections.`,
        evidence: `High entropy regions at offsets: ${entropyResult.highEntropyRegions.slice(0, 5).map(b => `0x${b.offset.toString(16)}`).join(', ')}`,
      });
    }
  }

  // 2. Executables embedded in firmware
  const exeSignatures = signatures.filter(s =>
    /ELF|PE\/EXE|MZ|script/i.test(s.description)
  );
  if (exeSignatures.length > 0) {
    findings.push({
      category: 'embedded_executables',
      severity: 'suspicious',
      title: `${exeSignatures.length} executable(s) embedded in binary`,
      description: `Found ${exeSignatures.length} embedded executables: ${exeSignatures.slice(0, 5).map(s => s.description).join(', ')}`,
      evidence: exeSignatures.map(s => `0x${s.offset.toString(16)}: ${s.description}`).join('\n'),
    });
  }

  // 3. Archives embedded in binary (possible second stage)
  const archiveSignatures = signatures.filter(s =>
    /zip|rar|7z|gzip|bzip2|xz|tar/i.test(s.description)
  );
  if (archiveSignatures.length > 1) {
    findings.push({
      category: 'nested_archives',
      severity: 'suspicious',
      title: `${archiveSignatures.length} archive(s) embedded in binary`,
      description: `Multiple embedded archives may indicate staged payloads or firmware update mechanisms: ${archiveSignatures.slice(0, 5).map(s => s.description).join(', ')}`,
      evidence: archiveSignatures.map(s => `0x${s.offset.toString(16)}: ${s.description}`).join('\n'),
    });
  }

  // 4. Filesystem signatures
  const fsSignatures = signatures.filter(s =>
    /squashfs|cramfs|jffs2|ubi|ext[234]|fat|ntfs|hfs|romfs/i.test(s.description)
  );
  if (fsSignatures.length > 0) {
    findings.push({
      category: 'filesystem',
      severity: 'benign',
      title: `${fsSignatures.length} filesystem(s) detected`,
      description: `Embedded filesystems found: ${fsSignatures.map(s => s.description).join(', ')}. These may contain the firmware's root filesystem.`,
      evidence: fsSignatures.map(s => `0x${s.offset.toString(16)}: ${s.description}`).join('\n'),
    });
  }

  // 5. OpenSSL keys/certificates
  const cryptoSignatures = signatures.filter(s =>
    /RSA |DSA |certificate|private key/i.test(s.description)
  );
  if (cryptoSignatures.length > 0) {
    findings.push({
      category: 'cryptographic_material',
      severity: 'highly_suspicious',
      title: `Cryptographic material detected (${cryptoSignatures.length} item(s))`,
      description: `Found RSA keys, certificates, or other cryptographic material embedded in the binary. These should be extracted for further analysis.`,
      evidence: cryptoSignatures.map(s => `0x${s.offset.toString(16)}: ${s.description}`).join('\n'),
    });
  }

  // 6. Very small file with high average entropy (potential packed payload)
  if (fileSize < 500_000 && entropyResult.level === 'very_high') {
    findings.push({
      category: 'packed_payload',
      severity: 'critical',
      title: `Small file with very high entropy (possible packed payload)`,
      description: `File is ${fileSize} bytes with average entropy of ${entropyResult.average}. This is strongly indicative of a packed or encrypted payload designed to evade analysis.`,
      evidence: `Size: ${fileSize}, Entropy: ${entropyResult.average}`,
    });
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeWithBinwalk(filePath: string): BinwalkResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      signatures: [],
      embeddedFiles: [],
      entropyAnalysis: { average: 0, level: 'low', blocks: [], highEntropyRegions: [] },
      firmwareMetadata: { model: '', vendor: '', architecture: '', endian: '', bootloader: '' },
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];
  let toolUsed = 'none';

  console.log(`[JURI-X Binwalk] Analyzing ${fileName} (${fileStat.size} bytes)`);

  let signatures: BinwalkSignature[] = [];
  let embeddedFiles: BinwalkEmbeddedFile[] = [];

  // Try binwalk first
  const binwalkResult = runBinwalkScan(filePath);
  if (binwalkResult.signatures.length > 0) {
    signatures = binwalkResult.signatures;
    toolUsed = 'binwalk';
    console.log(`[JURI-X Binwalk] Using binwalk: ${signatures.length} signatures found`);
  }

  // Try binwalk extraction
  const outputDir = `/tmp/recon-x/extracted/binwalk_${fileName.replace(/[^\w.-]/g, '_')}`;
  embeddedFiles = runBinwalkExtract(filePath, outputDir);
  if (embeddedFiles.length > 0) {
    console.log(`[JURI-X Binwalk] Extracted: ${embeddedFiles.length} files`);
  }

  // Run entropy analysis (always, using our own implementation)
  const entropyAnalysis = analyzeEntropy(filePath);
  console.log(`[JURI-X Binwalk] Entropy: ${entropyAnalysis.average} (${entropyAnalysis.level}), high entropy blocks: ${entropyAnalysis.highEntropyRegions.length}`);

  // Extract firmware metadata
  const firmwareMetadata = extractFirmwareMetadata(filePath);
  if (firmwareMetadata.vendor) {
    console.log(`[JURI-X Binwalk] Firmware: ${firmwareMetadata.vendor} ${firmwareMetadata.model} (${firmwareMetadata.architecture})`);
  }

  // Fallback: if binwalk not available, use custom signature scan
  if (toolUsed === 'none') {
    console.log('[JURI-X Binwalk] binwalk not available, using custom signature scanner');
    signatures = scanKnownSignatures(filePath);
    if (signatures.length > 0) {
      toolUsed = 'custom_scanner';
      console.log(`[JURI-X Binwalk] Custom scanner: ${signatures.length} signatures found`);
    }
  }

  // Detect suspicious findings
  const suspiciousFindings = detectSuspiciousBinwalk(signatures, entropyAnalysis, firmwareMetadata, fileStat.size);

  // Additional string-based checks
  const suspiciousStrings = runTool(`strings -n 6 "${filePath}" 2>/dev/null | rg -i "(password|secret|token|api.key|aws_secret|mysql_pass|jdbc)" 2>/dev/null || true`);
  if (suspiciousStrings) {
    const lines = suspiciousStrings.split('\n').filter(l => l.trim().length > 0);
    if (lines.length > 0) {
      suspiciousFindings.push({
        category: 'embedded_credentials',
        severity: 'critical',
        title: `Potential credentials found in binary (${lines.length} matches)`,
        description: `Strings extraction found potential credentials or API keys embedded in the binary.`,
        evidence: lines.slice(0, 5).join('\n'),
      });
    }
  }

  // Check for known malware family strings
  const malwareStrings = runTool(`strings -n 8 "${filePath}" 2>/dev/null | rg -i "(mirai|mozi|hajime|bashlite|reaper|nyxdrop)" 2>/dev/null || true`);
  if (malwareStrings) {
    const malwareLines = malwareStrings.split('\n').filter(l => l.trim().length > 0);
    if (malwareLines.length > 0) {
      suspiciousFindings.push({
        category: 'known_malware',
        severity: 'critical',
        title: `Known malware family indicators detected`,
        description: `Strings associated with known IoT/targeted malware families were found in the binary.`,
        evidence: malwareLines.slice(0, 5).join('\n'),
      });
    }
  }

  console.log(`[JURI-X Binwalk] Analysis complete: ${signatures.length} signatures, ${embeddedFiles.length} embedded files, ${suspiciousFindings.length} findings`);

  return {
    available: signatures.length > 0 || entropyAnalysis.blocks.length > 0,
    filePath,
    signatures,
    embeddedFiles,
    entropyAnalysis,
    firmwareMetadata,
    suspiciousFindings,
    toolUsed,
    errors,
  };
}
