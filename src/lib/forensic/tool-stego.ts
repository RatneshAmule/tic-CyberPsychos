/**
 * tool-stego.ts — Steganography Detection
 *
 * Uses: steghide, zsteg, and entropy analysis for steganography detection
 * in image files (JPEG, PNG, BMP, GIF).
 *
 * Detects: hidden data via steghide (JPEG/BMP/WAV), LSB steganography in
 * PNG files via zsteg, and entropy anomalies that suggest hidden content.
 *
 * Falls back gracefully if steganography tools are not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync, openSync, readSync, closeSync } from 'fs';
import { basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SteghideResult {
  toolAvailable: boolean;
  dataFound: boolean;
  message: string;
  extractedSize: number;
}

export interface ZstegResult {
  toolAvailable: boolean;
  anomalies: string[];
  rawOutput: string;
}

export interface StegoSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface StegoResult {
  available: boolean;
  filePath: string;
  imageType: string;
  hasSteganography: boolean;
  steghideResult: SteghideResult;
  zstegResult: ZstegResult;
  entropyAnomaly: boolean;
  suspiciousFindings: StegoSuspiciousFinding[];
  toolUsed: string;
  errors: string[];
}

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
      console.warn(`[JURI-X Stego] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X Stego] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
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

/** Expected entropy ranges for different image types. */
function getExpectedEntropyRange(imageType: string): { min: number; max: number } {
  const type = imageType.toLowerCase();

  if (type.includes('jpeg') || type.includes('jpg')) {
    // JPEG images are compressed, typically 6.5-7.5 entropy
    return { min: 6.0, max: 7.8 };
  }
  if (type.includes('png')) {
    // PNG with typical content: 5.0-7.5 depending on content
    return { min: 4.5, max: 7.8 };
  }
  if (type.includes('gif')) {
    // GIF images typically have lower entropy
    return { min: 3.0, max: 7.0 };
  }
  if (type.includes('bmp')) {
    // BMP uncompressed: varies widely
    return { min: 2.0, max: 7.8 };
  }

  // Default range
  return { min: 3.0, max: 7.8 };
}

// ─── Steganography Tool Functions ───────────────────────────────────────────

/** Run steghide to check for hidden data. */
function runSteghide(filePath: string): SteghideResult {
  // Try steghide extraction with empty passphrase
  const result: SteghideResult = {
    toolAvailable: false,
    dataFound: false,
    message: '',
    extractedSize: 0,
  };

  const output = runTool(`steghide extract -sf "${filePath}" -p "" 2>&1`);
  if (output === null) {
    result.message = 'steghide is not installed';
    return result;
  }

  result.toolAvailable = true;

  // steghide returns exit code 0 if data was extracted
  // It returns non-zero with "nothing to extract" or "no embedded data"
  if (output.includes('wrote extracted') || output.includes('extracted data')) {
    result.dataFound = true;
    result.message = 'Hidden data was successfully extracted with empty passphrase';
    // Try to get the size of extracted data from output
    const sizeMatch = output.match(/(\d+)\s*bytes?/i);
    if (sizeMatch) {
      result.extractedSize = parseInt(sizeMatch[1], 10);
    }
  } else if (output.includes('nothing to extract') || output.includes('could not extract')) {
    result.dataFound = false;
    result.message = 'No hidden data found via steghide';
  } else if (output.includes('no embedded data') || output.includes('steghide')) {
    result.dataFound = false;
    result.message = 'No steganographic data detected by steghide';
  } else {
    // Check if steghide found something but couldn't extract (wrong passphrase)
    result.dataFound = false;
    result.message = `steghide output: ${output.substring(0, 200)}`;
  }

  return result;
}

/** Run zsteg for PNG steganography analysis. */
function runZsteg(filePath: string): ZstegResult {
  const result: ZstegResult = {
    toolAvailable: false,
    anomalies: [],
    rawOutput: '',
  };

  const output = runTool(`zsteg "${filePath}" 2>&1`);
  if (output === null) {
    result.message = 'zsteg is not installed';
    return result;
  }

  result.toolAvailable = true;
  result.rawOutput = output;

  // Parse zsteg output for anomalies
  // zsteg output format:
  // [x] key: value
  // extradata: 0x00 (0 bytes)  (header checksum: 0x00)
  // b1,r,lsb: .. .. .. .. .. (82 bytes)
  // b1,g,lsb: .. .. .. .. .. (82 bytes)
  // b1,b,msb: ................ (82 bytes)
  // b2,rgb,lsb: .. ...... .. ...... (82 bytes)
  // b3,a,lsb: ................ (82 bytes)
  // b4,r,msb: ................ (82 bytes)
  //
  // Anomalies include: "redacted" strings, extracted meaningful data, embedded text

  for (const line of output.split('\n')) {
    if (!line.trim()) continue;

    // zsteg sometimes reports "redacted" or shows extracted data
    if (/redacted/i.test(line)) {
      result.anomalies.push(`Redacted content detected: ${line.trim()}`);
    }

    // Check for extracted text/data (non-dot characters in LSB)
    // Lines with lots of non-dot characters may indicate embedded data
    if (/[:]\s+[.]{0,20}[^\s.]+.+[.]{0,20}/.test(line) && /[\w]{10,}/.test(line)) {
      result.anomalies.push(`Possible LSB embedded data: ${line.trim().substring(0, 100)}`);
    }

    // Look for specific anomaly indicators
    if (/extradata/i.test(line) && !/0 bytes/i.test(line)) {
      result.anomalies.push(`Extra data found in PNG: ${line.trim()}`);
    }

    // Check for palette anomalies
    if (/palette|colormap/i.test(line) && /unusual|anomal|suspicious/i.test(line)) {
      result.anomalies.push(`Palette anomaly: ${line.trim()}`);
    }
  }

  // Check if zsteg found anything interesting by looking at the overall output
  if (output.includes('extradata') && !output.includes('0 bytes')) {
    if (!result.anomalies.some(a => a.includes('extradata'))) {
      result.anomalies.push('Extra data detected in PNG file metadata');
    }
  }

  return result;
}

/** Analyze entropy of image file to detect anomalies. */
function analyzeImageEntropy(filePath: string, imageType: string): {
  entropy: number;
  isAnomalous: boolean;
  details: string;
} {
  const fd = openSync(filePath, 'r');
  try {
    const fileStat = statSync(filePath);
    const maxReadSize = Math.min(fileStat.size, 5 * 1024 * 1024); // Read up to 5MB
    const buffer = Buffer.alloc(maxReadSize);
    const bytesRead = readSync(fd, buffer, 0, maxReadSize, 0);
    const data = buffer.subarray(0, bytesRead);

    const entropy = calculateEntropy(data);
    const range = getExpectedEntropyRange(imageType);
    const isAnomalous = entropy > range.max;

    let details = `Entropy: ${entropy.toFixed(4)}, Expected range: ${range.min}-${range.max} for ${imageType}`;
    if (isAnomalous) {
      details += ` — ANOMALOUS: entropy exceeds expected maximum for this image type`;
    }

    return {
      entropy: Math.round(entropy * 10000) / 10000,
      isAnomalous,
      details,
    };
  } finally {
    closeSync(fd);
  }
}

/** Get image file type. */
function getImageType(filePath: string): string {
  const output = runTool(`file -b "${filePath}" 2>/dev/null`);
  return output || 'unknown';
}

/** Check if file is a supported image type for steganography analysis. */
function isSupportedImage(imageType: string): boolean {
  const type = imageType.toLowerCase();
  return (
    type.includes('jpeg') || type.includes('jpg') ||
    type.includes('png') ||
    type.includes('bmp') ||
    type.includes('gif') ||
    type.includes('tiff')
  );
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousStego(
  steghideResult: SteghideResult,
  zstegResult: ZstegResult,
  entropyResult: { entropy: number; isAnomalous: boolean; details: string },
  imageType: string,
  fileSize: number,
): StegoSuspiciousFinding[] {
  const findings: StegoSuspiciousFinding[] = [];

  // 1. steghide found hidden data — critical
  if (steghideResult.dataFound) {
    findings.push({
      category: 'steghide_data',
      severity: 'critical',
      title: 'Hidden data extracted via steghide',
      description: `steghide successfully extracted hidden data from the image using an empty passphrase. This strongly confirms steganography was used.`,
      evidence: steghideResult.message + (steghideResult.extractedSize > 0 ? ` (size: ${steghideResult.extractedSize} bytes)` : ''),
    });
  }

  // 2. zsteg anomalies — highly suspicious
  if (zstegResult.anomalies.length > 0) {
    findings.push({
      category: 'zsteg_anomalies',
      severity: 'highly_suspicious',
      title: `PNG steganography anomalies detected (${zstegResult.anomalies.length} finding${zstegResult.anomalies.length > 1 ? 's' : ''})`,
      description: `zsteg detected anomalies in the PNG file that may indicate LSB steganography or other data hiding techniques.`,
      evidence: zstegResult.anomalies.join('\n'),
    });
  }

  // 3. Entropy anomaly — suspicious
  if (entropyResult.isAnomalous) {
    findings.push({
      category: 'entropy_anomaly',
      severity: 'suspicious',
      title: 'Image entropy anomaly detected',
      description: `The image has higher entropy than expected for its type, which may indicate embedded/hidden data. Normal ${imageType} images typically have lower entropy.`,
      evidence: entropyResult.details,
    });
  }

  // 4. Very small image with high entropy — highly suspicious
  if (fileSize < 100_000 && entropyResult.entropy > 7.5) {
    findings.push({
      category: 'small_high_entropy',
      severity: 'highly_suspicious',
      title: 'Small image with very high entropy',
      description: `A small image file (${fileSize} bytes) with very high entropy (${entropyResult.entropy.toFixed(4)}) is highly suspicious. This pattern is common in steganography where large amounts of data are hidden in small carriers.`,
      evidence: `Size: ${fileSize} bytes, Entropy: ${entropyResult.entropy.toFixed(4)}`,
    });
  }

  // 5. Multiple indicators combined — critical
  if (
    (steghideResult.dataFound || zstegResult.anomalies.length > 0) &&
    entropyResult.isAnomalous
  ) {
    findings.push({
      category: 'combined_indicators',
      severity: 'critical',
      title: 'Multiple steganography indicators detected',
      description: `Both tool-based detection and entropy analysis suggest steganography. The combination of these indicators provides high confidence that hidden data is present.`,
      evidence: `Tools: ${steghideResult.dataFound ? 'steghide(+), ' : 'steghide(-), '}${zstegResult.anomalies.length > 0 ? `zsteg(+)` : 'zsteg(-)'}. Entropy: ${entropyResult.entropy.toFixed(4)}`,
    });
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeSteganography(filePath: string): StegoResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      imageType: 'unknown',
      hasSteganography: false,
      steghideResult: { toolAvailable: false, dataFound: false, message: '', extractedSize: 0 },
      zstegResult: { toolAvailable: false, anomalies: [], rawOutput: '' },
      entropyAnomaly: false,
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];
  let toolUsed = 'none';

  console.log(`[JURI-X Stego] Analyzing ${fileName} (${fileStat.size} bytes)`);

  // Determine image type
  const imageType = getImageType(filePath);
  console.log(`[JURI-X Stego] Image type: ${imageType}`);

  if (!isSupportedImage(imageType)) {
    console.log(`[JURI-X Stego] Unsupported image type: ${imageType}`);
    return {
      available: false,
      filePath,
      imageType,
      hasSteganography: false,
      steghideResult: { toolAvailable: false, dataFound: false, message: 'Unsupported image type', extractedSize: 0 },
      zstegResult: { toolAvailable: false, anomalies: [], rawOutput: '' },
      entropyAnomaly: false,
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`Unsupported image type: ${imageType}`],
    };
  }

  // Run steghide (works on JPEG, BMP, WAV)
  let steghideResult: SteghideResult = { toolAvailable: false, dataFound: false, message: '', extractedSize: 0 };
  if (/jpeg|jpg|bmp|wav/i.test(imageType)) {
    console.log('[JURI-X Stego] Running steghide analysis...');
    steghideResult = runSteghide(filePath);
    if (steghideResult.toolAvailable) {
      toolUsed = toolUsed === 'none' ? 'steghide' : `${toolUsed}+steghide`;
      console.log(`[JURI-X Stego] steghide: ${steghideResult.message}`);
    }
  }

  // Run zsteg (works on PNG)
  let zstegResult: ZstegResult = { toolAvailable: false, anomalies: [], rawOutput: '' };
  if (/png/i.test(imageType)) {
    console.log('[JURI-X Stego] Running zsteg analysis...');
    zstegResult = runZsteg(filePath);
    if (zstegResult.toolAvailable) {
      toolUsed = toolUsed === 'none' ? 'zsteg' : `${toolUsed}+zsteg`;
      console.log(`[JURI-X Stego] zsteg: ${zstegResult.anomalies.length} anomalies`);
    }
  }

  // Always run entropy analysis
  console.log('[JURI-X Stego] Running entropy analysis...');
  const entropyResult = analyzeImageEntropy(filePath, imageType);
  console.log(`[JURI-X Stego] Entropy: ${entropyResult.entropy.toFixed(4)} (anomalous: ${entropyResult.isAnomalous})`);
  toolUsed = toolUsed === 'none' ? 'entropy' : `${toolUsed}+entropy`;

  // Detect suspicious findings
  const suspiciousFindings = detectSuspiciousStego(
    steghideResult, zstegResult, entropyResult, imageType, fileStat.size
  );

  // Determine if steganography is likely present
  const hasSteganography =
    steghideResult.dataFound ||
    zstegResult.anomalies.length > 0 ||
    (entropyResult.isAnomalous && entropyResult.entropy > 7.5);

  console.log(`[JURI-X Stego] Analysis complete: steganography=${hasSteganography}, findings=${suspiciousFindings.length}`);

  return {
    available: toolUsed !== 'none',
    filePath,
    imageType,
    hasSteganography,
    steghideResult,
    zstegResult,
    entropyAnomaly: entropyResult.isAnomalous,
    suspiciousFindings,
    toolUsed,
    errors,
  };
}
