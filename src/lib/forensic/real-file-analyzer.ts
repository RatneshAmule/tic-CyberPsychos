import { open } from 'fs/promises';
import { statSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

// Magic bytes signatures
const MAGIC_BYTES: { bytes: number[]; offset: number; type: string; description: string }[] = [
  { bytes: [0x50, 0x4B, 0x03, 0x04], offset: 0, type: 'archive', description: 'ZIP Archive (also Office docs, APK, JAR)' },
  { bytes: [0x25, 0x50, 0x44, 0x46], offset: 0, type: 'document', description: 'PDF Document' },
  { bytes: [0x89, 0x50, 0x4E, 0x47], offset: 0, type: 'image', description: 'PNG Image' },
  { bytes: [0xFF, 0xD8, 0xFF], offset: 0, type: 'image', description: 'JPEG Image' },
  { bytes: [0x47, 0x49, 0x46], offset: 0, type: 'image', description: 'GIF Image' },
  { bytes: [0x42, 0x4D], offset: 0, type: 'image', description: 'BMP Image' },
  { bytes: [0x49, 0x44, 0x33], offset: 0, type: 'audio', description: 'MP3 Audio (ID3)' },
  { bytes: [0x1A, 0x45, 0xDF, 0xA3], offset: 0, type: 'video', description: 'MKV/WebM Video' },
  { bytes: [0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], offset: 4, type: 'video', description: 'MP4 Video' },
  { bytes: [0x52, 0x49, 0x46, 0x46], offset: 0, type: 'image', description: 'WebP Image' },
  { bytes: [0x45, 0x4C, 0x46], offset: 0, type: 'executable', description: 'ELF Binary (Linux)' },
  { bytes: [0x4D, 0x5A], offset: 0, type: 'executable', description: 'PE/EXE Binary (Windows)' },
  { bytes: [0x7F, 0x45, 0x4C, 0x46], offset: 0, type: 'executable', description: 'ELF Binary' },
  { bytes: [0xD0, 0xCF, 0x11, 0xE0], offset: 0, type: 'document', description: 'MS Compound File (DOC/XLS/PPT)' },
  { bytes: [0x50, 0x4F, 0x51, 0x53], offset: 0, type: 'filesystem', description: 'PFS/Ext2/3 filesystem' },
  { bytes: [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A], offset: 0, type: 'disk_image', description: 'EnCase E01 Image' },
  { bytes: [0x1F, 0x8B], offset: 0, type: 'archive', description: 'GZIP Compressed' },
  { bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], offset: 0, type: 'archive', description: 'RAR Archive' },
  { bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], offset: 0, type: 'archive', description: '7-Zip Archive' },
  { bytes: [0x53, 0x51, 0x4C, 0x69], offset: 0, type: 'database', description: 'SQLite Database' },
  { bytes: [0xD4, 0xC3, 0xB2, 0xA1], offset: 0, type: 'network_capture', description: 'PCAP Network Capture (little-endian)' },
  { bytes: [0xA1, 0xB2, 0xC3, 0xD4], offset: 0, type: 'network_capture', description: 'PCAP Network Capture (big-endian)' },
  { bytes: [0x0D, 0x0D, 0x0D, 0x0A], offset: 0, type: 'registry_hive', description: 'Windows Registry Hive' },
  { bytes: [0x4D, 0x41, 0x43, 0x43], offset: 0, type: 'disk_image', description: 'MAC OS X Disk Image' },
  { bytes: [0x56, 0x43, 0x44], offset: 40, type: 'disk_image', description: 'VirtualPC Disk Image' },
  { bytes: [0x78, 0x56, 0x34, 0x12], offset: 0, type: 'memory_dump', description: 'Windows Crash Dump / hibernation' },
  // MBR / Boot sector signatures
  { bytes: [0xEB, 0x3C, 0x90], offset: 0, type: 'disk_image', description: 'Possible boot sector / disk image (x86 JMP)' },
  { bytes: [0xEB, 0x58, 0x90], offset: 0, type: 'disk_image', description: 'Possible FAT32 boot sector' },
  { bytes: [0xEB, 0x52, 0x90], offset: 0, type: 'disk_image', description: 'Possible NTFS boot sector' },
  // VMDK
  { bytes: [0x4B, 0x44, 0x4D], offset: 0, type: 'disk_image', description: 'VMware VMDK Disk Image' },
  // QCOW2
  { bytes: [0x51, 0x46, 0x49, 0xFB], offset: 0, type: 'disk_image', description: 'QCOW2 Disk Image' },
  // VDI
  { bytes: [0x7F, 0x10, 0xDA, 0xBE], offset: 0, type: 'disk_image', description: 'VirtualBox VDI Disk Image' },
];

export interface FileAnalysisResult {
  filePath: string;
  fileName: string;
  fileSize: number;
  magicType: string;
  magicDescription: string;
  mimeType: string;
  entropy: number;
  entropyLevel: 'low' | 'medium' | 'high' | 'very_high';
  isEncrypted: boolean;
  isExecutable: boolean;
  isCompressed: boolean;
  isImage: boolean;
  isDocument: boolean;
  isDiskImage: boolean;
  isSuspicious: boolean;
  suspiciousReasons: string[];
  fileCommand: string;
  stringsCount: number;
  diskImageInfo?: DiskImageInfo;
}

export interface DiskImageInfo {
  partitionTable?: string;
  partitions?: { id: string; start: string; end: string; size: string; type: string; system: string }[];
  fileSystems?: string[];
  volumeLabel?: string;
  totalSectors?: string;
  sectorSize?: string;
}

// Shannon entropy calculation
export function calculateEntropy(buffer: Buffer): number {
  const freq = new Map<number, number>();
  for (const byte of buffer) {
    freq.set(byte, (freq.get(byte) || 0) + 1);
  }
  let entropy = 0;
  const len = buffer.length;
  if (len === 0) return 0;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function classifyEntropy(entropy: number): 'low' | 'medium' | 'high' | 'very_high' {
  if (entropy < 5) return 'low';
  if (entropy < 6.5) return 'medium';
  if (entropy < 7.5) return 'high';
  return 'very_high';
}

// Detect magic bytes
export function detectMagicBytes(buffer: Buffer): { type: string; description: string } | null {
  for (const sig of MAGIC_BYTES) {
    if (buffer.length < sig.offset + sig.bytes.length) continue;
    let match = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (buffer[sig.offset + i] !== sig.bytes[i]) {
        match = false;
        break;
      }
    }
    if (match) return { type: sig.type, description: sig.description };
  }
  return null;
}

// Read only the first N bytes of a file — safe for any size
async function readFileHead(filePath: string, maxBytes: number = 512): Promise<Buffer> {
  const handle = await open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const toRead = Math.min(maxBytes, stat.size);
    const buf = Buffer.alloc(toRead);
    await handle.read(buf, 0, toRead, 0);
    return buf;
  } finally {
    await handle.close();
  }
}

// Read a sample chunk from file for entropy calculation
async function readFileSample(filePath: string, sampleSize: number = 100_000): Promise<Buffer> {
  const handle = await open(filePath, 'r');
  try {
    const stat = await handle.stat();
    const toRead = Math.min(sampleSize, stat.size);
    // Read from 3 different positions for better entropy sample
    if (stat.size <= sampleSize) {
      const buf = Buffer.alloc(toRead);
      await handle.read(buf, 0, toRead, 0);
      return buf;
    }
    // Sample from beginning, middle, and end
    const third = Math.floor(toRead / 3);
    const buf = Buffer.alloc(toRead);
    await handle.read(buf, 0, third, 0);
    const midOffset = Math.floor(stat.size / 2) - Math.floor(third / 2);
    await handle.read(buf, third, third, midOffset);
    const endOffset = stat.size - third;
    await handle.read(buf, third * 2, toRead - third * 2, Math.max(0, endOffset));
    return buf;
  } finally {
    await handle.close();
  }
}

// Disk image partition analysis using system tools
function analyzeDiskImage(filePath: string): DiskImageInfo | null {
  const info: DiskImageInfo = {};

  try {
    // Try `file` command for detailed info
    const fileOutput = execSync(`file -b "${filePath}"`, { encoding: 'utf-8', timeout: 10000 });
    if (fileOutput.toLowerCase().includes('partition')) {
      info.partitionTable = fileOutput.trim().substring(0, 200);
    }
    if (fileOutput.toLowerCase().includes('filesystem') || fileOutput.toLowerCase().includes('ext') || fileOutput.toLowerCase().includes('ntfs') || fileOutput.toLowerCase().includes('fat')) {
      info.fileSystems = fileOutput.match(/(ext[234]|ntfs|fat[123x]+|hfs\+?|apfs|btrfs|xfs|reiser|ufs)/gi)?.map(s => s.toUpperCase()) || [];
    }
  } catch {
    /* file command not available */
  }

  try {
    // Try fdisk for partition table
    const fdiskOutput = execSync(`fdisk -l "${filePath}" 2>/dev/null || sfdisk -l "${filePath}" 2>/dev/null`, {
      encoding: 'utf-8',
      maxBuffer: 5 * 1024 * 1024,
      timeout: 15000,
    });

    if (fdiskOutput.includes('Device') || fdiskOutput.includes('Start')) {
      info.partitionTable = 'Detected';
      info.partitions = [];
      const lines = fdiskOutput.split('\n').filter(l => l.trim() && !l.startsWith('Disk ') && !l.startsWith('Units') && !l.startsWith('Sector'));
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && parts[0] && /^\//.test(parts[0])) {
          info.partitions.push({
            id: parts[0],
            start: parts[1] || '',
            end: parts[2] || '',
            size: parts[3] || '',
            type: parts[4] || '',
            system: parts.slice(5).join(' ') || '',
          });
        }
        // Also handle lines like: "1   2048   ..." (fdisk short format)
        if (parts.length >= 4 && /^\d+$/.test(parts[0]) && parts[1].match(/^\d+$/) && parts[2].match(/^\d+$/)) {
          info.partitions.push({
            id: `Partition ${parts[0]}`,
            start: parts[1],
            end: parts[2],
            size: parts[3],
            type: parts[4] || '',
            system: parts.slice(5).join(' ') || '',
          });
        }
      }
    }

    // Extract total sectors and sector size from fdisk output
    const sectorMatch = fdiskOutput.match(/(\d+)\s*sectors/);
    const secSizeMatch = fdiskOutput.match(/(\d+)\s*bytes\s*\/\s*sector/);
    if (sectorMatch) info.totalSectors = sectorMatch[1];
    if (secSizeMatch) info.sectorSize = secSizeMatch[1];

  } catch {
    /* fdisk/sfdisk not available or failed */
  }

  try {
    // Try sleuthkit's mmls for media management
    const mmlsOutput = execSync(`mmls "${filePath}" 2>/dev/null`, {
      encoding: 'utf-8',
      maxBuffer: 5 * 1024 * 1024,
      timeout: 15000,
    });
    if (mmlsOutput.includes('DOS')) {
      if (!info.partitionTable) info.partitionTable = 'MBR (detected by sleuthkit)';
      info.partitions = [];
      const lines = mmlsOutput.split('\n').filter(l => l.trim() && !l.startsWith('DOS') && !l.includes('Units'));
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5 && /^\d+:/.test(parts[0])) {
          info.partitions.push({
            id: parts[0],
            start: parts[1],
            end: parts[2],
            size: parts[3],
            type: '',
            system: parts.slice(5).join(' ') || parts[4],
          });
        }
      }
    }
    if (mmlsOutput.includes('GPT')) {
      if (!info.partitionTable) info.partitionTable = 'GPT (detected by sleuthkit)';
    }
  } catch {
    /* mmls not available */
  }

  try {
    // Try fls (file listing from sleuthkit)
    const flsOutput = execSync(`fls -r -p "${filePath}" 2>/dev/null | head -100`, {
      encoding: 'utf-8',
      maxBuffer: 5 * 1024 * 1024,
      timeout: 20000,
    });
    if (flsOutput.trim().length > 0) {
      const files = flsOutput.split('\n').filter(l => l.trim()).length;
      if (!info.fileSystems) info.fileSystems = [];
      if (files > 5) {
        info.volumeLabel = `Contains approximately ${files} file entries`;
      }
    }
  } catch {
    /* fls not available */
  }

  try {
    // Try blkid
    const blkidOutput = execSync(`blkid "${filePath}" 2>/dev/null || file -s "${filePath}" 2>/dev/null`, {
      encoding: 'utf-8',
      timeout: 10000,
    }).trim();
    if (blkidOutput.toLowerCase().includes('label')) {
      const labelMatch = blkidOutput.match(/LABEL=["']?([^"'\s]+)/i);
      if (labelMatch) info.volumeLabel = labelMatch[1];
    }
  } catch {
    /* blkid not available */
  }

  // Return null if we found nothing
  if (!info.partitionTable && !info.fileSystems?.length && !info.partitions?.length && !info.volumeLabel) {
    return null;
  }
  return info;
}

// Full file analysis — safe for large files (reads only head + samples)
export async function analyzeFile(filePath: string): Promise<FileAnalysisResult> {
  const fileStat = statSync(filePath);
  const isLarge = fileStat.size > 50 * 1024 * 1024; // > 50MB

  // Only read first 512 bytes for magic detection — safe for ANY file size
  const headerBuffer = await readFileHead(filePath, 512);

  const magic = detectMagicBytes(headerBuffer);

  // Sample up to 100KB for entropy calculation (reads from multiple positions)
  const entropySample = await readFileSample(filePath, 100_000);
  const entropy = calculateEntropy(entropySample);
  const entropyLevel = classifyEntropy(entropy);

  // Run `file` command
  let fileCommand = 'unknown';
  try {
    fileCommand = execSync(`file -b "${filePath}"`, { encoding: 'utf-8', timeout: 5000 }).trim();
  } catch {
    /* command not available or failed */
  }

  // Count readable strings (quick estimate from sample only)
  let stringsCount = 0;
  let inString = false;
  const minStrLen = 4;
  let strLen = 0;
  for (const byte of entropySample) {
    if (byte >= 32 && byte <= 126) {
      strLen++;
      if (!inString && strLen >= minStrLen) {
        stringsCount++;
        inString = true;
      }
    } else {
      if (inString) inString = false;
      strLen = 0;
    }
  }

  const fileName = path.basename(filePath).toLowerCase();
  const isExecutable =
    magic?.type === 'executable' ||
    fileName.endsWith('.exe') ||
    fileName.endsWith('.dll') ||
    fileName.endsWith('.sys');
  const isCompressed =
    magic?.type === 'archive' &&
    (magic.description.includes('GZIP') || magic.description.includes('RAR') || magic.description.includes('7-Zip'));
  const isImage =
    magic?.type === 'image' ||
    ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff', '.svg'].some(ext => fileName.endsWith(ext));
  const isDocument =
    magic?.type === 'document' ||
    ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'].some(ext => fileName.endsWith(ext));
  const isDiskImage =
    magic?.type === 'disk_image' ||
    ['.dd', '.img', '.e01', '.raw', '.dmg', '.vmdk', '.vdi', '.qcow2'].some(ext => fileName.endsWith(ext)) ||
    fileCommand.toLowerCase().includes('partition') ||
    fileCommand.toLowerCase().includes('filesystem') ||
    fileCommand.toLowerCase().includes('boot sector') ||
    fileCommand.toLowerCase().includes('disk image');
  const isEncrypted = entropyLevel === 'very_high' && !isCompressed;

  // Suspicious reasons
  const suspiciousReasons: string[] = [];
  if (isEncrypted) suspiciousReasons.push('Very high entropy — possible encrypted or packed content');
  if (isExecutable && entropy > 7) suspiciousReasons.push('Executable with high entropy — possibly packed/obfuscated');
  if (fileName.startsWith('.') && !isImage) suspiciousReasons.push('Hidden file (starts with dot)');
  if (fileName.includes('password') || fileName.includes('credential'))
    suspiciousReasons.push('Filename contains sensitive keywords');
  if (fileName.includes('keylogger') || fileName.includes('rootkit'))
    suspiciousReasons.push('Filename matches known malware patterns');
  if (fileName.includes('inject') || fileName.includes('hook'))
    suspiciousReasons.push('Filename suggests code injection');
  if (isExecutable && !isCompressed && entropy > 7.5)
    suspiciousReasons.push('Possibly packed with UPX or similar');
  if (entropyLevel === 'very_high' && fileStat.size < 100_000)
    suspiciousReasons.push('Small file with very high entropy — potential encrypted payload');
  if (magic?.type === 'executable' && fileCommand.includes('script'))
    suspiciousReasons.push('Executable script detected');
  // Disk image specific checks
  if (isDiskImage && fileStat.size > 10 * 1024 * 1024 * 1024)
    suspiciousReasons.push('Very large disk image — verify acquisition integrity');

  // Disk image analysis (only for identified disk images)
  let diskImageInfo: DiskImageInfo | undefined;
  if (isDiskImage) {
    console.log(`[JURI-X]   Running disk image analysis for ${path.basename(filePath)}...`);
    try {
      diskImageInfo = analyzeDiskImage(filePath) || undefined;
      if (diskImageInfo) {
        console.log(`[JURI-X]   Disk image info: ${JSON.stringify(diskImageInfo).substring(0, 300)}`);
      }
    } catch (err: any) {
      console.warn(`[JURI-X]   Disk image analysis warning: ${err.message}`);
    }
  }

  return {
    filePath,
    fileName: path.basename(filePath),
    fileSize: fileStat.size,
    magicType: magic?.type || 'unknown',
    magicDescription: magic?.description || 'Unknown format',
    mimeType: fileCommand,
    entropy: Math.round(entropy * 1000) / 1000,
    entropyLevel,
    isEncrypted,
    isExecutable,
    isCompressed,
    isImage,
    isDocument,
    isDiskImage,
    isSuspicious: suspiciousReasons.length > 0,
    suspiciousReasons,
    fileCommand,
    stringsCount,
    diskImageInfo,
  };
}
