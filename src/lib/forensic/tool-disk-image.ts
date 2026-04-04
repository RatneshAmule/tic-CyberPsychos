/**
 * tool-disk-image.ts — Sleuth Kit Integration
 *
 * Uses: mmls, fls, icat, ils, sigfind from The Sleuth Kit (TSK)
 * Analyzes disk images: partition layout, file system listing (recursive),
 * deleted files, and timeline entries.
 *
 * Supports: raw images (.dd, .raw, .img), E01, split images, VMDK, QCOW2, VDI
 * Every tool call is wrapped in try/catch — gracefully degrades if tools are not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { join, basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SkPartition {
  index: number;
  startSector: string;
  endSector: string;
  size: string;
  description: string;
  type: string;
  offset: number;          // byte offset for tool chaining
}

export interface SkFileSystemEntry {
  metaAddr: string;
  fileMode: string;        // 'r' regular, 'd' directory, 'l' link, 'v' volume
  fileName: string;
  fullPath: string;
  size: string;
  modifiedTime: string;
  accessedTime: string;
  changedTime: string;
  createdTime: string;
  uid: string;
  gid: string;
  isDeleted: boolean;
  inodeType: string;       // 'regular', 'directory', ' symlink', 'socket', etc.
}

export interface SkDeletedFile {
  metaAddr: string;
  fileName: string;
  fullPath: string;
  size: string;
  deletedTime: string;
  inodeType: string;
  partition: string;
}

export interface SkTimelineEvent {
  timestamp: string;
  action: 'file_created' | 'file_deleted' | 'file_modified' | 'file_accessed';
  entity: string;
  description: string;
  source: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  confidence: number;
}

export interface SleuthKitResult {
  available: boolean;
  partitions: SkPartition[];
  fileSystemEntries: SkFileSystemEntry[];
  deletedFiles: SkDeletedFile[];
  timelineEvents: SkTimelineEvent[];
  toolVersions: Record<string, string>;
  errors: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 60_000,
};

function parseDateTime(raw: string): string {
  if (!raw || raw === '0' || raw === '-' || raw.includes('0000-00-00')) return '';
  const d = new Date(raw);
  return isNaN(d.getTime()) ? '' : d.toISOString();
}

function severityForName(name: string): SleuthKitResult['timelineEvents'][0]['severity'] {
  const lower = name.toLowerCase();
  if (/\.(exe|dll|bat|cmd|ps1|vbs|js|wsf|msi|scr|hta)$/i.test(lower)) return 'highly_suspicious';
  if (/\.(sh|py|rb|pl)$/i.test(lower)) return 'suspicious';
  if (/(password|credential|key|secret|shadow|sam|dump|shell|rootkit|backdoor|payload|exploit)/i.test(lower)) return 'critical';
  if (/(temp|cache|log|tmp)/i.test(lower)) return 'benign';
  return 'benign';
}

/** Run a tool and return its stdout. Returns null on any failure. */
function runTool(cmd: string): string | null {
  try {
    const out = execSync(cmd, EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found') || msg.includes('No such file')) {
      console.warn(`[JURI-X SleuthKit] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X SleuthKit] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Check if a tool is available and return version string if possible. */
function checkTool(name: string): string {
  try {
    const v = execSync(`${name} -V 2>&1 || ${name} --version 2>&1 || ${name} -h 2>&1`, {
      encoding: 'utf-8',
      timeout: 5_000,
    });
    return (v as string).split('\n')[0].trim();
  } catch {
    return 'not installed';
  }
}

// ─── Partition Analysis (mmls) ─────────────────────────────────────────────

function analyzePartitions(filePath: string): SkPartition[] {
  const partitions: SkPartition[] = [];
  const output = runTool(`mmls "${filePath}"`);
  if (!output) return partitions;

  const lines = output.split('\n');
  let sectorSize = 512;

  for (const line of lines) {
    const sectorMatch = line.match(/Units are in (\d+)-byte sectors/);
    if (sectorMatch) {
      sectorSize = parseInt(sectorMatch[1], 10);
      continue;
    }

    // Skip header lines
    if (!line.trim() || line.includes('DOS') || line.includes('GPT') || line.includes('Slot') || line.includes('Units') || line.includes('Description')) {
      continue;
    }

    const parts = line.trim().split(/\s+/);
    // mmls output: Slot  Start       End          Length       Description
    //                000:  Meta      0000000000   0000000000   Table
    //                001:  -------   0000002048   0002097152   Linux (0x83)
    if (parts.length >= 5) {
      const slotParts = parts[0].split(':');
      const idx = parseInt(slotParts[0], 10);
      if (isNaN(idx)) continue;

      const startSector = parts[1] === '-------' ? '0' : parts[1];
      const endSector = parts[2] === '-------' ? '0' : parts[2];
      const lengthSectors = parts[3] === '-------' ? '0' : parts[3];
      const description = parts.slice(4).join(' ');

      const startOffset = parseInt(startSector, 10) * sectorSize;

      // Detect partition type from description
      let type = 'unknown';
      if (/NTFS/i.test(description)) type = 'ntfs';
      else if (/FAT|exFAT/i.test(description)) type = 'fat';
      else if (/Linux|ext[234]/i.test(description)) type = 'linux';
      else if (/HFS|APFS/i.test(description)) type = 'mac';
      else if (/Swap/i.test(description)) type = 'swap';
      else if (/Extended/i.test(description)) type = 'extended';
      else if (/Unallocated/i.test(description)) type = 'unallocated';
      else if (/Meta/i.test(description)) type = 'meta';
      else if (/Table/i.test(description)) type = 'table';

      partitions.push({
        index: idx,
        startSector,
        endSector,
        size: lengthSectors,
        description,
        type,
        offset: startOffset,
      });
    }
  }

  return partitions;
}

// ─── File System Listing (fls -r -p) ────────────────────────────────────────

function listFileSystem(filePath: string, partitionOffset?: number): { entries: SkFileSystemEntry[]; deleted: SkDeletedFile[] } {
  const entries: SkFileSystemEntry[] = [];
  const deleted: SkDeletedFile[] = [];

  // Build fls command — use partition offset if available
  let flsCmd = 'fls -r -p -l -u ';
  if (partitionOffset !== undefined && partitionOffset > 0) {
    flsCmd += `-o ${partitionOffset} `;
  }
  flsCmd += `"${filePath}" 2>/dev/null`;

  const output = runTool(flsCmd);
  if (!output) {
    // Try without -u flag (deleted files) if it fails
    const outputNoDeleted = runTool(`fls -r -p -l ${partitionOffset !== undefined ? `-o ${partitionOffset} ` : ''}"${filePath}" 2>/dev/null`);
    if (!outputNoDeleted) return { entries, deleted };
    return parseFlsOutput(outputNoDeleted, entries, deleted, partitionOffset);
  }

  return parseFlsOutput(output, entries, deleted, partitionOffset);
}

function parseFlsOutput(
  output: string,
  entries: SkFileSystemEntry[],
  deleted: SkDeletedFile[],
  partitionOffset?: number,
): { entries: SkFileSystemEntry[]; deleted: SkDeletedFile[] } {
  const lines = output.split('\n');
  let currentPath = '';

  for (const line of lines) {
    if (!line.trim()) continue;

    // fls -l output format varies. Common patterns:
    // d/d/r * file (deleted flag)      size   date           time  file_name
    // r/r  * file (no flag)            12345  2024-01-15     10:30  file.txt

    // Extract the filename (last column)
    const parts = line.split(/\s{2,}/).map(s => s.trim());
    if (parts.length < 2) continue;

    const fileName = parts[parts.length - 1];
    if (!fileName || fileName === '.' || fileName === '..') continue;

    // Detect deleted flag — often marked with '*' or '(deleted)'
    const isDeleted = line.includes('*') || line.toLowerCase().includes('(deleted)');

    // Detect file mode from the first column
    const firstCol = parts[0] || '';
    let fileMode = 'r';
    let inodeType = 'regular';
    if (/^[dr]/.test(firstCol)) { fileMode = 'd'; inodeType = 'directory'; }
    else if (/^[l]/.test(firstCol)) { fileMode = 'l'; inodeType = 'symlink'; }
    else if (/[csb]/.test(firstCol)) { inodeType = 'special'; }

    // Parse size
    let size = '0';
    for (const part of parts) {
      if (/^\d+$/.test(part) && parseInt(part, 10) > 0 && !/^\d{4}-\d{2}/.test(part)) {
        size = part;
        break;
      }
    }

    // Parse dates — look for YYYY-MM-DD pattern
    const dateMatch = line.match(/(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}(?::\d{2})?)/);
    const modifiedTime = dateMatch ? `${dateMatch[1]}T${dateMatch[2]}:00.000Z` : '';

    // Try to extract meta address (inode number)
    const metaMatch = line.match(/^(\d+)/);
    const metaAddr = metaMatch ? metaMatch[1] : '';

    // Build full path
    const fullPath = fileName.startsWith('/') ? fileName : `/${fileName}`;

    const entry: SkFileSystemEntry = {
      metaAddr,
      fileMode,
      fileName,
      fullPath,
      size,
      modifiedTime,
      accessedTime: '',
      changedTime: '',
      createdTime: '',
      uid: '',
      gid: '',
      isDeleted,
      inodeType,
    };

    entries.push(entry);

    if (isDeleted) {
      deleted.push({
        metaAddr,
        fileName,
        fullPath,
        size,
        deletedTime: modifiedTime,
        inodeType,
        partition: partitionOffset !== undefined ? `offset_${partitionOffset}` : 'default',
      });
    }
  }

  return { entries, deleted };
}

// ─── Inode Analysis (ils) ───────────────────────────────────────────────────

function analyzeInodes(filePath: string, partitionOffset?: number): SkDeletedFile[] {
  const deleted: SkDeletedFile[] = [];

  let ilsCmd = 'ils -l ';
  if (partitionOffset !== undefined && partitionOffset > 0) {
    ilsCmd += `-o ${partitionOffset} `;
  }
  ilsCmd += `"${filePath}" 2>/dev/null`;

  const output = runTool(ilsCmd);
  if (!output) return deleted;

  const lines = output.split('\n');
  for (const line of lines) {
    if (!line.trim() || line.startsWith('st_ino')) continue;

    // ils output has inode info — look for deleted/allocated status
    const isAllocated = !line.includes('not alloc') && !line.includes('unalloc');
    if (isAllocated) continue; // Focus on unallocated inodes

    const parts = line.trim().split(/\s+/);
    if (parts.length >= 5) {
      const metaAddr = parts[0] || parts[1] || '';
      const size = parts[3] || '0';
      // ils doesn't give us filenames, just inode numbers
      deleted.push({
        metaAddr,
        fileName: `<inode ${metaAddr}>`,
        fullPath: `<unallocated inode ${metaAddr}>`,
        size,
        deletedTime: '',
        inodeType: 'unknown',
        partition: partitionOffset !== undefined ? `offset_${partitionOffset}` : 'default',
      });
    }
  }

  return deleted;
}

// ─── Signature Search (sigfind) ─────────────────────────────────────────────

function findSignatures(filePath: string, partitionOffset?: number): string[] {
  const signatures: string[] = [];

  const sigfindCmd = partitionOffset !== undefined && partitionOffset > 0
    ? `sigfind -o ${partitionOffset} "${filePath}" 2>/dev/null`
    : `sigfind "${filePath}" 2>/dev/null`;

  const output = runTool(sigfindCmd);
  if (output) {
    for (const line of output.split('\n')) {
      if (line.trim()) signatures.push(line.trim());
    }
  }

  return signatures;
}

// ─── Timeline Builder ───────────────────────────────────────────────────────

function buildTimeline(
  entries: SkFileSystemEntry[],
  deleted: SkDeletedFile[],
  source: string,
): SkTimelineEvent[] {
  const events: SkTimelineEvent[] = [];
  let id = 0;

  for (const entry of entries) {
    if (entry.modifiedTime) {
      events.push({
        timestamp: entry.modifiedTime,
        action: 'file_modified',
        entity: entry.fullPath,
        description: `File modified: ${entry.fullPath} (${entry.size} bytes, mode: ${entry.fileMode})`,
        source,
        severity: severityForName(entry.fileName),
        confidence: 0.9,
      });
    }
    if (entry.accessedTime) {
      events.push({
        timestamp: entry.accessedTime,
        action: 'file_accessed',
        entity: entry.fullPath,
        description: `File accessed: ${entry.fullPath}`,
        source,
        severity: 'benign',
        confidence: 0.7,
      });
    }
    if (entry.createdTime) {
      events.push({
        timestamp: entry.createdTime,
        action: 'file_created',
        entity: entry.fullPath,
        description: `File created: ${entry.fullPath} (${entry.size} bytes)`,
        source,
        severity: severityForName(entry.fileName),
        confidence: 0.85,
      });
    }
  }

  for (const del of deleted) {
    if (del.deletedTime) {
      events.push({
        timestamp: del.deletedTime,
        action: 'file_deleted',
        entity: del.fullPath,
        description: `Deleted file recovered: ${del.fullPath} (${del.size} bytes)`,
        source,
        severity: severityForName(del.fileName),
        confidence: 0.8,
      });
    } else {
      // Even without timestamp, report deleted file
      events.push({
        timestamp: new Date().toISOString(), // analysis time
        action: 'file_deleted',
        entity: del.fullPath,
        description: `Deleted file found: ${del.fullPath} (${del.size} bytes, partition: ${del.partition})`,
        source,
        severity: severityForName(del.fileName),
        confidence: 0.7,
      });
    }
  }

  // Sort by timestamp
  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return events;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeWithSleuthKit(filePath: string): SleuthKitResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      partitions: [],
      fileSystemEntries: [],
      deletedFiles: [],
      timelineEvents: [],
      toolVersions: {},
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const baseName = basename(filePath);
  const errors: string[] = [];

  console.log(`[JURI-X SleuthKit] Starting analysis of ${baseName} (${fileStat.size} bytes)`);

  // Check tool availability
  const toolVersions: Record<string, string> = {
    mmls: checkTool('mmls'),
    fls: checkTool('fls'),
    icat: checkTool('icat'),
    ils: checkTool('ils'),
    sigfind: checkTool('sigfind'),
  };

  const anyToolAvailable = Object.values(toolVersions).some(v => v !== 'not installed');
  if (!anyToolAvailable) {
    console.warn('[JURI-X SleuthKit] No Sleuth Kit tools found. Install sleuthkit package for disk image analysis.');
    return {
      available: false,
      partitions: [],
      fileSystemEntries: [],
      deletedFiles: [],
      timelineEvents: [],
      toolVersions,
      errors: ['Sleuth Kit is not installed. Run: apt install sleuthkit'],
    };
  }

  const partitions = analyzePartitions(filePath);
  const allEntries: SkFileSystemEntry[] = [];
  const allDeleted: SkDeletedFile[] = [];

  if (partitions.length > 0) {
    console.log(`[JURI-X SleuthKit] Found ${partitions.length} partitions`);

    // Analyze each partition that has a valid offset
    for (const part of partitions) {
      if (part.type === 'unallocated' || part.type === 'meta' || part.type === 'table') continue;
      if (part.offset === 0 && partitions.length > 1) continue; // skip "full disk" entry

      console.log(`[JURI-X SleuthKit]   Partition ${part.index} at offset ${part.offset} (${part.description})`);

      const result = listFileSystem(filePath, part.offset);
      allEntries.push(...result.entries);
      allDeleted.push(...result.deleted);

      // Also run ils on this partition
      const ilsDeleted = analyzeInodes(filePath, part.offset);
      allDeleted.push(...ilsDeleted);

      // Run sigfind on this partition
      const sigs = findSignatures(filePath, part.offset);
      if (sigs.length > 0) {
        console.log(`[JURI-X SleuthKit]   ${sigs.length} signatures found in partition ${part.index}`);
      }
    }
  } else {
    // No partition table — try fls on the whole image (might be a partition image or filesystem image)
    console.log('[JURI-X SleuthKit] No partition table found, trying direct filesystem analysis...');
    const result = listFileSystem(filePath);
    allEntries.push(...result.entries);
    allDeleted.push(...result.deleted);

    const ilsDeleted = analyzeInodes(filePath);
    allDeleted.push(...ilsDeleted);
  }

  // Deduplicate deleted files by metaAddr + fileName
  const seenDeleted = new Set<string>();
  const uniqueDeleted = allDeleted.filter(d => {
    const key = `${d.metaAddr}:${d.fileName}`;
    if (seenDeleted.has(key)) return false;
    seenDeleted.add(key);
    return true;
  });

  // Deduplicate entries by fullPath
  const seenEntries = new Set<string>();
  const uniqueEntries = allEntries.filter(e => {
    const key = `${e.fullPath}:${e.size}`;
    if (seenEntries.has(key)) return false;
    seenEntries.add(key);
    return true;
  });

  // Build timeline
  const timelineEvents = buildTimeline(uniqueEntries, uniqueDeleted, `SleuthKit: ${baseName}`);

  console.log(`[JURI-X SleuthKit] Analysis complete: ${partitions.length} partitions, ${uniqueEntries.length} files, ${uniqueDeleted.length} deleted, ${timelineEvents.length} timeline events`);

  return {
    available: true,
    partitions,
    fileSystemEntries: uniqueEntries,
    deletedFiles: uniqueDeleted,
    timelineEvents,
    toolVersions,
    errors,
  };
}
