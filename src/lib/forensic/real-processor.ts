import {
  existsSync,
  mkdirSync,
  readdirSync,
  statSync,
  openSync,
  closeSync,
  readSync,
  readFileSync,
  writeFileSync,
} from 'fs';
import { join, extname, basename } from 'path';
import { calculateFileHash } from './real-hash';
import { analyzeFile } from './real-file-analyzer';
import { parseLogFile } from './real-log-parser';
import { extractStrings, searchStringsForKeywords } from './real-string-extractor';
import { searchKeywordsInContent, FORENSIC_KEYWORDS } from './real-keyword-engine';
// Image analyzer uses sharp (native C++) — loaded dynamically
// import { analyzeImage } from './real-image-analyzer';
// SQLite parser loaded dynamically (better-sqlite3 is native, may not compile)
// import { parseSqliteDatabase } from './real-sqlite-parser';
// All tool wrappers loaded dynamically to prevent import crashes
// import { analyzeWithSleuthKit } from './tool-disk-image';
// import { analyzeMemoryDump } from './tool-memory-analyzer';
// import { analyzePCAP } from './tool-pcap-analyzer';
// import { extractAndAnalyzeArchive } from './tool-archive-extractor';
// import { analyzeRegistryHive } from './tool-registry-analyzer';
// import { analyzePDF } from './tool-pdf-analyzer';
// import { analyzeWithExifTool } from './tool-exif-analyzer';
// import { analyzeWithBinwalk } from './tool-binwalk';
import type {
  Evidence,
  TimelineEvent,
  RewindEvent,
  SuspiciousFinding,
  CorrelationGraph,
  CorrelationNode,
  CorrelationEdge,
  ActivityHeatmap,
  KeywordResult,
  GeoIPResult,
  SeverityLevel,
  ActionCategory,
  CaseInfo,
  CustodyEntry,
} from './types';

// ---------- sub-types ----------

export interface ProcessedFile {
  path: string;
  name: string;
  size: number;
  hash: string;
  fileType: string;
  magicType: string;
  magicDescription: string;
  entropy: number;
  entropyLevel: string;
  isSuspicious: boolean;
  suspiciousReasons: string[];
  isImage: boolean;
  isLog: boolean;
  isText: boolean;
  isBinary: boolean;
  isSQLite: boolean;
  isDiskImage: boolean;
  analysis: ReturnType<typeof analyzeFile> extends Promise<infer T> ? T : never;
  strings: string[];
  logEvents: any[];
  imageAnalysis: any;
  sqliteAnalysis: any;
  keywordResults: any[];
  diskImageInfo: any;
}

export interface RealAnalysisResult {
  caseId: string;
  caseInfo: CaseInfo;
  evidence: Evidence[];
  processedFiles: ProcessedFile[];
  timeline: TimelineEvent[];
  rewindSequence: RewindEvent[];
  suspiciousFindings: SuspiciousFinding[];
  correlations: CorrelationGraph;
  heatmap: ActivityHeatmap[];
  keywordResults: KeywordResult[];
  geoIPResults: GeoIPResult[];
  custody: CustodyEntry[];
  stats: {
    totalEvents: number;
    suspiciousCount: number;
    criticalCount: number;
    timeRange: { start: string; end: string };
    topCategories: { category: string; count: number }[];
    filesProcessed: number;
    filesSuspicious: number;
    totalStrings: number;
    keywordsFound: number;
  };
}

// ---------- helpers ----------

const EVIDENCE_DIR = '/tmp/recon-x/evidence';
const MAX_TEXT_READ = 10 * 1024 * 1024; // 10MB max for text reading

function ensureDir(dir: string) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function isTextFile(content: string): boolean {
  let printable = 0;
  const sample = content.substring(0, 10_000);
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (
      code === 10 ||
      code === 13 ||
      code === 9 ||
      (code >= 32 && code <= 126) ||
      code >= 128
    ) {
      printable++;
    }
  }
  return sample.length > 0 && printable / sample.length > 0.85;
}

// Safely read text from file — only reads up to MAX_TEXT_READ bytes (safe for ANY file size)
function safeReadText(filePath: string): string {
  try {
    const stat = statSync(filePath);
    if (stat.size === 0) return '';
    const toRead = Math.min(MAX_TEXT_READ, stat.size);
    const buf = Buffer.alloc(toRead);
    const fd = openSync(filePath, 'r');
    try {
      readSync(fd, buf, 0, toRead, 0);
    } finally {
      closeSync(fd);
    }
    return buf.toString('utf-8');
  } catch {
    return '';
  }
}

// ---------- public API ----------

export async function processUploadedFiles(
  files: { name: string; content: Buffer }[],
  caseId: string
): Promise<RealAnalysisResult> {
  const caseDir = join(EVIDENCE_DIR, caseId);
  ensureDir(caseDir);

  for (const file of files) {
    writeFileSync(join(caseDir, file.name), file.content);
  }

  return analyzeCase(caseId);
}

export async function analyzeCase(caseId: string): Promise<RealAnalysisResult> {
  const caseDir = join(EVIDENCE_DIR, caseId);
  if (!existsSync(caseDir)) {
    throw new Error(`Case directory not found: ${caseId}`);
  }

  const fileNames = readdirSync(caseDir);
  const processedFiles: ProcessedFile[] = [];
  const allTimelineEvents: TimelineEvent[] = [];
  const allFindings: SuspiciousFinding[] = [];
  const allKeywordResults: KeywordResult[] = [];
  const allNodes: CorrelationNode[] = [];
  const allEdges: CorrelationEdge[] = [];
  const allCustody: CustodyEntry[] = [];
  let eventId = 0;
  let findingId = 0;

  const caseInfo: CaseInfo = {
    id: caseId,
    name: `Case ${caseId}`,
    description: `Real forensic analysis of ${fileNames.length} evidence file(s)`,
    createdAt: new Date().toISOString(),
    status: 'active',
    evidenceIds: [],
    analyst: 'JURI-X Automated',
  };

  for (const fileName of fileNames) {
    const filePath = join(caseDir, fileName);

    try {
      const fileStat = statSync(filePath);

      console.log(
        `[JURI-X] Processing: ${fileName} (${formatSize(fileStat.size)})`
      );

      // 1. Real SHA-256 hash
      let hash = 'error';
      try {
        hash = await calculateFileHash(filePath);
      } catch (hashErr: any) {
        console.warn(`[JURI-X]   Hash failed: ${hashErr.message}`);
      }

      // Chain of custody — acquisition
      allCustody.push({
        id: `cust-${allCustody.length + 1}`,
        evidenceId: fileName,
        action: 'uploaded',
        performedBy: 'JURI-X',
        timestamp: new Date().toISOString(),
        details: `File acquired: ${fileName} (${formatSize(fileStat.size)})`,
        hash,
      });

      // 2. Real file analysis (magic bytes, entropy, disk info) — safe for large files
      let fileAnalysis: any;
      try {
        fileAnalysis = await analyzeFile(filePath);
      } catch (analysisErr: any) {
        console.warn(`[JURI-X]   File analysis failed: ${analysisErr.message}`);
        fileAnalysis = {
          magicType: 'unknown', magicDescription: 'Analysis failed: ' + analysisErr.message,
          entropy: 0, entropyLevel: 'low', isImage: false, isDiskImage: false, isExecutable: false,
          isCompressed: false, isEncrypted: false, isDocument: false, isSuspicious: false,
          suspiciousReasons: [`File analysis error: ${analysisErr.message}`],
          fileCommand: 'error', stringsCount: 0, diskImageInfo: null,
        };
      }

    const ext = extname(fileName).toLowerCase();
    const isSQLite =
      ['.db', '.sqlite', '.sqlite3'].some(e => ext === e) ||
      fileAnalysis.magicType === 'database';
    const isImage =
      fileAnalysis.isImage ||
      ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'].some(e => ext === e);
    const isDiskImage =
      fileAnalysis.isDiskImage ||
      ['.dd', '.img', '.e01', '.raw', '.dmg', '.vmdk', '.vdi', '.qcow2'].some(e => ext === e);

    // 3. Read text content safely (max 10MB)
    let fileContent = '';
    let isText = false;
    let isBinary = false;

    if (!isDiskImage && !isImage && !isSQLite) {
      fileContent = safeReadText(filePath);
      if (fileContent.length > 0) {
        isText = isTextFile(fileContent);
        isBinary = !isText;
      } else {
        isBinary = true;
      }
    } else {
      isBinary = true;
    }

    // 4. Extract strings from binary / large files
    let extractedStrings: string[] = [];
    if (isBinary || fileStat.size > 100_000) {
      console.log(`[JURI-X]   Extracting strings from ${fileName}...`);
      extractedStrings = extractStrings(filePath);
      console.log(`[JURI-X]   Strings extracted: ${extractedStrings.length}`);
    } else if (isText) {
      extractedStrings = fileContent.split('\n').filter(l => l.trim().length >= 4);
    }

    // 5. Keyword search
    let keywordResults: any[] = [];
    if (isText && fileContent.length > 0) {
      keywordResults = searchKeywordsInContent(
        fileContent,
        fileName
      ).filter(r => r.totalMatches > 0);
    } else if (extractedStrings.length > 0) {
      keywordResults = searchStringsForKeywords(
        extractedStrings,
        FORENSIC_KEYWORDS
      );
    }
    const totalKwMatches = keywordResults.reduce((sum: number, r: any) => sum + r.totalMatches, 0);
    console.log(`[JURI-X]   Keywords found: ${totalKwMatches}`);

    // 6. Log parsing (only for text files, skip disk images)
    let logEvents: any[] = [];
    if (
      isText && !isDiskImage &&
      (ext === '.log' ||
        ext === '.txt' ||
        fileName.toLowerCase().includes('log') ||
        fileName.toLowerCase().includes('event'))
    ) {
      logEvents = parseLogFile(fileContent, fileName);
      console.log(`[JURI-X]   Log events parsed: ${logEvents.length}`);
    }

    // 7. Image analysis
    let imageAnalysis: any = null;
    if (isImage) {
      try {
        const { analyzeImage } = await import('./real-image-analyzer');
        imageAnalysis = await analyzeImage(filePath);
        if (imageAnalysis) {
          console.log(
            `[JURI-X]   Image analyzed: ${imageAnalysis.width}x${imageAnalysis.height}, GPS: ${imageAnalysis.hasGPS}`
          );
        }
      } catch (imgErr: any) {
        console.warn(`[JURI-X]   Image analysis failed: ${imgErr.message}`);
      }
    }

    // 8. SQLite parsing
    let sqliteAnalysis: any = null;
    if (isSQLite) {
      try {
        const { parseSqliteDatabase } = await import('./real-sqlite-parser');
        sqliteAnalysis = await parseSqliteDatabase(filePath);
        console.log(
          `[JURI-X]   SQLite parsed: type=${sqliteAnalysis.databaseType}, tables=${sqliteAnalysis.tables.length}, history=${sqliteAnalysis.history.length}`
        );
      } catch (err: any) {
        console.warn(`[JURI-X]   SQLite parse failed: ${err.message}`);
      }
    }

    // === DISK IMAGE SPECIFIC ANALYSIS ===
    let diskImageInfo = fileAnalysis.diskImageInfo || null;

    if (isDiskImage) {
      console.log(`[JURI-X]   === DISK IMAGE ANALYSIS ===`);

      // Sleuth Kit integration (mmls, fls, icat)
      try {
        console.log(`[JURI-X]   Running Sleuth Kit on ${fileName}...`);
        const { analyzeWithSleuthKit } = await import('./tool-disk-image');
        const skResult: any = analyzeWithSleuthKit(filePath);
        if (skResult.partitions?.length) {
          for (const part of skResult.partitions) {
            allNodes.push({ id: `sk-part-${part.start}-${fileName}`, type: 'artifact', label: part.description || `Partition ${part.start}`, properties: { start: part.start, end: part.end, type: part.type } });
          }
        }
        if (skResult.fileSystemEntries?.length) {
          const entries = skResult.fileSystemEntries.slice(0, 200);
          for (const entry of entries) {
            allTimelineEvents.push({
              id: `evt-sk-${++eventId}`, timestamp: entry.modifiedTime || new Date().toISOString(),
              action: (entry.name?.startsWith?.('Deleted') ? 'file_deleted' : entry.isDirectory ? 'file_opened' : 'file_modified') as ActionCategory,
              entity: entry.name || entry.filePath || 'unknown', description: entry.filePath || entry.name || '',
              source: `Sleuth Kit: ${fileName}`, confidence: 0.9, severity: 'benign' as SeverityLevel, metadata: { size: entry.size, inode: entry.inode }, relatedEvents: [],
            });
          }
          console.log(`[JURI-X]   Sleuth Kit: ${entries.length} file entries found`);
        }
        if (skResult.deletedFiles?.length) {
          allFindings.push({
            id: `find-sk-${++findingId}`, severity: 'suspicious' as SeverityLevel, category: 'Disk Image (Sleuth Kit)',
            title: `Deleted files found in ${fileName}`, description: `Sleuth Kit found ${skResult.deletedFiles.length} deleted file(s). First few: ${skResult.deletedFiles.slice(0, 10).map(f => f.name || f.filePath).join(', ')}`,
            evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.95,
            recommendation: 'Deleted files may contain evidence. Use icat to recover file contents.',
          });
        }
        if (skResult.timelineEvents?.length) {
          for (const evt of skResult.timelineEvents) {
            allTimelineEvents.push({ id: `evt-skt-${++eventId}`, timestamp: evt.time || new Date().toISOString(), action: evt.action as ActionCategory, entity: evt.file || evt.path || '', description: evt.description || '', source: `Sleuth Kit Timeline: ${fileName}`, confidence: 0.85, severity: evt.suspicious ? 'suspicious' as SeverityLevel : 'benign' as SeverityLevel, metadata: {}, relatedEvents: [] });
          }
        }
      } catch (skErr: any) {
        console.warn(`[JURI-X]   Sleuth Kit: ${skErr.message}`);
      }

      // Add disk image specific timeline events
      allTimelineEvents.push({
        id: `evt-real-${++eventId}`,
        timestamp: new Date().toISOString(),
        action: 'file_opened' as ActionCategory,
        entity: fileName,
        description: `Disk image loaded: ${fileName} (${formatSize(fileStat.size)}). Type: ${fileAnalysis.magicDescription}. ${fileAnalysis.fileCommand}`,
        source: `Disk Image Analyzer`,
        confidence: 0.99,
        severity: 'benign' as SeverityLevel,
        metadata: {
          magicType: fileAnalysis.magicType,
          entropy: fileAnalysis.entropy,
          entropyLevel: fileAnalysis.entropyLevel,
        },
        relatedEvents: [],
      });

      // Disk image findings
      if (diskImageInfo?.partitionTable) {
        allTimelineEvents.push({
          id: `evt-real-${++eventId}`,
          timestamp: new Date().toISOString(),
          action: 'file_opened' as ActionCategory,
          entity: fileName,
          description: `Partition table detected: ${diskImageInfo.partitionTable}`,
          source: `Disk Image: ${fileName}`,
          confidence: 0.95,
          severity: 'benign' as SeverityLevel,
          metadata: diskImageInfo.partitions ? { partitions: diskImageInfo.partitions } : {},
          relatedEvents: [],
        });

        // Add partition nodes to correlation graph
        if (diskImageInfo.partitions) {
          for (const part of diskImageInfo.partitions) {
            allNodes.push({
              id: `node-${fileName}-${part.id}`,
              type: 'artifact',
              label: `${part.id}${part.system ? ` (${part.system})` : ''}`,
              properties: {
                start: part.start,
                end: part.end,
                size: part.size,
                type: part.type,
              },
            });
            allEdges.push({
              source: `node-${fileName}`,
              target: `node-${fileName}-${part.id}`,
              relation: 'contains_partition',
              weight: 1,
            });
          }
        }
      }

      if (diskImageInfo?.fileSystems?.length) {
        allFindings.push({
          id: `find-real-${++findingId}`,
          severity: 'benign' as SeverityLevel,
          category: 'Disk Image Analysis',
          title: `File Systems Detected: ${diskImageInfo.fileSystems.join(', ')}`,
          description: `Disk image ${fileName} contains the following file systems: ${diskImageInfo.fileSystems.join(', ')}. This information helps determine the source operating system.`,
          evidence: fileName,
          timestamp: new Date().toISOString(),
          relatedArtifacts: [fileName],
          confidence: 0.9,
          recommendation: 'Use appropriate file system tools to extract files and metadata.',
        });
      }

      if (diskImageInfo?.volumeLabel) {
        allTimelineEvents.push({
          id: `evt-real-${++eventId}`,
          timestamp: new Date().toISOString(),
          action: 'file_opened' as ActionCategory,
          entity: fileName,
          description: `Volume: ${diskImageInfo.volumeLabel}`,
          source: `Disk Image: ${fileName}`,
          confidence: 0.85,
          severity: 'benign' as SeverityLevel,
          metadata: {},
          relatedEvents: [],
        });
      }

      // High entropy disk image finding
      if (fileAnalysis.entropyLevel === 'very_high') {
        allFindings.push({
          id: `find-real-${++findingId}`,
          severity: 'suspicious' as SeverityLevel,
          category: 'Disk Image Analysis',
          title: `${fileName}: Very high entropy disk image`,
          description: `Disk image ${fileName} has very high entropy (${fileAnalysis.entropy}). This could indicate the disk is encrypted (BitLocker, LUKS, FileVault), contains mostly compressed files, or has been wiped/overwritten.`,
          evidence: fileName,
          timestamp: new Date().toISOString(),
          relatedArtifacts: [fileName],
          confidence: 0.7,
          recommendation: 'Check if the source disk was encrypted. Try decryption tools (bitlocker2john, luksdump) if applicable.',
        });
      }

      // Large disk image warning
      if (fileStat.size > 5 * 1024 * 1024 * 1024) {
        allFindings.push({
          id: `find-real-${++findingId}`,
          severity: 'benign' as SeverityLevel,
          category: 'Disk Image Analysis',
          title: `Large disk image: ${formatSize(fileStat.size)}`,
          description: `The disk image ${fileName} is ${formatSize(fileStat.size)} in size. String extraction and keyword search have been performed on the full file. For deeper analysis, consider mounting the image or using specialized tools like Autopsy, FTK Imager, or Sleuth Kit directly.`,
          evidence: fileName,
          timestamp: new Date().toISOString(),
          relatedArtifacts: [fileName],
          confidence: 0.99,
          recommendation: 'For full disk forensics, mount the image on Kali Linux and use Autopsy/The Sleuth Kit for file recovery, timeline analysis, and artifact extraction.',
        });
      }

      console.log(`[JURI-X]   === DISK IMAGE ANALYSIS COMPLETE ===`);
    }

    // === MEMORY DUMP ANALYSIS (Volatility3) ===
    const isMemDump = ['.dmp', '.vmem', '.liemem'].some(e => ext === e) && !isDiskImage && fileStat.size > 10 * 1024 * 1024;
    if (isMemDump) {
      try {
        console.log(`[JURI-X]   === MEMORY ANALYSIS (Volatility3) ===`);
        const { analyzeMemoryDump } = await import('./tool-memory-analyzer');
        const memResult: any = analyzeMemoryDump(filePath);
        if (memResult.osInfo) {
          allTimelineEvents.push({ id: `evt-mem-${++eventId}`, timestamp: new Date().toISOString(), action: 'file_opened' as ActionCategory, entity: memResult.osInfo.osName || 'Unknown OS', description: `Memory dump OS: ${memResult.osInfo.osName || 'Unknown'} ${memResult.osInfo.osVersion || ''}`, source: `Volatility3: ${fileName}`, confidence: 0.95, severity: 'benign' as SeverityLevel, metadata: memResult.osInfo as any, relatedEvents: [] });
        }
        if (memResult.processes?.length) {
          for (const proc of memResult.processes.slice(0, 100)) {
            allNodes.push({ id: `proc-${proc.pid}-${fileName}`, type: 'process', label: `${proc.name} (PID ${proc.pid})`, properties: { pid: proc.pid, ppid: proc.ppid } });
            if (proc.commandLine) {
              allNodes.push({ id: `cmd-${proc.pid}-${fileName}`, type: 'artifact', label: proc.commandLine.substring(0, 100), properties: {} });
              allEdges.push({ source: `proc-${proc.pid}-${fileName}`, target: `cmd-${proc.pid}-${fileName}`, relation: 'command_line', weight: 1 });
            }
          }
          const susProcs = memResult.processes.filter(p => /password|credential|inject|hook|keylog|rootkit/i.test(p.commandLine || ''));
          for (const sp of susProcs) {
            allFindings.push({ id: `find-mem-${++findingId}`, severity: 'critical' as SeverityLevel, category: 'Memory Analysis', title: `Suspicious process: ${sp.name} (PID ${sp.pid})`, description: `Command: ${sp.commandLine || 'N/A'}`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.85, recommendation: 'Investigate process tree and command line.' });
          }
          console.log(`[JURI-X]   Volatility3: ${memResult.processes.length} processes`);
        }
        if (memResult.hiddenProcesses?.length) {
          allFindings.push({ id: `find-mem-h-${++findingId}`, severity: 'critical' as SeverityLevel, category: 'Memory Analysis', title: `${memResult.hiddenProcesses.length} hidden processes found`, description: `Possible rootkit: ${memResult.hiddenProcesses.slice(0, 10).map(p => `${p.name}(${p.pid})`).join(', ')}`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.95, recommendation: 'Hidden processes indicate rootkit.' });
        }
        if (memResult.networkConnections?.length) {
          for (const conn of memResult.networkConnections.slice(0, 50)) {
            allNodes.push({ id: `net-${conn.remoteIp || conn.localIp}-${fileName}`, type: 'ip', label: `${conn.remoteIp}:${conn.remotePort || ''}`, properties: { pid: conn.pid } });
          }
          console.log(`[JURI-X]   Volatility3: ${memResult.networkConnections.length} connections`);
        }
        if (memResult.suspiciousFindings?.length) {
          for (const sf of memResult.suspiciousFindings) {
            allFindings.push({ id: `find-vol-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Memory Analysis', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || 'Investigate further.' });
          }
        }
        console.log(`[JURI-X]   === MEMORY ANALYSIS COMPLETE ===`);
      } catch (memErr: any) { console.warn(`[JURI-X]   Volatility3: ${memErr.message}`); }
    }

    // === PCAP ANALYSIS (TShark) ===
    const isPCAP = ['.pcap', '.pcapng', '.cap'].some(e => ext === e) || fileAnalysis.magicType === 'network_capture';
    if (isPCAP) {
      try {
        console.log(`[JURI-X]   === PCAP ANALYSIS (TShark) ===`);
        const { analyzePCAP } = await import('./tool-pcap-analyzer');
        const pcapResult: any = analyzePCAP(filePath);
        if (pcapResult.dnsQueries?.length) {
          for (const dns of pcapResult.dnsQueries.slice(0, 100)) {
            allNodes.push({ id: `dns-${dns.domain}-${fileName}`, type: 'domain', label: dns.domain, properties: { ip: dns.resolvedIp } });
            allTimelineEvents.push({ id: `evt-dns-${++eventId}`, timestamp: new Date().toISOString(), action: 'network_connection' as ActionCategory, entity: dns.domain, description: `DNS: ${dns.domain} → ${dns.resolvedIp || 'N/A'}`, source: `TShark: ${fileName}`, confidence: 0.95, severity: 'benign' as SeverityLevel, relatedEvents: [] });
          }
          console.log(`[JURI-X]   TShark: ${pcapResult.dnsQueries.length} DNS queries`);
        }
        if (pcapResult.httpRequests?.length) {
          for (const http of pcapResult.httpRequests.slice(0, 100)) {
            allTimelineEvents.push({ id: `evt-http-${++eventId}`, timestamp: new Date().toISOString(), action: 'web_page_visited' as ActionCategory, entity: `${http.host || ''}${http.uri || ''}`, description: `HTTP: ${http.host}${http.uri || ''}`, source: `TShark: ${fileName}`, confidence: 0.95, severity: 'benign' as SeverityLevel, relatedEvents: [] });
            allNodes.push({ id: `url-http-${http.host}-${fileName}`, type: 'url', label: `${http.host}${http.uri || '/'}`, properties: { method: http.method } });
          }
          console.log(`[JURI-X]   TShark: ${pcapResult.httpRequests.length} HTTP requests`);
        }
        if (pcapResult.tcpConnections?.length) {
          for (const tcp of pcapResult.tcpConnections.slice(0, 50)) {
            allNodes.push({ id: `tcp-${tcp.srcIp}-${fileName}`, type: 'ip', label: tcp.srcIp, properties: { port: tcp.srcPort } });
            if (tcp.dstIp) { allNodes.push({ id: `tcp-dst-${tcp.dstIp}-${fileName}`, type: 'ip', label: tcp.dstIp, properties: { port: tcp.dstPort } }); allEdges.push({ source: `tcp-${tcp.srcIp}-${fileName}`, target: `tcp-dst-${tcp.dstIp}-${fileName}`, relation: `tcp:${tcp.dstPort}`, weight: 1 }); }
          }
        }
        if (pcapResult.credentials?.length) {
          allFindings.push({ id: `find-pcap-cred-${++findingId}`, severity: 'critical' as SeverityLevel, category: 'Network Analysis', title: `${pcapResult.credentials.length} credentials captured`, description: pcapResult.credentials.slice(0, 5).map(c => `${c.protocol}: ${c.username || c.info || ''}`).join('\n'), evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.95, recommendation: 'Reset affected accounts immediately.' });
        }
        if (pcapResult.suspiciousFindings?.length) {
          for (const sf of pcapResult.suspiciousFindings) { allFindings.push({ id: `find-pcap-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Network Analysis', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); }
        }
        console.log(`[JURI-X]   === PCAP ANALYSIS COMPLETE ===`);
      } catch (pcapErr: any) { console.warn(`[JURI-X]   TShark: ${pcapErr.message}`); }
    }

    // === ARCHIVE ANALYSIS ===
    const isArchive = ['.zip', '.7z', '.tar', '.gz', '.rar'].some(e => ext === e) || fileAnalysis.magicType === 'archive';
    if (isArchive && !isImage) {
      try {
        console.log(`[JURI-X]   === ARCHIVE ANALYSIS ===`);
        const extractDir = `/tmp/recon-x/extracted/${caseId}/${fileName}`;
        ensureDir(extractDir);
        const { extractAndAnalyzeArchive } = await import('./tool-archive-extractor');
        const archResult: any = extractAndAnalyzeArchive(filePath, extractDir);
        if (archResult.extractedFiles?.length) {
          for (const ef of archResult.extractedFiles) {
            allTimelineEvents.push({ id: `evt-arch-${++eventId}`, timestamp: new Date().toISOString(), action: 'file_opened' as ActionCategory, entity: ef.name, description: `Extracted: ${ef.name} (${formatSize(ef.size)})`, source: `Archive: ${fileName}`, confidence: 0.9, severity: ef.suspicious ? 'suspicious' as SeverityLevel : 'benign' as SeverityLevel, metadata: { hash: ef.hash }, relatedEvents: [] });
          }
          console.log(`[JURI-X]   Archive: ${archResult.extractedFiles.length} files`);
        }
        if (archResult.suspiciousFindings?.length) {
          for (const sf of archResult.suspiciousFindings) { allFindings.push({ id: `find-arch-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Archive Analysis', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); }
        }
      } catch (archErr: any) { console.warn(`[JURI-X]   Archive: ${archErr.message}`); }
    }

    // === REGISTRY ANALYSIS ===
    const isRegistry = ['.reg', '.hive'].some(e => ext === e) || fileAnalysis.magicType === 'registry_hive' || /ntuser\.dat|sam$|system$|software$|security$/i.test(basename(filePath));
    if (isRegistry) {
      try {
        console.log(`[JURI-X]   === REGISTRY ANALYSIS ===`);
        const { analyzeRegistryHive } = await import('./tool-registry-analyzer');
        const regResult: any = analyzeRegistryHive(filePath);
        if (regResult.runKeys?.length) {
          allFindings.push({ id: `find-reg-run-${++findingId}`, severity: 'highly_suspicious' as SeverityLevel, category: 'Registry Analysis', title: `${regResult.runKeys.length} Run keys (persistence)`, description: regResult.runKeys.map(r => `${r.key}: ${r.value}`).join('\n'), evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9, recommendation: 'Run keys enable persistence. Investigate each.' });
        }
        if (regResult.usbDevices?.length) {
          for (const usb of regResult.usbDevices) {
            allTimelineEvents.push({ id: `evt-usb-${++eventId}`, timestamp: usb.lastWriteTime || new Date().toISOString(), action: 'usb_connected' as ActionCategory, entity: usb.deviceName || 'USB', description: `USB: ${usb.deviceName || usb.serial}`, source: `Registry: ${fileName}`, confidence: 0.85, severity: 'benign' as SeverityLevel, relatedEvents: [] });
          }
        }
        if (regResult.suspiciousFindings?.length) {
          for (const sf of regResult.suspiciousFindings) { allFindings.push({ id: `find-reg-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Registry', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); }
        }
        console.log(`[JURI-X]   === REGISTRY ANALYSIS COMPLETE ===`);
      } catch (regErr: any) { console.warn(`[JURI-X]   Registry: ${regErr.message}`); }
    }

    // === PDF ANALYSIS ===
    if (ext === '.pdf') {
      try {
        console.log(`[JURI-X]   === PDF ANALYSIS ===`);
        const { analyzePDF } = await import('./tool-pdf-analyzer');
        const pdfResult: any = analyzePDF(filePath);
        if (pdfResult.hasJS) { allFindings.push({ id: `find-pdf-js-${++findingId}`, severity: 'critical' as SeverityLevel, category: 'PDF Analysis', title: `JavaScript in PDF`, description: 'Embedded JS — commonly used in exploits.', evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9, recommendation: 'Extract and analyze the JS code.' }); }
        if (pdfResult.hasActions) { allFindings.push({ id: `find-pdf-act-${++findingId}`, severity: 'highly_suspicious' as SeverityLevel, category: 'PDF Analysis', title: `Auto-actions in PDF`, description: `${pdfResult.actions?.length || 0} launch/open actions.`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.85, recommendation: 'Auto-launch can execute code.' }); }
        if (pdfResult.hasEmbeddedFiles) { allFindings.push({ id: `find-pdf-emb-${++findingId}`, severity: 'suspicious' as SeverityLevel, category: 'PDF Analysis', title: `Embedded files in PDF`, description: 'Contains embedded files — possible malware payload.', evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.75, recommendation: 'Extract embedded files.' }); }
        if (pdfResult.suspiciousFindings?.length) { for (const sf of pdfResult.suspiciousFindings) { allFindings.push({ id: `find-pdf-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'PDF', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); } }
      } catch (pdfErr: any) { console.warn(`[JURI-X]   PDF: ${pdfErr.message}`); }
    }

    // === EXIFTOOL ANALYSIS (images) ===
    if (isImage) {
      try {
        const { analyzeWithExifTool } = await import('./tool-exif-analyzer');
        const exifResult: any = analyzeWithExifTool(filePath);
        if (exifResult.gpsCoordinates) { allFindings.push({ id: `find-exif-${++findingId}`, severity: 'suspicious' as SeverityLevel, category: 'EXIF', title: `GPS: ${exifResult.gpsCoordinates.latitude}, ${exifResult.gpsCoordinates.longitude}`, description: `Camera: ${exifResult.cameraInfo?.make || ''} ${exifResult.cameraInfo?.model || ''}`, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.9, recommendation: 'Plot GPS coordinates on map.' }); }
        if (exifResult.suspiciousFindings?.length) { for (const sf of exifResult.suspiciousFindings) { allFindings.push({ id: `find-exif2-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'EXIF', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); } }
      } catch (exifErr: any) { console.warn(`[JURI-X]   ExifTool: ${exifErr.message}`); }
    }

    // === BINWALK ANALYSIS (binary files) ===
    if (isBinary && !isDiskImage && !isSQLite && !isPCAP) {
      try {
        const { analyzeWithBinwalk } = await import('./tool-binwalk');
        const bwResult: any = analyzeWithBinwalk(filePath);
        if (bwResult.embeddedFiles?.length) { allFindings.push({ id: `find-bw-${++findingId}`, severity: 'suspicious' as SeverityLevel, category: 'Binwalk', title: `${bwResult.embeddedFiles.length} embedded files`, description: bwResult.embeddedFiles.slice(0, 10).map(f => `${f.description} at ${f.offset}`).join('\n'), evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: 0.8, recommendation: 'Extract embedded files.' }); }
        if (bwResult.suspiciousFindings?.length) { for (const sf of bwResult.suspiciousFindings) { allFindings.push({ id: `find-bw2-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Binwalk', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); } }
      } catch (bwErr: any) { console.warn(`[JURI-X]   Binwalk: ${bwErr.message}`); }
    }

    // === YARA MALWARE DETECTION (all files) ===
    try {
      console.log(`[JURI-X]   === YARA MALWARE SCAN ===`);
      const { analyzeWithYARA } = await import('./tool-yara');
      const yaraResult: any = analyzeWithYARA(filePath);
      if (yaraResult.available && yaraResult.matchedRules?.length > 0) {
        for (const rule of yaraResult.matchedRules) {
          allFindings.push({
            id: `find-yara-${++findingId}`,
            severity: rule.tags?.includes('critical') ? 'critical' as SeverityLevel : rule.tags?.includes('high') ? 'highly_suspicious' as SeverityLevel : 'suspicious' as SeverityLevel,
            category: 'YARA Malware Detection',
            title: `YARA Rule Match: ${rule.rule}`,
            description: rule.description || `YARA rule "${rule.rule}" matched at offset ${rule.offset}. Tags: ${(rule.tags || []).join(', ')}`,
            evidence: fileName,
            timestamp: new Date().toISOString(),
            relatedArtifacts: [fileName],
            confidence: 0.9,
            recommendation: rule.tags?.includes('ransomware') ? 'ISOLATE immediately. Ransomware indicators detected.' : rule.tags?.includes('backdoor') ? 'Network access may be compromised. Check for C2 communication.' : 'Investigate matched patterns. Submit to VirusTotal for further analysis.',
          });
          allNodes.push({ id: `yara-${rule.rule}-${fileName}`, type: 'file', label: `${rule.rule}`, properties: { offset: rule.offset, tags: rule.tags } });
        }
        console.log(`[JURI-X]   YARA: ${yaraResult.matchedRules.length} rules matched`);
      }
      if (yaraResult.suspiciousFindings?.length) {
        for (const sf of yaraResult.suspiciousFindings) { allFindings.push({ id: `find-yara2-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'YARA', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); }
      }
      console.log(`[JURI-X]   === YARA SCAN COMPLETE ===`);
    } catch (yaraErr: any) { console.warn(`[JURI-X]   YARA: ${yaraErr.message}`); }

    // === DEEP TSHARK PCAP ANALYSIS (upgrade for PCAP files) ===
    if (isPCAP) {
      try {
        console.log(`[JURI-X]   === DEEP TSHARK ANALYSIS ===`);
        const { analyzeWithTShark } = await import('./tool-tshark');
        const tsharkResult: any = analyzeWithTShark(filePath);
        if (tsharkResult.available) {
          if (tsharkResult.tlsSni?.length) {
            for (const sni of tsharkResult.tlsSni.slice(0, 100)) {
              allNodes.push({ id: `tls-${sni.hostname}-${fileName}`, type: 'domain', label: sni.hostname, properties: { port: sni.port, ip: sni.ip } });
              allTimelineEvents.push({ id: `evt-tls-${++eventId}`, timestamp: new Date().toISOString(), action: 'network_connection' as ActionCategory, entity: sni.hostname, description: `TLS SNI: ${sni.hostname} (${sni.port})`, source: `TShark: ${fileName}`, confidence: 0.95, severity: 'benign' as SeverityLevel, relatedEvents: [] });
            }
            console.log(`[JURI-X]   TShark Deep: ${tsharkResult.tlsSni.length} TLS SNI entries`);
          }
          if (tsharkResult.topTalkers?.length) {
            for (const talker of tsharkResult.topTalkers.slice(0, 20)) {
              allNodes.push({ id: `talker-${talker.ip}-${fileName}`, type: 'ip', label: talker.ip, properties: { packets: talker.packets, bytes: talker.bytes } });
            }
          }
          if (tsharkResult.suspiciousFindings?.length) {
            for (const sf of tsharkResult.suspiciousFindings) { allFindings.push({ id: `find-tshark-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Deep Network (TShark)', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.85, recommendation: sf.recommendation || '' }); }
          }
        }
        console.log(`[JURI-X]   === DEEP TSHARK COMPLETE ===`);
      } catch (tsharkErr: any) { console.warn(`[JURI-X]   TShark Deep: ${tsharkErr.message}`); }
    }

    // === STEGANOGRAPHY DETECTION (images) ===
    if (isImage) {
      try {
        console.log(`[JURI-X]   === STEGANOGRAPHY ANALYSIS ===`);
        const { analyzeSteganography } = await import('./tool-stego');
        const stegoResult: any = analyzeSteganography(filePath);
        if (stegoResult.available) {
          if (stegoResult.hasSteganography) {
            allFindings.push({
              id: `find-stego-${++findingId}`,
              severity: 'critical' as SeverityLevel,
              category: 'Steganography',
              title: `Hidden data detected in ${fileName}`,
              description: `Steganography analysis detected hidden/embedded data in this image. ${stegoResult.steghideResult?.message || stegoResult.zstegResult?.summary || 'Unknown steganography technique.'}`,
              evidence: fileName,
              timestamp: new Date().toISOString(),
              relatedArtifacts: [fileName],
              confidence: 0.85,
              recommendation: 'Extract hidden data using steghide or zsteg. This could contain malware, credentials, or C2 instructions.',
            });
          }
          if (stegoResult.suspiciousFindings?.length) {
            for (const sf of stegoResult.suspiciousFindings) { allFindings.push({ id: `find-stego2-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'Steganography', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); }
          }
        }
        console.log(`[JURI-X]   === STEGANOGRAPHY COMPLETE ===`);
      } catch (stegoErr: any) { console.warn(`[JURI-X]   Steganography: ${stegoErr.message}`); }
    }

    // === SCALPEL FILE CARVING (disk images & large files) ===
    if (isDiskImage || (isBinary && fileStat.size > 1024 * 1024)) {
      try {
        console.log(`[JURI-X]   === SCALPEL FILE CARVING ===`);
        const { carveWithScalpel } = await import('./tool-scalpel');
        const scalpelResult: any = carveWithScalpel(filePath);
        if (scalpelResult.available && scalpelResult.carvedFiles?.length > 0) {
          for (const cf of scalpelResult.carvedFiles.slice(0, 50)) {
            allTimelineEvents.push({ id: `evt-carve-${++eventId}`, timestamp: new Date().toISOString(), action: 'file_created' as ActionCategory, entity: cf.name, description: `Carved: ${cf.name} (${cf.size} bytes) — ${cf.type}`, source: `Scalpel: ${fileName}`, confidence: 0.85, severity: /executable|script|ELF|PE/i.test(cf.type) ? 'suspicious' as SeverityLevel : 'benign' as SeverityLevel, metadata: { type: cf.type, offset: cf.sourceOffset }, relatedEvents: [] });
            allNodes.push({ id: `carved-${cf.name}-${fileName}`, type: 'file', label: cf.name, properties: { size: cf.size, type: cf.type, offset: cf.sourceOffset } });
          }
          console.log(`[JURI-X]   Scalpel: ${scalpelResult.carvedFiles.length} files carved`);
        }
        if (scalpelResult.suspiciousFindings?.length) {
          for (const sf of scalpelResult.suspiciousFindings) { allFindings.push({ id: `find-scalpel-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'File Carving (Scalpel)', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.8, recommendation: sf.recommendation || '' }); }
        }
        console.log(`[JURI-X]   === SCALPEL COMPLETE ===`);
      } catch (scalpelErr: any) { console.warn(`[JURI-X]   Scalpel: ${scalpelErr.message}`); }
    }

    // === HAYABUSA EVTX ANALYSIS ===
    const isEVTX = ext === '.evtx' || fileAnalysis.magicType === 'evtx' || fileName.toLowerCase().includes('event') && ext === '.log';
    if (isEVTX) {
      try {
        console.log(`[JURI-X]   === HAYABUSA EVTX ANALYSIS ===`);
        const { analyzeEVTX } = await import('./tool-evtx');
        const evtxResult: any = analyzeEVTX(filePath);
        if (evtxResult.available) {
          if (evtxResult.criticalEvents?.length) {
            for (const evt of evtxResult.criticalEvents.slice(0, 100)) {
              allTimelineEvents.push({ id: `evt-evtx-${++eventId}`, timestamp: evt.timestamp || new Date().toISOString(), action: evt.action || 'system_shutdown' as ActionCategory, entity: evt.description || `EventID ${evt.eventId}`, description: `[EVTX ${evt.eventId}] ${evt.description}`, source: `Hayabusa: ${fileName}`, confidence: 0.9, severity: evt.level === 'critical' ? 'critical' as SeverityLevel : evt.level === 'high' ? 'highly_suspicious' as SeverityLevel : 'suspicious' as SeverityLevel, metadata: { eventId: evt.eventId, data: evt.data }, relatedEvents: [] });
            }
          }
          if (evtxResult.suspiciousFindings?.length) {
            for (const sf of evtxResult.suspiciousFindings) { allFindings.push({ id: `find-evtx-${++findingId}`, severity: sf.severity as SeverityLevel, category: 'EVTX (Hayabusa)', title: sf.title, description: sf.description, evidence: fileName, timestamp: new Date().toISOString(), relatedArtifacts: [fileName], confidence: sf.confidence || 0.85, recommendation: sf.recommendation || '' }); }
          }
          console.log(`[JURI-X]   Hayabusa: ${evtxResult.totalEvents} events, ${evtxResult.criticalEvents?.length || 0} critical`);
        }
        console.log(`[JURI-X]   === HAYABUSA EVTX COMPLETE ===`);
      } catch (evtxErr: any) { console.warn(`[JURI-X]   Hayabusa: ${evtxErr.message}`); }
    }

    // Accumulate keyword results
    for (const kr of keywordResults) {
      allKeywordResults.push({
        keyword: kr.keyword,
        matches: kr.matches.map((m: any) => ({
          file: m.file || fileName,
          line: m.line || 0,
          context: m.context,
          source: m.source || fileName,
        })),
        totalMatches: kr.totalMatches,
      });
    }

    // Timeline from log events
    for (const evt of logEvents) {
      const id = `evt-real-${++eventId}`;
      allTimelineEvents.push({
        id,
        timestamp: evt.timestamp.toISOString(),
        action: evt.action,
        entity: evt.entity,
        description: evt.description.substring(0, 300),
        source: evt.source,
        confidence: evt.confidence,
        severity: evt.severity,
        metadata: { raw: evt.raw.substring(0, 200) },
        relatedEvents: [],
      });
    }

    // Timeline from browser history (SQLite)
    if (sqliteAnalysis && sqliteAnalysis.history.length > 0) {
      for (const entry of sqliteAnalysis.history) {
        allTimelineEvents.push({
          id: `evt-real-${++eventId}`,
          timestamp: entry.lastVisitTime || new Date().toISOString(),
          action: 'web_page_visited' as ActionCategory,
          entity: entry.url.substring(0, 150),
          description: entry.title || entry.url,
          source: `${fileName} (browser history)`,
          confidence: 0.95,
          severity: 'benign' as SeverityLevel,
          metadata: {
            visitCount: entry.visitCount,
            typedCount: entry.typedCount,
          },
          relatedEvents: [],
        });
      }
    }

    // Timeline from downloads (SQLite)
    if (sqliteAnalysis && sqliteAnalysis.downloads.length > 0) {
      for (const dl of sqliteAnalysis.downloads) {
        allTimelineEvents.push({
          id: `evt-real-${++eventId}`,
          timestamp: dl.startTime || new Date().toISOString(),
          action: 'file_downloaded' as ActionCategory,
          entity: dl.targetPath || dl.url,
          description: `Downloaded: ${dl.url.substring(0, 200)}`,
          source: `${fileName} (downloads)`,
          confidence: 0.95,
          severity:
            dl.totalBytes > 10 * 1024 * 1024
              ? ('suspicious' as SeverityLevel)
              : ('benign' as SeverityLevel),
          metadata: { size: dl.totalBytes, mimeType: dl.mimeType },
          relatedEvents: [],
        });
      }
    }

    // Suspicious URLs from SQLite
    if (sqliteAnalysis && sqliteAnalysis.suspiciousUrls.length > 0) {
      for (const su of sqliteAnalysis.suspiciousUrls) {
        allFindings.push({
          id: `find-real-${++findingId}`,
          severity: 'highly_suspicious' as SeverityLevel,
          category: 'Browser Activity',
          title: `Suspicious URL: ${su.url.substring(0, 100)}`,
          description: `Found in ${fileName}: ${su.reason}. Title: "${su.title}"`,
          evidence: fileName,
          timestamp: new Date().toISOString(),
          relatedArtifacts: [fileName],
          confidence: 0.9,
          recommendation:
            'Investigate the URL further. Check if the user actively visited this site or if it was embedded.',
        });
      }
    }

    // Suspicious findings from file analysis
    if (fileAnalysis.isSuspicious) {
      for (const reason of fileAnalysis.suspiciousReasons) {
        const sev = reason.includes('encrypted') ||
          reason.includes('malware') ||
          reason.includes('rootkit') ||
          reason.includes('keylog')
          ? ('critical' as SeverityLevel)
          : reason.includes('high entropy') ||
            reason.includes('packed') ||
            reason.includes('password') ||
            reason.includes('sensitive')
            ? ('highly_suspicious' as SeverityLevel)
            : ('suspicious' as SeverityLevel);

        allFindings.push({
          id: `find-real-${++findingId}`,
          severity: sev,
          category: isDiskImage ? 'Disk Image Analysis' : 'File Analysis',
          title: `${fileName}: ${reason}`,
          description: `File analysis of ${fileName} (${formatSize(fileStat.size)}) revealed: ${reason}. Entropy: ${fileAnalysis.entropy} (${fileAnalysis.entropyLevel}). Type: ${fileAnalysis.magicDescription}.`,
          evidence: fileName,
          timestamp: new Date().toISOString(),
          relatedArtifacts: [fileName],
          confidence: 0.85,
          recommendation: reason.includes('encrypted')
            ? 'The file appears to be encrypted. Try decryption tools or check if this is expected.'
            : reason.includes('entropy')
              ? 'High entropy may indicate packed/encrypted content. Submit to VirusTotal for analysis.'
              : 'Review the file contents and determine if this is expected behavior.',
        });
      }
    }

    // Image suspicious findings
    if (imageAnalysis?.isSuspicious) {
      for (const reason of imageAnalysis.suspiciousReasons) {
        allFindings.push({
          id: `find-real-${++findingId}`,
          severity: reason.includes('GPS')
            ? ('suspicious' as SeverityLevel)
            : ('highly_suspicious' as SeverityLevel),
          category: 'Image Analysis',
          title: `Image ${fileName}: ${reason}`,
          description: `EXIF analysis of ${fileName} (${imageAnalysis.width}x${imageAnalysis.height}). ${reason}`,
          evidence: fileName,
          timestamp: new Date().toISOString(),
          relatedArtifacts: [fileName],
          confidence: 0.8,
          recommendation: reason.includes('GPS')
            ? 'GPS data can reveal the location where the photo was taken.'
            : 'Image metadata may contain evidence of manipulation.',
        });
      }
    }

    // Correlation node for this file
    allNodes.push({
      id: `node-${fileName}`,
      type: 'file',
      label: fileName,
      properties: {
        size: fileStat.size,
        type: fileAnalysis.magicType,
        entropy: fileAnalysis.entropy,
        hash: hash.substring(0, 20) + '...',
        ...(isDiskImage && diskImageInfo ? { diskImageInfo: {
          partitionTable: diskImageInfo.partitionTable,
          fileSystems: diskImageInfo.fileSystems,
          volumeLabel: diskImageInfo.volumeLabel,
          partitions: diskImageInfo.partitions?.length || 0,
        }} : {}),
      },
      severity: fileAnalysis.isSuspicious
        ? ('suspicious' as SeverityLevel)
        : undefined,
    });

    // Store processed file record
    processedFiles.push({
      path: filePath,
      name: fileName,
      size: fileStat.size,
      hash,
      fileType: ext || 'unknown',
      magicType: fileAnalysis.magicType,
      magicDescription: fileAnalysis.magicDescription,
      entropy: fileAnalysis.entropy,
      entropyLevel: fileAnalysis.entropyLevel,
      isSuspicious: fileAnalysis.isSuspicious,
      suspiciousReasons: fileAnalysis.suspiciousReasons,
      isImage,
      isLog: logEvents.length > 0,
      isText,
      isBinary,
      isSQLite,
      isDiskImage,
      analysis: fileAnalysis,
      strings: extractedStrings.slice(0, 50),
      logEvents,
      imageAnalysis,
      sqliteAnalysis,
      keywordResults,
      diskImageInfo,
    });

    caseInfo.evidenceIds.push(fileName);

    } catch (fileErr: any) {
      // If ANY error occurs while processing this file, log it and continue with next file
      console.error(`[JURI-X] ERROR processing ${fileName}: ${fileErr.message}`);
      allCustody.push({
        id: `cust-${allCustody.length + 1}`,
        evidenceId: fileName,
        action: 'error',
        performedBy: 'JURI-X',
        timestamp: new Date().toISOString(),
        details: `Processing failed: ${fileErr.message}`,
      });
      allFindings.push({
        id: `find-err-${++findingId}`,
        severity: 'suspicious' as SeverityLevel,
        category: 'System Error',
        title: `Failed to process: ${fileName}`,
        description: `Error: ${fileErr.message}. The file may be corrupted or in an unsupported format.`,
        evidence: fileName,
        timestamp: new Date().toISOString(),
        relatedArtifacts: [fileName],
        confidence: 0.5,
        recommendation: 'Check the file format. Try opening it manually with appropriate tools.',
      });
      caseInfo.evidenceIds.push(fileName);
    }
  }

  // Sort timeline by timestamp
  allTimelineEvents.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  // Rewind sequence — top 50 most interesting events
  const interestingEvents = allTimelineEvents
    .filter(
      e =>
        e.severity !== 'benign' ||
        e.action === 'web_page_visited' ||
        e.action === 'login_attempt' ||
        e.action === 'file_downloaded' ||
        e.action === 'usb_connected'
    )
    .slice(0, 50);

  const rewindSequence: RewindEvent[] = interestingEvents.map(e => ({
    id: `rwd-${e.id}`,
    timestamp: e.timestamp,
    action: e.action,
    entity: e.entity,
    description: e.description.substring(0, 200),
    source: e.source,
    confidence: e.confidence,
  }));

  // Correlation graph
  const correlationGraph: CorrelationGraph = { nodes: allNodes, edges: allEdges };

  // Activity heatmap (7 days × 24 hours)
  const hourMap = new Map<string, number>();
  for (const evt of allTimelineEvents) {
    const d = new Date(evt.timestamp);
    const day = d.getUTCDay();
    const hour = d.getUTCHours();
    const key = `${day}-${hour}`;
    hourMap.set(key, (hourMap.get(key) || 0) + 1);
  }
  const heatmap: ActivityHeatmap[] = [];
  for (let day = 0; day < 7; day++) {
    for (let hour = 0; hour < 24; hour++) {
      heatmap.push({ hour, day, count: hourMap.get(`${day}-${hour}`) || 0 });
    }
  }

  // Stats
  const suspiciousCount = allFindings.filter(
    f => f.severity === 'suspicious' || f.severity === 'highly_suspicious'
  ).length;
  const criticalCount = allFindings.filter(
    f => f.severity === 'critical'
  ).length;
  const timeRange =
    allTimelineEvents.length > 0
      ? {
          start: allTimelineEvents[0].timestamp,
          end: allTimelineEvents[allTimelineEvents.length - 1].timestamp,
        }
      : {
          start: new Date().toISOString(),
          end: new Date().toISOString(),
        };

  const categoryMap = new Map<string, number>();
  for (const evt of allTimelineEvents) {
    categoryMap.set(evt.action, (categoryMap.get(evt.action) || 0) + 1);
  }
  const topCategories = Array.from(categoryMap.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  console.log(
    `[JURI-X] Analysis complete. Events: ${allTimelineEvents.length}, Findings: ${allFindings.length}, Keywords: ${allKeywordResults.reduce((s, k) => s + k.totalMatches, 0)}`
  );

  return {
    caseId,
    caseInfo,
    evidence: processedFiles.map(pf => ({
      id: pf.name,
      caseId,
      name: pf.name,
      type: pf.isDiskImage
        ? ('disk_image' as const)
        : pf.isImage
          ? ('image' as const)
          : pf.isSQLite
            ? ('browser_data' as const)
            : pf.isLog
              ? ('log_file' as const)
              : ('filesystem' as const),
      path: pf.path,
      size: pf.size,
      hash: pf.hash,
      status: 'analyzed' as const,
      uploadedAt: new Date().toISOString(),
      analyzedAt: new Date().toISOString(),
      metadata: {
        magicType: pf.magicType,
        magicDescription: pf.magicDescription,
        entropy: pf.entropy,
        entropyLevel: pf.entropyLevel,
        isDiskImage: pf.isDiskImage,
        stringsCount: pf.strings.length,
        logEvents: pf.logEvents.length,
        keywordMatches: pf.keywordResults.reduce(
          (s: number, k: any) => s + k.totalMatches,
          0
        ),
        ...(pf.diskImageInfo ? { diskImage: pf.diskImageInfo } : {}),
      },
    })),
    processedFiles,
    timeline: allTimelineEvents,
    rewindSequence,
    suspiciousFindings: allFindings,
    correlations: correlationGraph,
    heatmap,
    keywordResults: allKeywordResults,
    geoIPResults: [],
    custody: allCustody,
    stats: {
      totalEvents: allTimelineEvents.length,
      suspiciousCount,
      criticalCount,
      timeRange,
      topCategories,
      filesProcessed: processedFiles.length,
      filesSuspicious: processedFiles.filter(f => f.isSuspicious).length,
      totalStrings: processedFiles.reduce((s, f) => s + f.strings.length, 0),
      keywordsFound: allKeywordResults.reduce(
        (s, k) => s + k.totalMatches,
        0
      ),
    },
  };
}

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}
