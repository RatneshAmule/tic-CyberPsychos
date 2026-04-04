/**
 * tool-memory-analyzer.ts — Volatility3 Integration
 *
 * Uses: vol (volatility3) or vol.py for memory dump forensics.
 * Runs multiple volatility plugins with graceful degradation.
 *
 * Plugins:
 *   - windows.info.Info        — OS info (auto-detects OS type)
 *   - windows.pslist.PsList    — active process list
 *   - windows.psscan.PsScan    — hidden/terminated processes
 *   - windows.netstat.NetStat  — network connections
 *   - windows.cmdline.CmdLine  — process command lines
 *   - windows.registry.hivelist.HiveList — registry hives
 *   - windows.dumpfiles.DumpFiles — file extraction info
 *   - linux.pslist.PsList      — Linux process list
 *   - linux.check_syscall.Syscall — Linux syscall table check
 *   - linux.bash.Bash          — bash command history
 *   - macos.pslist.PsList      — macOS process list
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join, basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export type DetectedOS = 'windows' | 'linux' | 'macos' | 'unknown';

export interface OsInfo {
  osName: string;
  osVersion: string;
  architecture: string;
  kernelVersion: string;
  dtbAddress: string;
  createdAt: string;
}

export interface ProcessEntry {
  pid: number;
  ppid: number;
  name: string;
  createTime: string;
  exitTime: string;
  threads: number;
  handles: number;
  sessionId: string;
  wow64: boolean;
  commandLine: string;
  source: string;           // 'pslist' or 'psscan'
  isHidden: boolean;
}

export interface NetworkConnection {
  pid: number;
  processName: string;
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
}

export interface RegistryHive {
  offset: string;
  name: string;
  path: string;
  description: string;
}

export interface SuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface Volatility3Result {
  available: boolean;
  detectedOS: DetectedOS;
  osInfo: OsInfo | null;
  processes: ProcessEntry[];
  hiddenProcesses: ProcessEntry[];
  networkConnections: NetworkConnection[];
  commandLines: Map<number, string>;   // pid → command line
  registryHives: RegistryHive[];
  suspiciousFindings: SuspiciousFinding[];
  pluginResults: Record<string, boolean>;
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

/** Find the volatility binary — try common paths and names. */
function findVolatilityBinary(): string | null {
  const candidates = [
    'vol',
    'vol.py',
    'volatility3',
    'volatility',
    'python3 -m volatility3',
    'python3 vol.py',
    'python vol.py',
    '/usr/local/bin/vol',
    '/usr/bin/vol',
    '/opt/volatility3/vol.py',
  ];

  for (const cmd of candidates) {
    try {
      execSync(`${cmd} --help 2>&1 | head -1`, { encoding: 'utf-8', timeout: 10_000 });
      return cmd;
    } catch {
      continue;
    }
  }
  return null;
}

/** Run a volatility plugin with CSV output. Returns raw CSV string or null. */
function runPlugin(
  volBin: string,
  filePath: string,
  plugin: string,
  timeout = 60_000,
): string | null {
  const cmd = `${volBin} -f "${filePath}" -q --output=csv ${plugin}`;
  try {
    const out = execSync(cmd, {
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      timeout,
    });
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    // Volatility3 outputs errors to stderr, but the plugin result might still be in stdout
    if (err?.stdout && (err.stdout as string).trim().length > 0) {
      return (err.stdout as string).trim();
    }
    console.warn(`[JURI-X Volatility] Plugin ${plugin} failed: ${msg.substring(0, 200)}`);
    return null;
  }
}

/** Parse CSV output into array of objects. */
function parseCSV(csv: string): Record<string, string>[] {
  if (!csv || csv.trim().length === 0) return [];

  const lines = csv.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length < 2) return [];

  // Parse header
  const headers = parseCSVLine(lines[0]);

  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    const row: Record<string, string> = {};
    for (let j = 0; j < headers.length && j < values.length; j++) {
      row[headers[j].trim()] = values[j].trim();
    }
    if (Object.keys(row).length > 0) {
      rows.push(row);
    }
  }

  return rows;
}

/** Parse a single CSV line handling quoted fields. */
function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

/** Try to detect OS type from info plugin output or file signatures. */
function detectOSType(csv: string): DetectedOS {
  if (!csv) return 'unknown';
  const lower = csv.toLowerCase();
  if (lower.includes('windows') || lower.includes('win')) return 'windows';
  if (lower.includes('linux')) return 'linux';
  if (lower.includes('darwin') || lower.includes('macos') || lower.includes('mac os')) return 'macos';
  return 'unknown';
}

/** Try to detect OS from the memory dump file itself (fallback). */
function detectOSFromFile(filePath: string): DetectedOS {
  try {
    const output = execSync(`file -b "${filePath}"`, { encoding: 'utf-8', timeout: 5_000 }).trim();
    const lower = output.toLowerCase();
    if (lower.includes('windows') || lower.includes('win') || lower.includes('pe') || lower.includes('nt')) return 'windows';
    if (lower.includes('linux') || lower.includes('elf')) return 'linux';
    if (lower.includes('darwin') || lower.includes('mach-o') || lower.includes('macos')) return 'macos';
  } catch {
    /* file command not available */
  }

  // Try magic bytes
  try {
    const head = execSync(`head -c 4096 "${filePath}" 2>/dev/null`, { encoding: 'buffer', timeout: 5_000 });
    const str = head.toString('utf-8').toLowerCase();
    if (str.includes('windows') || str.includes('ntoskrnl') || str.includes('microsoft')) return 'windows';
    if (str.includes('linux') || str.includes('/bin/bash') || str.includes('vmlinux')) return 'linux';
    if (str.includes('darwin') || str.includes('mach_kernel') || str.includes('xnu')) return 'macos';
  } catch {
    /* head not available */
  }

  return 'unknown';
}

// ─── Plugin-Specific Parsers ────────────────────────────────────────────────

function parseWindowsInfo(csv: string): OsInfo {
  const rows = parseCSV(csv);
  if (rows.length === 0) {
    return { osName: 'Unknown', osVersion: '', architecture: '', kernelVersion: '', dtbAddress: '', createdAt: new Date().toISOString() };
  }

  const row = rows[0];
  return {
    osName: row['OS name'] || row['os_name'] || row['Operating System'] || 'Unknown',
    osVersion: row['OS version'] || row['os_version'] || row['Version'] || '',
    architecture: row['Architecture'] || row['architecture'] || row['Arch'] || '',
    kernelVersion: row['Kernel version'] || row['kernel_version'] || row['Kernel'] || '',
    dtbAddress: row['DTB'] || row['DTB Address'] || '',
    createdAt: new Date().toISOString(),
  };
}

function parseWindowsPsList(csv: string, source: string): ProcessEntry[] {
  const rows = parseCSV(csv);
  return rows.map(row => {
    const pid = parseInt(row['PID'] || row['pid'] || '0', 10);
    return {
      pid,
      ppid: parseInt(row['PPID'] || row['ppid'] || '0', 10),
      name: row['ImageFileName'] || row['Name'] || row['Process'] || '',
      createTime: row['CreateTime'] || row['Create Time'] || row['Created'] || '',
      exitTime: row['ExitTime'] || row['Exit Time'] || '',
      threads: parseInt(row['Threads'] || row['NumberOfThreads'] || '0', 10),
      handles: parseInt(row['Handles'] || row['HandleCount'] || '0', 10),
      sessionId: row['SessionId'] || row['Session'] || row['SID'] || '',
      wow64: (row['Wow64'] || '').toLowerCase() === 'true' || (row['WoW64'] || '').toLowerCase() === 'true',
      commandLine: '',
      source,
      isHidden: false,
    };
  }).filter(p => p.pid > 0);
}

function parseWindowsPsScan(csv: string): ProcessEntry[] {
  const processes = parseWindowsPsList(csv, 'psscan');
  return processes.map(p => ({ ...p, source: 'psscan', isHidden: true }));
}

function parseWindowsNetStat(csv: string): NetworkConnection[] {
  const rows = parseCSV(csv);
  return rows.map(row => ({
    pid: parseInt(row['PID'] || row['pid'] || '0', 10),
    processName: row['Process'] || row['ImageFileName'] || row['Name'] || '',
    protocol: row['Protocol'] || row['Proto'] || '',
    localAddress: row['LocalAddr'] || row['Local Address'] || row['Local'] || '',
    localPort: parseInt((row['LocalAddr'] || row['Local'] || '').split(':').pop() || '0', 10),
    remoteAddress: row['ForeignAddr'] || row['Foreign Address'] || row['Remote'] || '',
    remotePort: parseInt((row['ForeignAddr'] || row['Remote'] || '').split(':').pop() || '0', 10),
    state: row['State'] || row['Status'] || '',
  })).filter(c => c.pid > 0 || c.protocol.length > 0);
}

function parseWindowsCmdLine(csv: string): Map<number, string> {
  const rows = parseCSV(csv);
  const map = new Map<number, string>();
  for (const row of rows) {
    const pid = parseInt(row['PID'] || row['pid'] || '0', 10);
    const cmd = row['CommandLine'] || row['Command Line'] || row['Args'] || '';
    if (pid > 0 && cmd) {
      map.set(pid, cmd);
    }
  }
  return map;
}

function parseWindowsHiveList(csv: string): RegistryHive[] {
  const rows = parseCSV(csv);
  return rows.map(row => ({
    offset: row['Offset'] || row['Virtual'] || '',
    name: row['Name'] || row['Hive Name'] || '',
    path: row['FileFullPath'] || row['Path'] || row['Filename'] || '',
    description: '',
  }));
}

function parseLinuxPsList(csv: string): ProcessEntry[] {
  const rows = parseCSV(csv);
  return rows.map(row => {
    const pid = parseInt(row['PID'] || row['pid'] || '0', 10);
    return {
      pid,
      ppid: parseInt(row['PPID'] || row['ppid'] || '0', 10),
      name: row['Comm'] || row['Name'] || row['Process'] || '',
      createTime: row['Start Time'] || row['StartTime'] || '',
      exitTime: '',
      threads: parseInt(row['NumThreads'] || row['Threads'] || '0', 10),
      handles: 0,
      sessionId: row['Session ID'] || row['SID'] || '',
      wow64: false,
      commandLine: '',
      source: 'linux_pslist',
      isHidden: false,
    };
  }).filter(p => p.pid > 0);
}

function parseLinuxBash(csv: string): SuspiciousFinding[] {
  const findings: SuspiciousFinding[] = [];
  const rows = parseCSV(csv);
  const suspiciousPatterns = [
    { pattern: /curl|wget|nc |ncat|python.*-c|bash.*-c|eval\s/i, severity: 'highly_suspicious' as const, title: 'Remote execution command' },
    { pattern: /rm\s+-rf|mkfs|dd\s+if=|chmod\s+777/i, severity: 'critical' as const, title: 'Destructive command detected' },
    { pattern: /password|passwd|shadow|sudo|su\s/i, severity: 'highly_suspicious' as const, title: 'Credential access command' },
    { pattern: /cat\s+\/etc\/|\/etc\/shadow|\/etc\/passwd/i, severity: 'critical' as const, title: 'Sensitive file access' },
    { pattern: /ssh\s|scp\s|sftp\s|rsync/i, severity: 'suspicious' as const, title: 'Remote connection command' },
    { pattern: /crontab|systemctl|service\s/i, severity: 'suspicious' as const, title: 'Persistence mechanism' },
    { pattern: /base64|openssl.*enc|gpg\s/i, severity: 'suspicious' as const, title: 'Encoding/encryption command' },
    { pattern: /pip\s+install|npm\s+install|apt-get|yum/i, severity: 'benign' as const, title: 'Package installation command' },
  ];

  for (const row of rows) {
    const cmd = row['Command'] || row['CmdLine'] || row['Line'] || '';
    for (const sp of suspiciousPatterns) {
      if (sp.pattern.test(cmd)) {
        findings.push({
          category: 'bash_history',
          severity: sp.severity,
          title: `${sp.title}: ${cmd.substring(0, 100)}`,
          description: `Bash history entry: ${cmd}`,
          evidence: cmd,
        });
      }
    }
  }

  return findings;
}

// ─── Suspicious Process Detection ───────────────────────────────────────────

function detectSuspiciousProcesses(
  processes: ProcessEntry[],
  hiddenProcesses: ProcessEntry[],
  commandLines: Map<number, string>,
  connections: NetworkConnection[],
): SuspiciousFinding[] {
  const findings: SuspiciousFinding[] = [];
  const allPids = new Set(processes.map(p => p.pid));

  // 1. Processes found by psscan but not pslist (hidden/terminated)
  for (const hp of hiddenProcesses) {
    if (!allPids.has(hp.pid)) {
      findings.push({
        category: 'hidden_process',
        severity: 'critical',
        title: `Hidden process detected: ${hp.name} (PID ${hp.pid})`,
        description: `Process ${hp.name} (PID ${hp.pid}, PPID ${hp.ppid}) was found via pool scanning but not in the active process list. This indicates rootkit activity or process hiding.`,
        evidence: `PID ${hp.pid} PPID ${hp.ppid} ${hp.name}`,
      });
    }
  }

  // 2. Suspicious process names
  const suspiciousNames = [
    { name: /cmd\.exe|powershell/i, severity: 'suspicious' as const, desc: 'Command shell running (possible lateral movement)' },
    { name: /mimikatz/i, severity: 'critical' as const, desc: 'Mimikatz credential dumping tool detected' },
    { name: /nc\.exe|ncat\.exe|netcat/i, severity: 'critical' as const, desc: 'Netcat backdoor detected' },
    { name: /psexec/i, severity: 'critical' as const, desc: 'PsExec remote execution detected' },
    { name: /procdump/i, severity: 'highly_suspicious' as const, desc: 'Process dumping tool detected (possible credential theft)' },
    { name: /vssadmin/i, severity: 'highly_suspicious' as const, desc: 'Volume shadow copy manipulation detected' },
    { name: /bitsadmin/i, severity: 'suspicious' as const, desc: 'Background Intelligent Transfer Service (living off the land)' },
    { name: /certutil/i, severity: 'suspicious' as const, desc: 'Certutil (common LOLBIN for file download)' },
    { name: /wmic\s/i, severity: 'suspicious' as const, desc: 'WMIC execution (common in lateral movement)' },
    { name: /reg\.exe/i, severity: 'suspicious' as const, desc: 'Registry manipulation tool detected' },
    { name: /tasklist|net\s/i, severity: 'benign' as const, desc: 'Reconnaissance commands detected' },
  ];

  for (const proc of processes) {
    const cmdLine = commandLines.get(proc.pid) || '';
    const combined = `${proc.name} ${cmdLine}`.toLowerCase();

    for (const sn of suspiciousNames) {
      if (sn.name.test(combined) && sn.severity !== 'benign') {
        findings.push({
          category: 'suspicious_process',
          severity: sn.severity,
          title: `Suspicious process: ${proc.name} (PID ${proc.pid})`,
          description: sn.desc + (cmdLine ? ` Command line: ${cmdLine.substring(0, 200)}` : ''),
          evidence: cmdLine || `PID ${proc.pid} ${proc.name}`,
        });
      }
    }
  }

  // 3. Suspicious command lines
  const suspiciousCmdPatterns = [
    { pattern: /-enc|FromBase64|encodedcommand/i, severity: 'highly_suspicious' as const, title: 'Encoded command detected' },
    { pattern: /downloadstring|iex|invoke-expression/i, severity: 'critical' as const, title: 'PowerShell download and execute' },
    { pattern: /invoke-mimikatz/i, severity: 'critical' as const, title: 'Mimikatz PowerShell module' },
    { pattern: /bypass.*policy|noprofile/i, severity: 'highly_suspicious' as const, title: 'PowerShell execution policy bypass' },
    { pattern: /hidden.*window|windowstyle.*hidden/i, severity: 'highly_suspicious' as const, title: 'Hidden window execution' },
  ];

  for (const [pid, cmd] of Array.from(commandLines.entries())) {
    for (const sp of suspiciousCmdPatterns) {
      if (sp.pattern.test(cmd)) {
        findings.push({
          category: 'suspicious_command',
          severity: sp.severity,
          title: `${sp.title} (PID ${pid})`,
          description: `Process with suspicious command line: ${cmd.substring(0, 300)}`,
          evidence: cmd,
        });
      }
    }
  }

  // 4. Suspicious network connections
  const suspiciousPorts = [4444, 5555, 6666, 6667, 1337, 31337, 1234, 8888, 9999];
  for (const conn of connections) {
    if (conn.remotePort > 0 && suspiciousPorts.includes(conn.remotePort)) {
      findings.push({
        category: 'suspicious_connection',
        severity: 'critical',
        title: `Connection to common C2 port: ${conn.remoteAddress}:${conn.remotePort}`,
        description: `${conn.processName} (PID ${conn.pid}) connected to ${conn.remoteAddress}:${conn.remotePort} (${conn.protocol}). This port is commonly used by backdoors and RATs.`,
        evidence: `${conn.localAddress}:${conn.localPort} -> ${conn.remoteAddress}:${conn.remotePort}`,
      });
    }

    // ESTABLISHED connections to unusual foreign addresses
    if (conn.state === 'ESTABLISHED' && conn.remoteAddress && conn.remoteAddress !== '0.0.0.0' && conn.remoteAddress !== '::') {
      // Check for known C2 patterns in address
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(conn.remoteAddress)) {
        const octets = conn.remoteAddress.split('.').map(Number);
        if (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168)) {
          // Private IP — note it
          findings.push({
            category: 'network_activity',
            severity: 'suspicious',
            title: `Connection to private IP: ${conn.remoteAddress}:${conn.remotePort}`,
            description: `${conn.processName} (PID ${conn.pid}) has established connection to private IP ${conn.remoteAddress}:${conn.remotePort}. Could indicate lateral movement.`,
            evidence: `${conn.localAddress}:${conn.localPort} -> ${conn.remoteAddress}:${conn.remotePort}`,
          });
        }
      }
    }
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeMemoryDump(filePath: string): Volatility3Result {
  if (!existsSync(filePath)) {
    return {
      available: false,
      detectedOS: 'unknown',
      osInfo: null,
      processes: [],
      hiddenProcesses: [],
      networkConnections: [],
      commandLines: new Map(),
      registryHives: [],
      suspiciousFindings: [],
      pluginResults: {},
      errors: [`File not found: ${filePath}`],
    };
  }

  console.log(`[JURI-X Volatility] Starting analysis of ${basename(filePath)}`);

  const volBin = findVolatilityBinary();
  if (!volBin) {
    console.warn('[JURI-X Volatility] Volatility3 not found. Install volatility3 for memory dump analysis.');
    return {
      available: false,
      detectedOS: 'unknown',
      osInfo: null,
      processes: [],
      hiddenProcesses: [],
      networkConnections: [],
      commandLines: new Map(),
      registryHives: [],
      suspiciousFindings: [],
      pluginResults: {},
      errors: ['Volatility3 is not installed. Install from https://github.com/volatilityfoundation/volatility3'],
    };
  }

  const errors: string[] = [];
  const pluginResults: Record<string, boolean> = {};
  const allProcesses: ProcessEntry[] = [];
  const hiddenProcesses: ProcessEntry[] = [];
  let networkConnections: NetworkConnection[] = [];
  const commandLines = new Map<number, string>();
  let registryHives: RegistryHive[] = [];
  let osInfo: OsInfo | null = null;
  let detectedOS: DetectedOS = 'unknown';

  // ── Step 1: Detect OS type via windows.info.Info ──────────────────────

  const infoOutput = runPlugin(volBin, filePath, 'windows.info.Info');
  pluginResults['windows.info.Info'] = infoOutput !== null;

  if (infoOutput) {
    osInfo = parseWindowsInfo(infoOutput);
    detectedOS = detectOSType(infoOutput);
    console.log(`[JURI-X Volatility] OS detected: ${detectedOS} — ${osInfo.osName} ${osInfo.osVersion}`);
  } else {
    // Fallback: detect from file
    detectedOS = detectOSFromFile(filePath);
    console.log(`[JURI-X Volatility] OS detection from info plugin failed, falling back to file analysis: ${detectedOS}`);
  }

  // ── Step 2: Run OS-specific plugins ───────────────────────────────────

  if (detectedOS === 'windows') {
    // Active process list
    const pslistOutput = runPlugin(volBin, filePath, 'windows.pslist.PsList');
    pluginResults['windows.pslist.PsList'] = pslistOutput !== null;
    if (pslistOutput) {
      allProcesses.push(...parseWindowsPsList(pslistOutput, 'pslist'));
      console.log(`[JURI-X Volatility] Processes (pslist): ${allProcesses.length}`);
    }

    // Hidden/terminated processes
    const psscanOutput = runPlugin(volBin, filePath, 'windows.psscan.PsScan', 120_000);
    pluginResults['windows.psscan.PsScan'] = psscanOutput !== null;
    if (psscanOutput) {
      hiddenProcesses.push(...parseWindowsPsScan(psscanOutput));
      console.log(`[JURI-X Volatility] Processes (psscan): ${hiddenProcesses.length}`);
    }

    // Network connections
    const netstatOutput = runPlugin(volBin, filePath, 'windows.netstat.NetStat');
    pluginResults['windows.netstat.NetStat'] = netstatOutput !== null;
    if (netstatOutput) {
      networkConnections = parseWindowsNetStat(netstatOutput);
      console.log(`[JURI-X Volatility] Network connections: ${networkConnections.length}`);
    }

    // Command lines
    const cmdlineOutput = runPlugin(volBin, filePath, 'windows.cmdline.CmdLine');
    pluginResults['windows.cmdline.CmdLine'] = cmdlineOutput !== null;
    if (cmdlineOutput) {
      const parsedCmds = parseWindowsCmdLine(cmdlineOutput);
      parsedCmds.forEach((v, k) => commandLines.set(k, v));
      console.log(`[JURI-X Volatility] Command lines: ${commandLines.size}`);
    }

    // Registry hives
    const hivelistOutput = runPlugin(volBin, filePath, 'windows.registry.hivelist.HiveList');
    pluginResults['windows.registry.hivelist.HiveList'] = hivelistOutput !== null;
    if (hivelistOutput) {
      registryHives = parseWindowsHiveList(hivelistOutput);
      console.log(`[JURI-X Volatility] Registry hives: ${registryHives.length}`);
    }

    // DumpFiles (file extraction info — note: this can be very large)
    const dumpfilesOutput = runPlugin(volBin, filePath, 'windows.dumpfiles.DumpFiles', 120_000);
    pluginResults['windows.dumpfiles.DumpFiles'] = dumpfilesOutput !== null;
    if (dumpfilesOutput) {
      const dumpRows = parseCSV(dumpfilesOutput);
      console.log(`[JURI-X Volatility] Extractable files: ${dumpRows.length}`);
    }
  } else if (detectedOS === 'linux') {
    // Linux process list
    const pslistOutput = runPlugin(volBin, filePath, 'linux.pslist.PsList');
    pluginResults['linux.pslist.PsList'] = pslistOutput !== null;
    if (pslistOutput) {
      allProcesses.push(...parseLinuxPsList(pslistOutput));
      console.log(`[JURI-X Volatility] Linux processes: ${allProcesses.length}`);
    }

    // Linux syscall check
    const syscallOutput = runPlugin(volBin, filePath, 'linux.check_syscall.Syscall');
    pluginResults['linux.check_syscall.Syscall'] = syscallOutput !== null;
    if (syscallOutput) {
      const syscallRows = parseCSV(syscallOutput);
      // Check for hooked syscalls
      const hooked = syscallRows.filter(r =>
        (r['Symbol'] || r['symbol'] || '').includes('unknown') ||
        (r['Module'] || r['module'] || '').includes('unknown') ||
        (r['Handler'] || r['handler'] || '').includes('ftrace')
      );
      if (hooked.length > 0) {
        errors.push(`WARNING: ${hooked.length} potentially hooked syscalls detected`);
      }
      console.log(`[JURI-X Volatility] Syscall check: ${syscallRows.length} entries, ${hooked.length} suspicious`);
    }

    // Bash history
    const bashOutput = runPlugin(volBin, filePath, 'linux.bash.Bash');
    pluginResults['linux.bash.Bash'] = bashOutput !== null;
    if (bashOutput) {
      const bashFindings = parseLinuxBash(bashOutput);
      console.log(`[JURI-X Volatility] Bash history entries analyzed`);
    }
  } else if (detectedOS === 'macos') {
    // macOS process list
    const pslistOutput = runPlugin(volBin, filePath, 'macos.pslist.PsList');
    pluginResults['macos.pslist.PsList'] = pslistOutput !== null;
    if (pslistOutput) {
      allProcesses.push(...parseLinuxPsList(pslistOutput)); // Same CSV format
      console.log(`[JURI-X Volatility] macOS processes: ${allProcesses.length}`);
    }
  } else {
    // Unknown OS — try all plugins
    console.log('[JURI-X Volatility] Unknown OS type, attempting all plugin variants...');

    const winPsList = runPlugin(volBin, filePath, 'windows.pslist.PsList');
    if (winPsList) {
      allProcesses.push(...parseWindowsPsList(winPsList, 'pslist'));
      detectedOS = 'windows';
      pluginResults['windows.pslist.PsList'] = true;
    }

    const linuxPsList = runPlugin(volBin, filePath, 'linux.pslist.PsList');
    if (linuxPsList && allProcesses.length === 0) {
      allProcesses.push(...parseLinuxPsList(linuxPsList));
      detectedOS = 'linux';
      pluginResults['linux.pslist.PsList'] = true;
    }

    const macPsList = runPlugin(volBin, filePath, 'macos.pslist.PsList');
    if (macPsList && allProcesses.length === 0) {
      allProcesses.push(...parseLinuxPsList(macPsList));
      detectedOS = 'macos';
      pluginResults['macos.pslist.PsList'] = true;
    }
  }

  // ── Step 3: Analyze for suspicious findings ───────────────────────────

  const suspiciousFindings = detectSuspiciousProcesses(allProcesses, hiddenProcesses, commandLines, networkConnections);

  // Add OS info finding
  if (osInfo) {
    console.log(`[JURI-X Volatility] Analysis complete: ${allProcesses.length} processes, ${hiddenProcesses.length} hidden, ${networkConnections.length} connections, ${suspiciousFindings.length} suspicious findings`);
  } else {
    console.log(`[JURI-X Volatility] Analysis complete (no OS info): ${allProcesses.length} processes, ${suspiciousFindings.length} suspicious findings`);
  }

  return {
    available: true,
    detectedOS,
    osInfo,
    processes: allProcesses,
    hiddenProcesses,
    networkConnections,
    commandLines,
    registryHives,
    suspiciousFindings,
    pluginResults,
    errors,
  };
}
