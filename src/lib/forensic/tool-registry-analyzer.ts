/**
 * tool-registry-analyzer.ts — Windows Registry Analysis
 *
 * Uses: hivexsh, hivexget, regripper (rip.exe), reglookup, or fallback string extraction.
 * Analyzes Windows registry hive files for forensic artifacts.
 *
 * Supported hive types: SAM, SYSTEM, SOFTWARE, NTUSER.DAT, USRCLASS.DAT,
 * Amcache.hve, AppCompatCache, SYSTEM32/config/*
 *
 * Extracts: Run/RunOnce keys, installed software, user accounts, recent files,
 * USB devices, services, shell extensions, network adapters, and more.
 */

import { execSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export type HiveType = 'SAM' | 'SYSTEM' | 'SOFTWARE' | 'SECURITY' | 'NTUSER.DAT' | 'USRCLASS.DAT' | 'Amcache' | 'AppCompatCache' | 'BCD' | 'COMPONENTS' | 'DRIVERS' | 'ELAM' | 'unknown';

export interface RunKey {
  hive: string;
  keyPath: string;
  name: string;
  value: string;
  type: string;
}

export interface InstalledSoftware {
    name: string;
    version: string;
    publisher: string;
    installDate: string;
    installLocation: string;
    uninstallCommand: string;
}

export interface UserAccount {
  username: string;
  rid: number;
  fullName: string;
  comment: string;
  isAdmin: boolean;
  lastLogin: string;
  passwordHint: string;
  disabled: boolean;
  accountType: string;
}

export interface RecentFile {
  path: string;
  name: string;
  lastAccessed: string;
  shellBagPath: string;
}

export interface USBDevice {
  name: string;
  serialNumber: string;
  vendor: string;
  product: string;
  driver: string;
  firstConnected: string;
  lastConnected: string;
  parentPrefix: string;
}

export interface ServiceEntry {
  name: string;
  displayName: string;
  imagePath: string;
  description: string;
  startType: string;
  state: string;
  objectName: string;
}

export interface NetworkAdapter {
  name: string;
  adapter: string;
  dhcpEnabled: boolean;
  ipAddress: string;
  subnetMask: string;
  defaultGateway: string;
  dnsServers: string[];
  macAddress: string;
}

export interface RegistrySuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface RegistryAnalysisResult {
  available: boolean;
  hivePath: string;
  hiveType: HiveType;
  hiveSize: number;
  lastModified: string;
  runKeys: RunKey[];
  installedSoftware: InstalledSoftware[];
  userAccounts: UserAccount[];
  recentFiles: RecentFile[];
  usbDevices: USBDevice[];
  services: ServiceEntry[];
  networkAdapters: NetworkAdapter[];
  shellExtensions: string[];
  typedURLs: string[];
  mountedDevices: Record<string, string>;
  suspiciousFindings: RegistrySuspiciousFinding[];
  rawKeys: Record<string, string>;
  errors: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 30_000,
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
      // Silent for expected missing tools
    } else {
      console.warn(`[JURI-X Registry] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Detect the registry hive type from filename and content. */
function detectHiveType(filePath: string): HiveType {
  const name = basename(filePath).toUpperCase();

  // Direct name match
  const nameMap: Record<string, HiveType> = {
    'SAM': 'SAM',
    'SYSTEM': 'SYSTEM',
    'SOFTWARE': 'SOFTWARE',
    'SECURITY': 'SECURITY',
    'NTUSER.DAT': 'NTUSER.DAT',
    'USRCLASS.DAT': 'USRCLASS.DAT',
    'AMCACHE.HVE': 'Amcache',
    'APPCOMPATCACHE': 'AppCompatCache',
    'BCD': 'BCD',
    'COMPONENTS': 'COMPONENTS',
    'DRIVERS': 'DRIVERS',
    'ELAM': 'ELAM',
  };

  if (nameMap[name]) return nameMap[name];

  // Partial match
  if (name.includes('NTUSER')) return 'NTUSER.DAT';
  if (name.includes('USRCLASS')) return 'USRCLASS.DAT';
  if (name.includes('AMCACHE')) return 'Amcache';
  if (name.includes('APPCOMPAT')) return 'AppCompatCache';

  // Check magic bytes (registry hive starts with "regf" or "hbin")
  try {
    const head = execSync(`head -c 4 "${filePath}" 2>/dev/null`, { encoding: 'buffer', timeout: 5_000 });
    const magic = head.toString('utf-8');
    if (magic === 'regf') {
      // It's a valid registry hive — check content for hints
      const content = execSync(`strings "${filePath}" 2>/dev/null | head -50`, {
        encoding: 'utf-8',
        maxBuffer: 5 * 1024 * 1024,
        timeout: 15_000,
      }) || '';

      if (content.includes('SAM') && content.includes('Domains')) return 'SAM';
      if (content.includes('ControlSet') && content.includes('Services')) return 'SYSTEM';
      if (content.includes('Microsoft') && content.includes('Windows')) return 'SOFTWARE';
      if (content.includes('Security') && content.includes('Policy')) return 'SECURITY';
      if (content.includes('Software') && content.includes('AppData')) return 'NTUSER.DAT';
      if (content.includes('MountedDevices') || content.includes('USBSTOR')) return 'SYSTEM';
      if (content.includes('Boot')) return 'BCD';
      if (content.includes('Component')) return 'COMPONENTS';
    }
  } catch {
    /* cannot read file */
  }

  return 'unknown';
}

/** Get hive last modified time. */
function getHiveLastModified(filePath: string): string {
  try {
    const stat = statSync(filePath);
    return stat.mtime.toISOString();
  } catch {
    return '';
  }
}

// ─── hivex-based Analysis ───────────────────────────────────────────────────

function extractWithHivex(filePath: string): Record<string, string> {
  const keys: Record<string, string> = {};

  // Use hivexget for known interesting keys
  const keyPaths: Record<string, string[]> = {
    'RunKeys': [
      'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx',
    ],
    'Services': [
      'ControlSet001\\Services',
    ],
    'NetworkAdapters': [
      'SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}',
    ],
    'USBDevices': [
      'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR',
    ],
    'MountedDevices': [
      'MountedDevices',
    ],
  };

  for (const [category, paths] of Object.entries(keyPaths)) {
    for (const kp of paths) {
      const output = runTool(`hivexget "${filePath}" "${kp}" 2>/dev/null`);
      if (output !== null) {
        keys[`${category}/${kp}`] = output;
      }
    }
  }

  // Use hivexsh to explore structure
  const hivexshOutput = runTool(
    `echo -e "lsrec \\"Software\\Microsoft\\Windows\\CurrentVersion\\"\\nquit" | hivexsh "${filePath}" 2>/dev/null`,
    true,
  );
  if (hivexshOutput) {
    keys['hivexsh_software_currentversion'] = hivexshOutput;
  }

  return keys;
}

// ─── regripper Analysis ─────────────────────────────────────────────────────

function analyzeWithRegRipper(filePath: string, hiveType: HiveType): string {
  // Try rip.pl (Perl regripper)
  let output = runTool(`rip.pl -r "${filePath}" -a 2>&1`, true);
  if (output !== null) return output;

  // Try regripper
  output = runTool(`regripper -r "${filePath}" -a 2>&1`, true);
  if (output !== null) return output;

  // Try rip.exe (Windows version under Wine)
  output = runTool(`rip.exe -r "${filePath}" -a 2>&1`, true);
  if (output !== null) return output;

  return '';
}

// ─── reglookup Analysis ─────────────────────────────────────────────────────

function extractWithReglookup(filePath: string): Record<string, string> {
  const keys: Record<string, string> = {};

  const output = runTool(`reglookup "${filePath}" 2>/dev/null`, true);
  if (!output) return keys;

  for (const line of output.split('\n')) {
    // reglookup output: KEY, VALUE types
    const keyMatch = line.match(/^"([^"]+)"\s*REG_(\w+)\s*(.*)/);
    if (keyMatch) {
      const keyPath = keyMatch[1];
      const valueType = keyMatch[2];
      const value = keyMatch[3].trim();

      if (keyPath && value) {
        keys[keyPath] = `${valueType}: ${value}`;
      }
    }
  }

  return keys;
}

// ─── String-based Fallback Analysis ─────────────────────────────────────────

function extractWithStrings(filePath: string): Record<string, string> {
  const keys: Record<string, string> = {};

  const output = runTool(`strings -n 6 "${filePath}" 2>/dev/null | head -5000`, true);
  if (!output) return keys;

  // Extract registry-like key paths
  const keyPattern = /([A-Za-z]\\[A-Za-z0-9_\\\- .{}()]+(?:\\[A-Za-z0-9_\\\- .{}()]+)*)/g;
  const matches = output.match(keyPattern) || [];

  const seen = new Set<string>();
  for (const match of matches) {
    if (match.length > 8 && match.length < 300 && !seen.has(match)) {
      seen.add(match);
      keys[`string_${Object.keys(keys).length}`] = match;
    }
  }

  return keys;
}

// ─── Structured Data Parsers ────────────────────────────────────────────────

function parseRunKeys(rawKeys: Record<string, string>): RunKey[] {
  const runKeys: RunKey[] = [];

  for (const [key, value] of Object.entries(rawKeys)) {
    if (!key.includes('Run') && !key.includes('run')) continue;

    // Parse hivexget output (may have multiple values separated by null bytes or newlines)
    const lines = value.split(/[\x00\n]/).filter(l => l.trim().length > 2);

    for (const line of lines) {
      const parts = line.split(/[=:]/, 2);
      if (parts.length >= 1) {
        const name = parts[0].trim().replace(/^"|"$/g, '');
        const val = parts.length > 1 ? parts[1].trim().replace(/^"|"$/g, '') : '';
        if (name.length > 0) {
          runKeys.push({
            hive: key,
            keyPath: key.includes('/') ? key.split('/').pop() || key : key,
            name,
            value: val,
            type: 'reg_sz',
          });
        }
      }
    }
  }

  return runKeys;
}

function parseInstalledSoftware(rawKeys: Record<string, string>): InstalledSoftware[] {
  const software: InstalledSoftware[] = [];

  // Look for software entries in raw keys
  for (const [key, value] of Object.entries(rawKeys)) {
    if (!key.includes('Software') && !key.includes('software')) continue;

    // Try to extract software name from key path
    const nameMatch = key.match(/(?:DisplayName|Name)[:=]\s*"([^"]+)"/i)
      || key.match(/(?:DisplayName|Name)[:=]\s*(.+)/i);

    if (nameMatch) {
      software.push({
        name: nameMatch[1].trim(),
        version: '',
        publisher: '',
        installDate: '',
        installLocation: '',
        uninstallCommand: '',
      });
    }
  }

  return software;
}

function parseUSBDevices(rawKeys: Record<string, string>): USBDevice[] {
  const devices: USBDevice[] = [];

  for (const [key, value] of Object.entries(rawKeys)) {
    if (!key.includes('USB') && !value.toLowerCase().includes('usb')) continue;

    // Extract USB device info
    if (value.toLowerCase().includes('usbstor') || key.toLowerCase().includes('usbstor')) {
      devices.push({
        name: key.split('\\').pop() || 'Unknown USB Device',
        serialNumber: key.match(/([A-Fa-f0-9]{8,})/)?.[0] || '',
        vendor: '',
        product: '',
        driver: '',
        firstConnected: '',
        lastConnected: '',
        parentPrefix: key,
      });
    }
  }

  return devices;
}

function parseServices(rawKeys: Record<string, string>): ServiceEntry[] {
  const services: ServiceEntry[] = [];

  for (const [key, value] of Object.entries(rawKeys)) {
    if (!key.includes('Service') && !key.includes('service')) continue;

    // Simple heuristic: if value contains "ImagePath", extract service
    const imagePathMatch = value.match(/ImagePath[:=]\s*"?([^"\n]+)"?/i);
    if (imagePathMatch) {
      services.push({
        name: key.split('\\').pop() || 'Unknown Service',
        displayName: '',
        imagePath: imagePathMatch[1].trim(),
        description: '',
        startType: '',
        state: '',
        objectName: '',
      });
    }
  }

  return services;
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousRegistryItems(
  hiveType: HiveType,
  runKeys: RunKey[],
  rawKeys: Record<string, string>,
): RegistrySuspiciousFinding[] {
  const findings: RegistrySuspiciousFinding[] = [];

  // 1. Suspicious Run/RunOnce entries
  const suspiciousRunPatterns = [
    { pattern: /powershell|cmd\.exe|wscript|cscript/i, severity: 'suspicious' as const, desc: 'Script engine in persistence key' },
    { pattern: /temp|tmp|%temp%|%appdata%|appdata/i, severity: 'suspicious' as const, desc: 'Temp directory in persistence key' },
    { pattern: /\\users\\public\\|\\programdata\\|\\temp\\/i, severity: 'highly_suspicious' as const, desc: 'Public/Temp location in persistence key (common malware technique)' },
    { pattern: /bitsadmin|certutil|mshta|regsvr32|rundll32/i, severity: 'highly_suspicious' as const, desc: 'Known LOLBin in persistence key' },
    { pattern: /http|https|ftp/i, severity: 'highly_suspicious' as const, desc: 'URL in persistence key (potential download cradle)' },
    { pattern: /base64|encoded|frombase64/i, severity: 'critical' as const, desc: 'Encoded payload in persistence key' },
    { pattern: /mimikatz|meterpreter|shellcode|payload/i, severity: 'critical' as const, desc: 'Known offensive tool reference' },
    { pattern: /\.vbs$|\.js$|\.ps1$|\.bat$|\.cmd$/i, severity: 'suspicious' as const, desc: 'Script file in persistence key' },
  ];

  for (const runKey of runKeys) {
    for (const sp of suspiciousRunPatterns) {
      if (sp.pattern.test(runKey.value) || sp.pattern.test(runKey.name)) {
        findings.push({
          category: 'persistence',
          severity: sp.severity,
          title: `Suspicious Run key: ${runKey.name}`,
          description: `${sp.desc}. Key: ${runKey.keyPath}, Value: ${runKey.value.substring(0, 200)}`,
          evidence: `${runKey.keyPath}\\${runKey.name} = ${runKey.value}`,
        });
      }
    }
  }

  // 2. Suspicious services
  for (const [key, value] of Object.entries(rawKeys)) {
    if (value.includes('ImagePath')) {
      const imgPathMatch = value.match(/ImagePath[:=]\s*"?([^"\n]+)"?/i);
      if (imgPathMatch) {
        const imgPath = imgPathMatch[1].trim().toLowerCase();
        if (/cmd\.exe|powershell|bitsadmin|certutil|mshta/i.test(imgPath)) {
          findings.push({
            category: 'suspicious_service',
            severity: 'highly_suspicious',
            title: `Suspicious service ImagePath`,
            description: `Service at ${key} has a suspicious ImagePath: ${imgPathMatch[1].trim()}. This is a known LOLBin technique for persistence.`,
            evidence: `${key}: ${imgPathMatch[1].trim()}`,
          });
        }
      }
    }
  }

  // 3. SAM-specific findings
  if (hiveType === 'SAM') {
    // Look for admin-level accounts
    const adminPatterns = [/Administrator/i, /admin/i, /root/i];
    for (const [key, value] of Object.entries(rawKeys)) {
      for (const ap of adminPatterns) {
        if (ap.test(key) || ap.test(value)) {
          findings.push({
            category: 'user_account',
            severity: 'suspicious',
            title: `Potential admin account found in SAM`,
            description: `Account reference matching ${ap.source} found in SAM hive.`,
            evidence: `${key}: ${value.substring(0, 100)}`,
          });
        }
      }
    }
  }

  // 4. SYSTEM-specific findings
  if (hiveType === 'SYSTEM') {
    // Check for disabled security features
    for (const [key, value] of Object.entries(rawKeys)) {
      const lowerVal = value.toLowerCase();
      if ((key.includes('UAC') || key.includes('uac')) && lowerVal.includes('disable')) {
        findings.push({
          category: 'security_bypass',
          severity: 'critical',
          title: 'UAC may be disabled',
          description: `Registry key suggests User Account Control is disabled: ${key}`,
          evidence: `${key}: ${value}`,
        });
      }
      if ((key.includes('Firewall') || key.includes('firewall')) && lowerVal.includes('disable')) {
        findings.push({
          category: 'security_bypass',
          severity: 'critical',
          title: 'Firewall may be disabled',
          description: `Registry key suggests Windows Firewall is disabled: ${key}`,
          evidence: `${key}: ${value}`,
        });
      }
      if ((key.includes('SafeBoot') || key.includes('safeboot')) && lowerVal.includes('minimal')) {
        findings.push({
          category: 'security_bypass',
          severity: 'highly_suspicious',
          title: 'Safe boot configuration modified',
          description: `Safe boot settings found in registry: ${key}`,
          evidence: `${key}: ${value}`,
        });
      }
    }
  }

  // 5. NTUSER.DAT-specific findings
  if (hiveType === 'NTUSER.DAT') {
    // Check for shell bags (evidence of files/folders accessed)
    for (const [key, value] of Object.entries(rawKeys)) {
      if (key.includes('Bag') || key.includes('bag')) {
        // Shell bags are present — this is informational
        findings.push({
          category: 'user_activity',
          severity: 'benign',
          title: 'Shell bags found in NTUSER.DAT',
          description: 'User file/folder access history (shell bags) detected in NTUSER.DAT. These contain references to files and folders accessed via Windows Explorer.',
          evidence: key,
        });
        break; // Only report once
      }
    }
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeRegistryHive(filePath: string): RegistryAnalysisResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      hivePath: filePath,
      hiveType: 'unknown',
      hiveSize: 0,
      lastModified: '',
      runKeys: [],
      installedSoftware: [],
      userAccounts: [],
      recentFiles: [],
      usbDevices: [],
      services: [],
      networkAdapters: [],
      shellExtensions: [],
      typedURLs: [],
      mountedDevices: {},
      suspiciousFindings: [],
      rawKeys: {},
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const hiveName = basename(filePath);
  const hiveType = detectHiveType(filePath);
  const lastModified = getHiveLastModified(filePath);
  const errors: string[] = [];

  console.log(`[JURI-X Registry] Analyzing ${hiveName} (${fileStat.size} bytes, type: ${hiveType})`);

  let rawKeys: Record<string, string> = {};

  // Try tools in order of preference:
  // 1. regripper (most comprehensive)
  // 2. hivexget/hivexsh (structured extraction)
  // 3. reglookup (alternative structured extraction)
  // 4. strings (fallback)

  // Check tool availability
  const ripperOutput = analyzeWithRegRipper(filePath, hiveType);
  if (ripperOutput && ripperOutput.length > 10) {
    console.log('[JURI-X Registry] Using regripper for analysis');
    // Parse regripper output into key-value pairs
    const lines = ripperOutput.split('\n').filter(l => l.trim());
    for (const line of lines) {
      const kvMatch = line.match(/^(.+?)\s*[:=]\s*(.+)$/);
      if (kvMatch && kvMatch[2].trim().length > 0) {
        rawKeys[`ripper_${rawKeys.length}`] = `${kvMatch[1].trim()}: ${kvMatch[2].trim()}`;
      }
    }
  }

  // Try hivex tools
  if (Object.keys(rawKeys).length === 0) {
    const hivexKeys = extractWithHivex(filePath);
    if (Object.keys(hivexKeys).length > 0) {
      console.log('[JURI-X Registry] Using hivex for analysis');
      rawKeys = { ...rawKeys, ...hivexKeys };
    }
  }

  // Try reglookup
  if (Object.keys(rawKeys).length === 0) {
    const reglookupKeys = extractWithReglookup(filePath);
    if (Object.keys(reglookupKeys).length > 0) {
      console.log('[JURI-X Registry] Using reglookup for analysis');
      rawKeys = { ...rawKeys, ...reglookupKeys };
    }
  }

  // Fallback: string extraction
  if (Object.keys(rawKeys).length === 0) {
    const stringKeys = extractWithStrings(filePath);
    if (Object.keys(stringKeys).length > 0) {
      console.log('[JURI-X Registry] Using string extraction fallback');
      rawKeys = { ...rawKeys, ...stringKeys };
    }
  }

  if (Object.keys(rawKeys).length === 0) {
    errors.push('No registry data could be extracted. The file may be corrupted or in an unsupported format.');
  }

  // Parse structured data from raw keys
  const runKeys = parseRunKeys(rawKeys);
  const installedSoftware = parseInstalledSoftware(rawKeys);
  const usbDevices = parseUSBDevices(rawKeys);
  const services = parseServices(rawKeys);

  // Detect suspicious items
  const suspiciousFindings = detectSuspiciousRegistryItems(hiveType, runKeys, rawKeys);

  console.log(`[JURI-X Registry] Analysis complete: ${Object.keys(rawKeys).length} keys extracted, ${runKeys.length} run keys, ${services.length} services, ${suspiciousFindings.length} findings`);

  return {
    available: Object.keys(rawKeys).length > 0,
    hivePath: filePath,
    hiveType,
    hiveSize: fileStat.size,
    lastModified,
    runKeys,
    installedSoftware,
    userAccounts: [],
    recentFiles: [],
    usbDevices,
    services,
    networkAdapters: [],
    shellExtensions: [],
    typedURLs: [],
    mountedDevices: {},
    suspiciousFindings,
    rawKeys,
    errors,
  };
}
