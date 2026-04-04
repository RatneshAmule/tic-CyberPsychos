/**
 * tool-yara.ts — YARA Malware Detection
 *
 * Uses: YARA pattern matching for malware detection, threat hunting,
 * and indicator-of-compromise (IOC) scanning.
 *
 * Includes built-in YARA rules for common malware families:
 * ransomware indicators, credential stealers, keyloggers, backdoors,
 * exploit patterns, and suspicious binary strings.
 *
 * Falls back gracefully if YARA is not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { basename, dirname, join } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface YARARuleMatch {
  rule: string;
  description: string;
  offset: number;
  tags: string[];
}

export interface YARASuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
  matchedRules: string[];
}

export interface YARAResult {
  available: boolean;
  filePath: string;
  matchedRules: YARARuleMatch[];
  totalMatches: number;
  suspiciousFindings: YARASuspiciousFinding[];
  toolUsed: string;
  errors: string[];
}

// ─── Built-in YARA Rules ────────────────────────────────────────────────────

const YARA_RULES_DIR = '/tmp/juri-x/rules';
const YARA_RULES_FILE = `${YARA_RULES_DIR}/malware_rules.yar`;

const BUILTIN_YARA_RULES = `// ─── JURI-X Built-in Malware Detection Rules ────────────────────────────
// Auto-generated rules for ransomware, stealers, keyloggers, backdoors,
// exploit patterns, and suspicious binary strings.

// ─── Ransomware Indicators ──────────────────────────────────────────────────

rule JURI_Ransomware_WannaCry_Indicator {
  meta:
    description = "WannaCry ransomware indicator strings"
    severity = "critical"
    family = "WannaCry"
  strings:
    $s1 = "WANACRY!" wide ascii nocase
    $s2 = "@WanaDecryptor@" wide ascii nocase
    $s3 = "taskse.exe" wide ascii nocase
    $s4 = "Please_Read_Me.txt" wide ascii nocase
    $s5 = ".WNCRY" wide ascii
  condition:
    2 of ($s*)
}

rule JURI_Ransomware_Cerber_Indicator {
  meta:
    description = "Cerber ransomware indicator strings"
    severity = "critical"
    family = "Cerber"
  strings:
    $s1 = "DECRYPT_INSTRUCTIONS.html" wide ascii nocase
    $s2 = "# DECRYPT MY FILES #" wide ascii nocase
    $s3 = "Cerber" wide ascii nocase
    $s4 = "_READ_ME_.txt" wide ascii nocase
    $s5 = ".cerber" wide ascii
  condition:
    2 of ($s*)
}

rule JURI_Ransomware_Locky_Indicator {
  meta:
    description = "Locky ransomware indicator strings"
    severity = "critical"
    family = "Locky"
  strings:
    $s1 = "locky" ascii nocase
    $s2 = "locky_decryptor" ascii nocase
    $s3 = "_Locky_recover_instructions" ascii nocase
    $s4 = ".locky" ascii
    $s5 = "HERMES" wide ascii nocase
  condition:
    2 of ($s*)
}

rule JURI_Ransomware_Ryuk_Indicator {
  meta:
    description = "Ryuk ransomware indicator strings"
    severity = "critical"
    family = "Ryuk"
  strings:
    $s1 = "RyukReadMe.txt" wide ascii nocase
    $s2 = "Ryuk" wide ascii nocase
    $s3 = "HERMES" wide ascii nocase
    $s4 = "SOS" ascii wide
  condition:
    2 of ($s*)
}

rule JURI_Ransomware_Generic_Extension {
  meta:
    description = "Generic ransomware file extension indicators"
    severity = "high"
    family = "Generic"
  strings:
    $s1 = ".encrypted" ascii
    $s2 = ".locked" ascii
    $s3 = ".crypt" ascii
    $s4 = ".crypz" ascii
    $s5 = ".crypto" ascii
    $s6 = ".enc" ascii
    $s7 = "DECRYPT_FILES" ascii nocase wide
    $s8 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase wide
    $s9 = "pay_the_bitcoin" ascii nocase wide
    $s10 = "recover_files" ascii nocase wide
  condition:
    3 of ($s*)
}

// ─── Credential Stealers ────────────────────────────────────────────────────

rule JURI_Stealer_RedLine_Indicator {
  meta:
    description = "RedLine credential stealer indicators"
    severity = "critical"
    family = "RedLine"
  strings:
    $s1 = "RedLine" ascii nocase
    $s2 = "AntiDebug" ascii nocase
    $s3 = "SQLite3" ascii
    $s4 = "chrome" ascii nocase
    $s5 = "Login Data" ascii nocase
  condition:
    2 of ($s*)
}

rule JURI_Stealer_Raccoon_Indicator {
  meta:
    description = "Raccoon Stealer indicators"
    severity = "critical"
    family = "Raccoon"
  strings:
    $s1 = "Raccoon" ascii nocase
    $s2 = "cookies.sqlite" ascii nocase
    $s3 = "logins.json" ascii nocase
    $s4 = "key4.db" ascii nocase
  condition:
    2 of ($s*)
}

rule JURI_Stealer_Generic_Browser_Theft {
  meta:
    description = "Generic browser credential theft indicators"
    severity = "high"
    family = "Generic"
  strings:
    $s1 = "Login Data" ascii nocase
    $s2 = "Web Data" ascii nocase
    $s3 = "Cookies" ascii nocase
    $s4 = "Chrome" ascii nocase
    $s5 = "Firefox" ascii nocase
    $s6 = "sqlite3" ascii nocase
    $s7 = "SELECT * FROM" ascii nocase
    $s8 = "autofill" ascii nocase
  condition:
    4 of ($s*)
}

// ─── Keyloggers ─────────────────────────────────────────────────────────────

rule JURI_Keylogger_Generic_Indicator {
  meta:
    description = "Generic keylogger indicators"
    severity = "high"
    family = "Keylogger"
  strings:
    $s1 = "GetAsyncKeyState" ascii nocase
    $s2 = "GetKeyState" ascii nocase
    $s3 = "SetWindowsHookEx" ascii nocase
    $s4 = "WH_KEYBOARD_LL" ascii nocase
    $s5 = "keylog" ascii nocase
    $s6 = "keystroke" ascii nocase
    $s7 = "hook" ascii nocase
    $s8 = "GetForegroundWindow" ascii nocase
  condition:
    3 of ($s*)
}

rule JURI_Keylogger_Hook_Based {
  meta:
    description = "Windows hook-based keylogger"
    severity = "critical"
    family = "Keylogger"
  strings:
    $s1 = "SetWindowsHookExA" ascii
    $s2 = "SetWindowsHookExW" ascii
    $s3 = "CallNextHookEx" ascii
    $s4 = "UnhookWindowsHookEx" ascii
    $s5 = "WH_KEYBOARD" ascii
  condition:
    3 of ($s*)
}

// ─── Backdoors ──────────────────────────────────────────────────────────────

rule JURI_Backdoor_ReverseShell_Indicator {
  meta:
    description = "Reverse shell backdoor indicators"
    severity = "critical"
    family = "Backdoor"
  strings:
    $s1 = "/bin/sh" ascii
    $s2 = "/bin/bash" ascii
    $s3 = "socket" ascii nocase
    $s4 = "connect" ascii nocase
    $s5 = "dup2" ascii nocase
    $s6 = "exec" ascii nocase
    $s7 = "0.0.0.0" ascii
    $s8 = "cmd.exe" ascii
  condition:
    4 of ($s*)
}

rule JURI_Backdoor_PHP_WebShell {
  meta:
    description = "PHP web shell indicators"
    severity = "critical"
    family = "WebShell"
  strings:
    $s1 = "eval(" ascii nocase
    $s2 = "base64_decode" ascii nocase
    $s3 = "system(" ascii nocase
    $s4 = "exec(" ascii nocase
    $s5 = "shell_exec(" ascii nocase
    $s6 = "passthru(" ascii nocase
    $s7 = "$_POST" ascii nocase
    $s8 = "$_GET" ascii nocase
    $s9 = "$_REQUEST" ascii nocase
    $s10 = "assert(" ascii nocase
  condition:
    5 of ($s*)
}

rule JURI_Backdoor_Python_Reverse {
  meta:
    description = "Python reverse shell indicators"
    severity = "critical"
    family = "Backdoor"
  strings:
    $s1 = "import socket" ascii
    $s2 = "import subprocess" ascii
    $s3 = "s.connect" ascii
    $s4 = "subprocess.call" ascii
    $s5 = "os.dup2" ascii
    $s6 = "pty.spawn" ascii
  condition:
    3 of ($s*)
}

rule JURI_Backdoor_Meterpreter_Indicator {
  meta:
    description = "Meterpreter payload indicators"
    severity = "critical"
    family = "Meterpreter"
  strings:
    $s1 = "meterpreter" ascii nocase
    $s2 = "metsrv" ascii nocase
    $s3 = "ReflectiveLoader" ascii nocase
    $s4 = "migrate" ascii nocase
    $s5 = "sys_inject" ascii nocase
  condition:
    2 of ($s*)
}

// ─── Exploit Patterns ───────────────────────────────────────────────────────

rule JURI_Exploit_BufferOverflow_Indicator {
  meta:
    description = "Buffer overflow exploit indicators"
    severity = "high"
    family = "Exploit"
  strings:
    $s1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }   // NOP sled
    $s2 = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 } // /bin/sh shellcode
    $s3 = { 6A 0B 58 99 52 68 2F 2F 73 68 }                   // execve shellcode
  condition:
    any of them
}

rule JURI_Exploit_PowerShell_Download {
  meta:
    description = "PowerShell-based download cradle"
    severity = "high"
    family = "Exploit"
  strings:
    $s1 = "Invoke-WebRequest" ascii nocase
    $s2 = "Invoke-Expression" ascii nocase
    $s3 = "DownloadString" ascii nocase
    $s4 = "IEX" ascii
    $s5 = "Start-BitsTransfer" ascii nocase
    $s6 = "Net.WebClient" ascii nocase
    $s7 = "New-Object" ascii nocase
    $s8 = "-WindowStyle Hidden" ascii nocase
  condition:
    3 of ($s*)
}

rule JURI_Exploit_SMB_Mimikatz {
  meta:
    description = "Mimikatz credential dumping indicators"
    severity = "critical"
    family = "Mimikatz"
  strings:
    $s1 = "mimikatz" ascii nocase wide
    $s2 = "sekurlsa::logonpasswords" ascii nocase wide
    $s3 = "lsadump::sam" ascii nocase wide
    $s4 = "kerberos::list" ascii nocase wide
    $s5 = "privilege::debug" ascii nocase wide
  condition:
    2 of ($s*)
}

// ─── Suspicious Binary Strings ──────────────────────────────────────────────

rule JURI_Suspicious_Password_Strings {
  meta:
    description = "Hardcoded password or credential strings"
    severity = "high"
    family = "Credential"
  strings:
    $s1 = "password" ascii nocase wide
    $s2 = "passwd" ascii nocase wide
    $s3 = "secret" ascii nocase wide
    $s4 = "credential" ascii nocase wide
    $s5 = "api_key" ascii nocase wide
    $s6 = "apikey" ascii nocase wide
    $s7 = "access_token" ascii nocase wide
    $s8 = "auth_token" ascii nocase wide
    $s9 = "private_key" ascii nocase wide
    $s10 = "Bearer" ascii wide
  condition:
    3 of ($s*)
}

rule JURI_Suspicious_Crypto_Mining {
  meta:
    description = "Cryptocurrency mining indicators"
    severity = "high"
    family = "CryptoMiner"
  strings:
    $s1 = "stratum+tcp" ascii nocase
    $s2 = "pool." ascii nocase
    $s3 = "minerd" ascii nocase
    $s4 = "xmrig" ascii nocase
    $s5 = "cryptonight" ascii nocase
    $s6 = "monero" ascii nocase
    $s7 = "XMR" ascii
    $s8 = "Bitcoin" ascii
  condition:
    3 of ($s*)
}

rule JURI_Suspicious_AntiAnalysis {
  meta:
    description = "Anti-analysis and anti-debugging techniques"
    severity = "high"
    family = "AntiAnalysis"
  strings:
    $s1 = "IsDebuggerPresent" ascii nocase
    $s2 = "CheckRemoteDebuggerPresent" ascii nocase
    $s3 = "NtQueryInformationProcess" ascii nocase
    $s4 = "OutputDebugString" ascii nocase
    $s5 = "VirtualAllocEx" ascii nocase
    $s6 = "WriteProcessMemory" ascii nocase
    $s7 = "CreateRemoteThread" ascii nocase
    $s8 = "IsDebuggerPresent" wide nocase
    $s9 = "VMProtect" ascii nocase
    $s10 = "UPX" ascii
  condition:
    3 of ($s*)
}

rule JURI_Suspicious_Network_Beacon {
  meta:
    description = "C2 beacon or callback indicators"
    severity = "high"
    family = "C2"
  strings:
    $s1 = "beacon" ascii nocase
    $s2 = "callback" ascii nocase
    $s3 = "Command and Control" ascii nocase
    $s4 = "C2" ascii
    $s5 = "user-agent" ascii nocase
    $s6 = "Mozilla/4.0" ascii
    $s7 = "Mozilla/5.0" ascii
    $s8 = "sleep(" ascii
  condition:
    3 of ($s*)
}

rule JURI_Suspicious_Dropper {
  meta:
    description = "Dropper/payload delivery indicators"
    severity = "high"
    family = "Dropper"
  strings:
    $s1 = "Temp" ascii nocase
    $s2 = "APPDATA" ascii nocase
    $s3 = "Startup" ascii nocase
    $s4 = "CreateProcess" ascii nocase
    $s5 = "ShellExecute" ascii nocase
    $s6 = "WinExec" ascii nocase
    $s7 = "Registry" ascii nocase
    $s8 = "HKLM" ascii nocase
    $s9 = "HKCU" ascii nocase
    $s10 = "RunOnce" ascii nocase
  condition:
    4 of ($s*)
}

rule JURI_Suspicious_DLL_Sideloading {
  meta:
    description = "DLL sideloading indicators"
    severity = "high"
    family = "DLLSideload"
  strings:
    $s1 = "LoadLibrary" ascii nocase
    $s2 = "GetProcAddress" ascii nocase
    $s3 = ".dll" ascii nocase
    $s4 = "DLL_PROCESS_ATTACH" ascii nocase
    $s5 = "DllMain" ascii nocase
  condition:
    3 of ($s*)
}
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
      console.warn(`[JURI-X YARA] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X YARA] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Ensure built-in YARA rules are written to disk. */
function ensureYARARulesExist(): boolean {
  try {
    if (!existsSync(YARA_RULES_DIR)) {
      mkdirSync(YARA_RULES_DIR, { recursive: true });
    }
    if (!existsSync(YARA_RULES_FILE)) {
      writeFileSync(YARA_RULES_FILE, BUILTIN_YARA_RULES, 'utf-8');
      console.log(`[JURI-X YARA] Wrote built-in rules to ${YARA_RULES_FILE}`);
    }
    return true;
  } catch (err: any) {
    console.warn(`[JURI-X YARA] Failed to write rules: ${err?.message}`);
    return false;
  }
}

/** Check if YARA is installed. */
function isYARAAvailable(): boolean {
  const output = runTool('yara --version 2>/dev/null');
  return output !== null;
}

// ─── YARA Execution ─────────────────────────────────────────────────────────

/** Run YARA against a file with built-in rules. */
function runYARAScan(filePath: string): YARARuleMatch[] {
  const matches: YARARuleMatch[] = [];

  if (!ensureYARARulesExist()) {
    return matches;
  }

  // Run YARA with recursive rule scanning
  const output = runTool(`yara -r "${YARA_RULES_FILE}" "${filePath}" 2>/dev/null`);
  if (!output) return matches;

  // Parse YARA output format:
  // rule_name  file_path  offset
  // JURI_Ransomware_WannaCry_Indicator  /path/to/file  0x1234
  for (const line of output.split('\n')) {
    if (!line.trim()) continue;

    // Split by whitespace — YARA output format: rule_name file_path [offset]
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;

    const ruleName = parts[0];
    const offsetStr = parts.length >= 3 ? parts[2] : '0x0';
    const offset = parseInt(offsetStr.replace('0x', ''), 16) || 0;

    // Extract description from rule name
    let description = ruleName;
    if (ruleName.startsWith('JURI_')) {
      const segments = ruleName.split('_');
      if (segments.length >= 4) {
        description = segments.slice(2, -1).join(' ');
      }
    }

    // Determine tags from rule name
    const tags: string[] = [];
    if (/ransomware/i.test(ruleName)) tags.push('ransomware');
    if (/stealer|theft/i.test(ruleName)) tags.push('stealer');
    if (/keylog/i.test(ruleName)) tags.push('keylogger');
    if (/backdoor|shell/i.test(ruleName)) tags.push('backdoor');
    if (/exploit/i.test(ruleName)) tags.push('exploit');
    if (/suspicious|password|credential/i.test(ruleName)) tags.push('credentials');
    if (/mining|crypto/i.test(ruleName)) tags.push('crypto_mining');
    if (/anti|debug|analysis/i.test(ruleName)) tags.push('anti_analysis');
    if (/beacon|c2|callback/i.test(ruleName)) tags.push('c2');
    if (/dropper/i.test(ruleName)) tags.push('dropper');
    if (/dll/i.test(ruleName)) tags.push('dll_sideloading');
    if (/webshell/i.test(ruleName)) tags.push('webshell');
    if (/meterpreter/i.test(ruleName)) tags.push('meterpreter');
    if (/mimikatz/i.test(ruleName)) tags.push('credential_dumping');

    matches.push({
      rule: ruleName,
      description,
      offset,
      tags,
    });
  }

  return matches;
}

/** Fallback: use strings + pattern matching if YARA not available. */
function fallbackStringScan(filePath: string): YARARuleMatch[] {
  const matches: YARARuleMatch[] = [];

  const patterns = [
    { pattern: /ransomware|wannacry|cerber|locky|ryuk|decrypt|encrypt/i, rule: 'FALLBACK_Ransomware_Indicator', description: 'Ransomware indicator', tags: ['ransomware'] },
    { pattern: /mimikatz|sekurlsa|lsadump/i, rule: 'FALLBACK_Mimikatz_Indicator', description: 'Credential dumping tool', tags: ['credential_dumping'] },
    { pattern: /reverse.shell|backdoor|webshell/i, rule: 'FALLBACK_Backdoor_Indicator', description: 'Backdoor indicator', tags: ['backdoor'] },
    { pattern: /keylog|keystroke|SetWindowsHookEx/i, rule: 'FALLBACK_Keylogger_Indicator', description: 'Keylogger indicator', tags: ['keylogger'] },
    { pattern: /password|passwd|secret|api_key|access_token|private_key/i, rule: 'FALLBACK_Credential_Strings', description: 'Credential strings', tags: ['credentials'] },
    { pattern: /stratum\+tcp|minerd|xmrig|cryptonight|monero/i, rule: 'FALLBACK_CryptoMining_Indicator', description: 'Cryptocurrency mining', tags: ['crypto_mining'] },
    { pattern: /IsDebuggerPresent|CheckRemoteDebugger|VMProtect|UPX/i, rule: 'FALLBACK_AntiAnalysis_Indicator', description: 'Anti-analysis technique', tags: ['anti_analysis'] },
    { pattern: /meterpreter|metsrv|ReflectiveLoader/i, rule: 'FALLBACK_Meterpreter_Indicator', description: 'Meterpreter payload', tags: ['meterpreter'] },
  ];

  const stringsOutput = runTool(`strings -n 6 "${filePath}" 2>/dev/null | head -5000`);
  if (!stringsOutput) return matches;

  const lines = stringsOutput.split('\n');
  for (const { pattern, rule, description, tags } of patterns) {
    let matchCount = 0;
    let firstMatchLine = 0;
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        matchCount++;
        if (firstMatchLine === 0) firstMatchLine = i;
      }
    }
    if (matchCount >= 2) {
      matches.push({
        rule,
        description,
        offset: 0,
        tags,
      });
    }
  }

  return matches;
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousYARA(matches: YARARuleMatch[]): YARASuspiciousFinding[] {
  const findings: YARASuspiciousFinding[] = [];

  if (matches.length === 0) return findings;

  // Group matches by tag
  const tagGroups = new Map<string, YARARuleMatch[]>();
  for (const match of matches) {
    for (const tag of match.tags) {
      if (!tagGroups.has(tag)) tagGroups.set(tag, []);
      tagGroups.get(tag)!.push(match);
    }
  }

  // 1. Ransomware matches — critical
  const ransomware = tagGroups.get('ransomware') || [];
  if (ransomware.length > 0) {
    findings.push({
      category: 'ransomware',
      severity: 'critical',
      title: `Ransomware indicators detected (${ransomware.length} match${ransomware.length > 1 ? 'es' : ''})`,
      description: `YARA rules matched known ransomware patterns including encryption routines, ransom notes, or known ransomware family identifiers.`,
      evidence: ransomware.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: ransomware.map(m => m.rule),
    });
  }

  // 2. Credential dumping — critical
  const credDump = tagGroups.get('credential_dumping') || [];
  if (credDump.length > 0) {
    findings.push({
      category: 'credential_dumping',
      severity: 'critical',
      title: `Credential dumping tools detected`,
      description: `Indicators of credential dumping tools such as Mimikatz were found. This suggests the binary may attempt to extract passwords from memory.`,
      evidence: credDump.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: credDump.map(m => m.rule),
    });
  }

  // 3. Backdoors — critical
  const backdoors = tagGroups.get('backdoor') || [];
  if (backdoors.length > 0) {
    findings.push({
      category: 'backdoor',
      severity: 'critical',
      title: `Backdoor indicators detected (${backdoors.length} match${backdoors.length > 1 ? 'es' : ''})`,
      description: `Reverse shells, web shells, or other backdoor mechanisms were detected. This binary may provide unauthorized remote access.`,
      evidence: backdoors.map(m => `Rule: ${m.rule} (offset: 0x${m.offset.toString(16)})`).join('\n'),
      matchedRules: backdoors.map(m => m.rule),
    });
  }

  // 4. Stealers — highly suspicious
  const stealers = tagGroups.get('stealer') || [];
  if (stealers.length > 0) {
    findings.push({
      category: 'credential_stealer',
      severity: 'highly_suspicious',
      title: `Credential stealer indicators detected`,
      description: `Patterns associated with credential stealing malware (browser data theft, cookie extraction) were found.`,
      evidence: stealers.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: stealers.map(m => m.rule),
    });
  }

  // 5. Keyloggers — highly suspicious
  const keyloggers = tagGroups.get('keylogger') || [];
  if (keyloggers.length > 0) {
    findings.push({
      category: 'keylogger',
      severity: 'highly_suspicious',
      title: `Keylogger indicators detected`,
      description: `Keyboard hooking or keystroke recording functionality was detected. This binary may capture user input including passwords.`,
      evidence: keyloggers.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: keyloggers.map(m => m.rule),
    });
  }

  // 6. Crypto mining — highly suspicious
  const miners = tagGroups.get('crypto_mining') || [];
  if (miners.length > 0) {
    findings.push({
      category: 'crypto_mining',
      severity: 'highly_suspicious',
      title: `Cryptocurrency mining indicators detected`,
      description: `Stratum protocol strings, mining pool URLs, or known mining software (XMRig, etc.) were found.`,
      evidence: miners.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: miners.map(m => m.rule),
    });
  }

  // 7. Exploit tools — highly suspicious
  const exploits = tagGroups.get('exploit') || [];
  if (exploits.length > 0) {
    findings.push({
      category: 'exploit',
      severity: 'highly_suspicious',
      title: `Exploit tool indicators detected`,
      description: `Shellcode, buffer overflow patterns, or PowerShell-based download cradles were found.`,
      evidence: exploits.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: exploits.map(m => m.rule),
    });
  }

  // 8. C2 communication — suspicious
  const c2 = tagGroups.get('c2') || [];
  if (c2.length > 0) {
    findings.push({
      category: 'c2_communication',
      severity: 'suspicious',
      title: `C2 beacon/callback indicators detected`,
      description: `Command and control communication patterns including beacons and callbacks were detected.`,
      evidence: c2.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: c2.map(m => m.rule),
    });
  }

  // 9. Anti-analysis — suspicious
  const antiAnalysis = tagGroups.get('anti_analysis') || [];
  if (antiAnalysis.length > 0) {
    findings.push({
      category: 'anti_analysis',
      severity: 'suspicious',
      title: `Anti-analysis techniques detected`,
      description: `Debugger detection, VM detection, or code obfuscation techniques (VMProtect, UPX) were found. This is common in malware to evade analysis.`,
      evidence: antiAnalysis.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: antiAnalysis.map(m => m.rule),
    });
  }

  // 10. Credential strings — suspicious
  const creds = tagGroups.get('credentials') || [];
  if (creds.length > 0 && stealers.length === 0 && credDump.length === 0) {
    findings.push({
      category: 'embedded_credentials',
      severity: 'suspicious',
      title: `Potential credential strings detected`,
      description: `Strings related to passwords, API keys, tokens, or secrets were found embedded in the binary.`,
      evidence: creds.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: creds.map(m => m.rule),
    });
  }

  // 11. DLL sideloading — suspicious
  const dllSideload = tagGroups.get('dll_sideloading') || [];
  if (dllSideload.length > 0) {
    findings.push({
      category: 'dll_sideloading',
      severity: 'suspicious',
      title: `DLL sideloading indicators detected`,
      description: `Dynamic library loading patterns consistent with DLL sideloading attacks were found.`,
      evidence: dllSideload.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: dllSideload.map(m => m.rule),
    });
  }

  // 12. Dropper — suspicious
  const droppers = tagGroups.get('dropper') || [];
  if (droppers.length > 0) {
    findings.push({
      category: 'dropper',
      severity: 'suspicious',
      title: `Dropper/payload delivery indicators detected`,
      description: `Patterns associated with dropper functionality (writing to temp, registry persistence) were found.`,
      evidence: droppers.map(m => `Rule: ${m.rule}`).join('\n'),
      matchedRules: droppers.map(m => m.rule),
    });
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeWithYARA(filePath: string): YARAResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      matchedRules: [],
      totalMatches: 0,
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];
  let toolUsed = 'none';

  console.log(`[JURI-X YARA] Analyzing ${fileName} (${fileStat.size} bytes)`);

  let matchedRules: YARARuleMatch[] = [];

  // Try YARA first
  if (isYARAAvailable()) {
    console.log('[JURI-X YARA] YARA is available, running scan...');
    matchedRules = runYARAScan(filePath);
    if (matchedRules.length > 0) {
      toolUsed = 'yara';
      console.log(`[JURI-X YARA] YARA scan: ${matchedRules.length} rules matched`);
    } else {
      console.log('[JURI-X YARA] YARA scan: no rules matched');
      toolUsed = 'yara';
    }
  } else {
    // Fallback: string-based scanning
    console.log('[JURI-X YARA] YARA not available, using fallback string scanner');
    matchedRules = fallbackStringScan(filePath);
    if (matchedRules.length > 0) {
      toolUsed = 'fallback_strings';
      console.log(`[JURI-X YARA] Fallback scanner: ${matchedRules.length} matches`);
    }
  }

  // Detect suspicious findings
  const suspiciousFindings = detectSuspiciousYARA(matchedRules);

  console.log(`[JURI-X YARA] Analysis complete: ${matchedRules.length} matches, ${suspiciousFindings.length} findings`);

  return {
    available: toolUsed !== 'none',
    filePath,
    matchedRules,
    totalMatches: matchedRules.length,
    suspiciousFindings,
    toolUsed,
    errors,
  };
}
