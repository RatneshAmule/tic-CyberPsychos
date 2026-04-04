/**
 * tool-pcap-analyzer.ts — TShark Integration
 *
 * Uses: tshark from Wireshark for network forensics.
 * Extracts DNS queries, HTTP requests, TCP connections, TLS SNI,
 * credentials, conversations, and protocol statistics.
 *
 * Every tshark call is wrapped in try/catch — gracefully degrades if tshark is not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { join, basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DNSQuery {
  queryName: string;
  answer: string;
  timestamp?: string;
}

export interface HTTPRequest {
  host: string;
  uri: string;
  method: string;
  userAgent: string;
  statusCode: string;
  contentType: string;
  contentLength: string;
}

export interface TCPConnection {
  sourceIP: string;
  sourcePort: number;
  destIP: string;
  destPort: number;
  flags: string;
}

export interface TLSHost {
  serverName: string;
  version: string;
  cipherSuite: string;
}

export interface CredentialEntry {
  protocol: string;
  server: string;
  user: string;
  info: string;
}

export interface ConversationEntry {
  addressA: string;
  portA: number;
  addressB: string;
  portB: number;
  packets: number;
  bytes: number;
  direction: string;  // A→B or B→A
}

export interface ProtocolStat {
  protocol: string;
  frames: number;
  bytes: number;
  percentage: string;
}

export interface PCAPSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface TSharkResult {
  available: boolean;
  totalPackets: number;
  captureDuration: string;
  dnsQueries: DNSQuery[];
  httpRequests: HTTPRequest[];
  tcpConnections: TCPConnection[];
  tlsHosts: TLSHost[];
  credentials: CredentialEntry[];
  conversations: ConversationEntry[];
  protocolStats: ProtocolStat[];
  suspiciousFindings: PCAPSuspiciousFinding[];
  topTalkers: { ip: string; packets: number; bytes: number }[];
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

function runTshark(cmd: string, longTimeout = false): string | null {
  try {
    const out = execSync(cmd, longTimeout ? LONG_EXEC_OPTIONS : EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found')) {
      console.warn('[JURI-X TShark] tshark not found. Install wireshark/tshark for PCAP analysis.');
    } else {
      console.warn(`[JURI-X TShark] Command failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

function parseTabularFields(output: string): string[][] {
  if (!output || output.trim().length === 0) return [];
  return output.split('\n')
    .map(line => line.split('\t').map(f => f.trim()))
    .filter(fields => fields.length > 0 && fields.some(f => f.length > 0));
}

function normalizeIP(ip: string): string {
  if (!ip) return '';
  const parts = ip.split(':');
  if (parts.length === 2) {
    const port = parts.pop();
    return parts.join(':');
  }
  return ip;
}

// ─── Capture Statistics ─────────────────────────────────────────────────────

function getCaptureStats(filePath: string): { totalPackets: number; duration: string } {
  const totalPackets = 0;
  let duration = '';

  // Get total packet count
  const countOutput = runTshark(`tshark -r "${filePath}" -T fields -e frame.number 2>/dev/null | wc -l`, true);
  const count = parseInt(countOutput || '0', 10);

  // Get capture duration
  const timeOutput = runTshark(
    `tshark -r "${filePath}" -T fields -e frame.time_relative 2>/dev/null | tail -1`,
    true,
  );
  const lastTime = parseFloat(timeOutput || '0');
  duration = lastTime.toFixed(2) + 's';

  return { totalPackets: count, duration };
}

// ─── DNS Analysis ───────────────────────────────────────────────────────────

function analyzeDNS(filePath: string): DNSQuery[] {
  const queries: DNSQuery[] = [];

  // DNS queries with answers
  const output = runTshark(
    `tshark -r "${filePath}" -Y "dns" -T fields -e dns.qry.name -e dns.a -e dns.qry.type -e dns.flags.response 2>/dev/null`,
    true,
  );
  if (!output) return queries;

  const seen = new Set<string>();
  for (const line of output.split('\n')) {
    const fields = line.split('\t').map(f => f.trim());
    if (fields.length < 2 || !fields[0]) continue;

    const key = fields[0];
    if (seen.has(key)) continue;
    seen.add(key);

    queries.push({
      queryName: fields[0],
      answer: fields[1] || '',
    });
  }

  return queries;
}

// ─── HTTP Analysis ──────────────────────────────────────────────────────────

function analyzeHTTP(filePath: string): HTTPRequest[] {
  const requests: HTTPRequest[] = [];

  // HTTP requests
  const reqOutput = runTshark(
    `tshark -r "${filePath}" -Y "http.request" -T fields -e http.host -e http.request.uri -e http.request.method -e http.user_agent 2>/dev/null`,
    true,
  );
  if (!reqOutput) return requests;

  const seen = new Set<string>();
  for (const line of reqOutput.split('\n')) {
    const fields = line.split('\t').map(f => f.trim());
    if (fields.length < 2 || !fields[0]) continue;

    const key = `${fields[0]}${fields[1]}`;
    if (seen.has(key)) continue;
    seen.add(key);

    requests.push({
      host: fields[0],
      uri: fields[1],
      method: fields[2] || 'GET',
      userAgent: fields[3] || '',
      statusCode: '',
      contentType: '',
      contentLength: '',
    });
  }

  // HTTP responses — match with requests by host+uri
  const respOutput = runTshark(
    `tshark -r "${filePath}" -Y "http.response" -T fields -e http.host -e http.request.uri -e http.response.code -e http.content_type -e http.content_length 2>/dev/null`,
    true,
  );
  if (respOutput) {
    for (const line of respOutput.split('\n')) {
      const fields = line.split('\t').map(f => f.trim());
      if (fields.length < 3) continue;

      const host = fields[0] || '';
      const uri = fields[1] || '';
      const statusCode = fields[2] || '';
      const contentType = fields[3] || '';
      const contentLength = fields[4] || '';

      // Find matching request
      for (const req of requests) {
        if (req.host === host && req.uri === uri && !req.statusCode) {
          req.statusCode = statusCode;
          req.contentType = contentType;
          req.contentLength = contentLength;
          break;
        }
      }
    }
  }

  return requests;
}

// ─── TCP Analysis ───────────────────────────────────────────────────────────

function analyzeTCP(filePath: string): TCPConnection[] {
  const connections: TCPConnection[] = [];

  const output = runTshark(
    `tshark -r "${filePath}" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport -e tcp.srcport -e tcp.flags 2>/dev/null`,
    true,
  );
  if (!output) return connections;

  const seen = new Set<string>();
  for (const line of output.split('\n')) {
    const fields = line.split('\t').map(f => f.trim());
    if (fields.length < 3 || !fields[0]) continue;

    const key = `${fields[0]}:${fields[1]}:${fields[2]}`;
    if (seen.has(key)) continue;
    seen.add(key);

    connections.push({
      sourceIP: fields[0],
      sourcePort: parseInt(fields[3] || '0', 10),
      destIP: fields[1],
      destPort: parseInt(fields[2] || '0', 10),
      flags: fields[4] || 'SYN',
    });
  }

  return connections;
}

// ─── TLS Analysis ───────────────────────────────────────────────────────────

function analyzeTLS(filePath: string): TLSHost[] {
  const hosts: TLSHost[] = [];

  // Extract SNI from TLS Client Hello
  const sniOutput = runTshark(
    `tshark -r "${filePath}" -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name -e tls.handshake.version -e tls.record.version 2>/dev/null`,
    true,
  );
  if (!sniOutput) return hosts;

  const seen = new Set<string>();
  for (const line of sniOutput.split('\n')) {
    const fields = line.split('\t').map(f => f.trim());
    if (fields.length < 1 || !fields[0]) continue;

    const serverName = fields[0];
    if (seen.has(serverName)) continue;
    seen.add(serverName);

    hosts.push({
      serverName,
      version: fields[1] || fields[2] || '',
      cipherSuite: '',
    });
  }

  // Extract cipher suites from TLS Server Hello
  const cipherOutput = runTshark(
    `tshark -r "${filePath}" -Y "tls.handshake.type==2" -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ciphersuite 2>/dev/null`,
    true,
  );
  if (cipherOutput) {
    const cipherMap = new Map<string, string>();
    for (const line of cipherOutput.split('\n')) {
      const fields = line.split('\t').map(f => f.trim());
      if (fields.length >= 2 && fields[0]) {
        cipherMap.set(fields[0], fields[1]);
      }
    }
    for (const host of hosts) {
      host.cipherSuite = cipherMap.get(host.serverName) || '';
    }
  }

  return hosts;
}

// ─── Credential Extraction ──────────────────────────────────────────────────

function analyzeCredentials(filePath: string): CredentialEntry[] {
  const credentials: CredentialEntry[] = [];

  // FTP
  const ftpOutput = runTshark(
    `tshark -r "${filePath}" -Y "ftp.request.command==USER || ftp.request.command==PASS" -T fields -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null`,
    true,
  );
  if (ftpOutput) {
    let currentUser = '';
    for (const line of ftpOutput.split('\n')) {
      const fields = line.split('\t').map(f => f.trim());
      if (fields.length < 4) continue;
      if (fields[2] === 'USER') currentUser = fields[3];
      if (fields[2] === 'PASS' && currentUser) {
        credentials.push({
          protocol: 'FTP',
          server: fields[1],
          user: currentUser,
          info: `Password: ${fields[3]}`,
        });
        currentUser = '';
      }
    }
  }

  // HTTP Basic Auth
  const httpAuthOutput = runTshark(
    `tshark -r "${filePath}" -Y "http.authorization" -T fields -e http.host -e http.authorization 2>/dev/null`,
    true,
  );
  if (httpAuthOutput) {
    for (const line of httpAuthOutput.split('\n')) {
      const fields = line.split('\t').map(f => f.trim());
      if (fields.length < 2 || !fields[1]) continue;

      // Try to decode Basic auth
      const authMatch = fields[1].match(/^Basic\s+(.+)/i);
      let info = fields[1].substring(0, 50);
      if (authMatch) {
        try {
          const decoded = Buffer.from(authMatch[1], 'base64').toString('utf-8');
          info = `Basic decoded: ${decoded}`;
        } catch {
          info = `Basic (encoded): ${authMatch[1].substring(0, 30)}...`;
        }
      }

      credentials.push({
        protocol: 'HTTP',
        server: fields[0],
        user: '',
        info,
      });
    }
  }

  // SMTP AUTH
  const smtpOutput = runTshark(
    `tshark -r "${filePath}" -Y "smtp.req.command==AUTH" -T fields -e ip.dst -e smtp.auth.username -e smtp.auth.password 2>/dev/null`,
    true,
  );
  if (smtpOutput) {
    for (const line of smtpOutput.split('\n')) {
      const fields = line.split('\t').map(f => f.trim());
      if (fields.length < 3) continue;
      credentials.push({
        protocol: 'SMTP',
        server: fields[0],
        user: fields[1],
        info: fields[2] ? `Password: ${fields[2]}` : '',
      });
    }
  }

  // Kerberos, NTLM, etc.
  const ntlmOutput = runTshark(
    `tshark -r "${filePath}" -Y "ntlmssp.auth.username || kerberos.CName" -T fields -e kerberos.CName -e ntlmssp.auth.username -e ntlmssp.auth.domain 2>/dev/null`,
    true,
  );
  if (ntlmOutput) {
    for (const line of ntlmOutput.split('\n')) {
      const fields = line.split('\t').map(f => f.trim());
      const user = fields[0] || fields[1] || '';
      const domain = fields[2] || '';
      if (user && !credentials.some(c => c.user === user && c.protocol === 'NTLM/Kerberos')) {
        credentials.push({
          protocol: 'NTLM/Kerberos',
          server: domain,
          user,
          info: domain ? `Domain: ${domain}` : '',
        });
      }
    }
  }

  return credentials;
}

// ─── Conversations Analysis ─────────────────────────────────────────────────

function analyzeConversations(filePath: string): ConversationEntry[] {
  const conversations: ConversationEntry[] = [];

  // TCP conversations
  const output = runTshark(
    `tshark -r "${filePath}" -q -z conv,tcp 2>/dev/null`,
    true,
  );
  if (!output) return conversations;

  const lines = output.split('\n');
  for (const line of lines) {
    if (!line.trim() || line.includes('===') || line.includes('|') || line.includes('Filter') || line.includes('TCP') || line.includes(' <-> ') === false) continue;
    if (line.includes('Address')) continue;

    // Parse: 192.168.1.1:1234 <-> 10.0.0.1:80    150    25000
    const match = line.match(/(\S+):(\d+)\s*<->\s*(\S+):(\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      conversations.push({
        addressA: match[1],
        portA: parseInt(match[2], 10),
        addressB: match[3],
        portB: parseInt(match[4], 10),
        packets: parseInt(match[5], 10),
        bytes: parseInt(match[6], 10),
        direction: `${match[1]}:${match[2]}→${match[3]}:${match[4]}`,
      });
    }
  }

  return conversations;
}

// ─── Protocol Hierarchy ─────────────────────────────────────────────────────

function analyzeProtocolHierarchy(filePath: string): ProtocolStat[] {
  const stats: ProtocolStat[] = [];

  const output = runTshark(
    `tshark -r "${filePath}" -q -z io,phs 2>/dev/null`,
    true,
  );
  if (!output) return stats;

  const lines = output.split('\n');
  for (const line of lines) {
    if (!line.trim() || line.includes('===') || line.includes('Protocol') || line.includes('Filter') || line.includes('frames')) continue;

    // Parse: eth              1500    60.0%   60.0%   90000
    const match = line.match(/^(\S+)\s+(\d+)\s+([\d.]+%)\s+([\d.]+%)\s+(\d+)/);
    if (match) {
      stats.push({
        protocol: match[1],
        frames: parseInt(match[2], 10),
        percentage: match[3],
        bytes: parseInt(match[5], 10),
      });
    }
  }

  return stats;
}

// ─── Top Talkers ────────────────────────────────────────────────────────────

function analyzeTopTalkers(filePath: string): { ip: string; packets: number; bytes: number }[] {
  const talkers: { ip: string; packets: number; bytes: number }[] = [];

  const output = runTshark(
    `tshark -r "${filePath}" -q -z io,stat,0 2>/dev/null | head -20`,
    true,
  );
  if (!output) {
    // Fallback: use conv,tcp to derive top talkers
    const convOutput = runTshark(
      `tshark -r "${filePath}" -q -z conv,ip 2>/dev/null`,
      true,
    );
    if (!convOutput) return talkers;

    const ipPackets = new Map<string, { packets: number; bytes: number }>();
    for (const line of convOutput.split('\n')) {
      const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s*<->\s*\S+\s+(\d+)\s+(\d+)/);
      if (match) {
        const ip = match[1];
        const existing = ipPackets.get(ip) || { packets: 0, bytes: 0 };
        existing.packets += parseInt(match[2], 10);
        existing.bytes += parseInt(match[3], 10);
        ipPackets.set(ip, existing);
      }
    }

    return Array.from(ipPackets.entries())
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 20);
  }

  return talkers;
}

// ─── Suspicious Findings Detection ──────────────────────────────────────────

function detectSuspiciousActivity(
  dns: DNSQuery[],
  http: HTTPRequest[],
  tcp: TCPConnection[],
  tls: TLSHost[],
  credentials: CredentialEntry[],
): PCAPSuspiciousFinding[] {
  const findings: PCAPSuspiciousFinding[] = [];

  // 1. DNS exfiltration patterns
  const longDns = dns.filter(d => d.queryName.length > 60);
  if (longDns.length > 5) {
    findings.push({
      category: 'dns_exfiltration',
      severity: 'critical',
      title: `Possible DNS exfiltration detected (${longDns.length} long queries)`,
      description: `Found ${longDns.length} DNS queries with abnormally long names (60+ characters), which may indicate DNS tunneling or data exfiltration.`,
      evidence: longDns.slice(0, 3).map(d => d.queryName).join(', '),
    });
  }

  // 2. Suspicious domains
  const suspiciousDomainPatterns = [
    /duckdns\./i, /no-ip\./i, /dyndns\./i, /freedns\./i, /zapto\./i,
    /strato\./i, /000webhost/i, /pastebin\./i, /ngrok\./i, /tor2web/i,
    /onion\./i,
  ];
  const suspiciousDomains = dns.filter(d =>
    suspiciousDomainPatterns.some(p => p.test(d.queryName)),
  );
  for (const sd of suspiciousDomains) {
    findings.push({
      category: 'suspicious_domain',
      severity: 'highly_suspicious',
      title: `Suspicious domain resolution: ${sd.queryName}`,
      description: `DNS query to a known dynamic DNS or anonymization service: ${sd.queryName}`,
      evidence: sd.queryName,
    });
  }

  // 3. HTTP to known suspicious URIs
  const suspiciousPaths = [
    /\/admin/i, /\/shell/i, /\/cmd/i, /\/exec/i, /\/upload/i,
    /\/webshell/i, /\/c99/i, /\/r57/i, /\/phpmyadmin/i,
    /\/wp-admin/i, /\/xmlrpc\.php/i, /\/.env/i, /\/\.git/i,
  ];
  for (const req of http) {
    if (suspiciousPaths.some(p => p.test(req.uri))) {
      findings.push({
        category: 'suspicious_http',
        severity: 'highly_suspicious',
        title: `Suspicious HTTP request: ${req.host}${req.uri}`,
        description: `HTTP ${req.method} to potentially sensitive path: ${req.host}${req.uri}`,
        evidence: `${req.method} ${req.host}${req.uri} UA: ${req.userAgent}`,
      });
    }
  }

  // 4. HTTP error codes suggesting scanning/exploitation
  const errorCodes = http.filter(r => r.statusCode && ['401', '403', '404', '500', '502', '503'].includes(r.statusCode));
  const errorHosts = new Map<string, number>();
  for (const e of errorCodes) {
    errorHosts.set(e.host, (errorHosts.get(e.host) || 0) + 1);
  }
  for (const [host, count] of Array.from(errorHosts.entries())) {
    if (count > 10) {
      findings.push({
        category: 'potential_scanning',
        severity: 'suspicious',
        title: `Possible web scanning: ${host} (${count} error responses)`,
        description: `${count} HTTP error responses from ${host}, which may indicate automated scanning or exploitation attempts.`,
        evidence: host,
      });
    }
  }

  // 5. Connections to common C2 ports
  const c2Ports = [4444, 5555, 6666, 6667, 1337, 31337, 1234, 8888, 9999, 4443, 8443, 8080];
  for (const conn of tcp) {
    if (c2Ports.includes(conn.destPort)) {
      findings.push({
        category: 'c2_port',
        severity: 'critical',
        title: `Connection to C2 port: ${conn.sourceIP} → ${conn.destIP}:${conn.destPort}`,
        description: `TCP SYN to commonly abused port ${conn.destPort}. This port is frequently used by backdoors and C2 frameworks.`,
        evidence: `${conn.sourceIP}:${conn.sourcePort} → ${conn.destIP}:${conn.destPort}`,
      });
    }
  }

  // 6. TLS to suspicious hosts
  const suspiciousTLS = tls.filter(t =>
    suspiciousDomainPatterns.some(p => p.test(t.serverName)),
  );
  for (const t of suspiciousTLS) {
    findings.push({
      category: 'suspicious_tls',
      severity: 'highly_suspicious',
      title: `TLS connection to suspicious host: ${t.serverName}`,
      description: `TLS handshake with known dynamic DNS or anonymization service: ${t.serverName}`,
      evidence: `${t.serverName} (${t.version})`,
    });
  }

  // 7. Credential findings
  if (credentials.length > 0) {
    for (const cred of credentials) {
      findings.push({
        category: 'credential_capture',
        severity: 'critical',
        title: `Credential captured: ${cred.protocol}`,
        description: `Captured ${cred.protocol} credentials: user=${cred.user || 'N/A'}, server=${cred.server}`,
        evidence: `${cred.protocol}: ${cred.user}@${cred.server} — ${cred.info}`,
      });
    }
  }

  // 8. High volume of DNS (possible DNS tunneling)
  if (dns.length > 0) {
    const uniqueDomains = new Set(dns.map(d => {
      const parts = d.queryName.split('.');
      return parts.slice(-2).join('.');
    }));
    if (uniqueDomains.size < 3 && dns.length > 50) {
      findings.push({
        category: 'dns_tunneling',
        severity: 'highly_suspicious',
        title: `Possible DNS tunneling: ${dns.length} queries to ${uniqueDomains.size} domains`,
        description: `High volume of DNS queries (${dns.length}) to very few unique base domains (${uniqueDomains.size}), which is a strong indicator of DNS tunneling.`,
        evidence: Array.from(uniqueDomains).join(', '),
      });
    }
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzePCAP(filePath: string): TSharkResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      totalPackets: 0,
      captureDuration: '',
      dnsQueries: [],
      httpRequests: [],
      tcpConnections: [],
      tlsHosts: [],
      credentials: [],
      conversations: [],
      protocolStats: [],
      suspiciousFindings: [],
      topTalkers: [],
      errors: [`File not found: ${filePath}`],
    };
  }

  const baseName = basename(filePath);
  const fileStat = statSync(filePath);
  console.log(`[JURI-X TShark] Starting analysis of ${baseName} (${fileStat.size} bytes)`);

  // Check if tshark is available
  const checkOutput = runTshark('tshark --version 2>&1 | head -1');
  if (checkOutput === null) {
    return {
      available: false,
      totalPackets: 0,
      captureDuration: '',
      dnsQueries: [],
      httpRequests: [],
      tcpConnections: [],
      tlsHosts: [],
      credentials: [],
      conversations: [],
      protocolStats: [],
      suspiciousFindings: [],
      topTalkers: [],
      errors: ['tshark is not installed. Install wireshark package.'],
    };
  }

  const errors: string[] = [];

  // Get capture stats
  const stats = getCaptureStats(filePath);
  console.log(`[JURI-X TShark] Capture: ${stats.totalPackets} packets, ${stats.duration}`);

  // Run all analyses
  console.log('[JURI-X TShark] Extracting DNS queries...');
  const dnsQueries = analyzeDNS(filePath);

  console.log('[JURI-X TShark] Extracting HTTP requests...');
  const httpRequests = analyzeHTTP(filePath);

  console.log('[JURI-X TShark] Extracting TCP connections...');
  const tcpConnections = analyzeTCP(filePath);

  console.log('[JURI-X TShark] Extracting TLS hosts...');
  const tlsHosts = analyzeTLS(filePath);

  console.log('[JURI-X TShark] Extracting credentials...');
  const credentials = analyzeCredentials(filePath);

  console.log('[JURI-X TShark] Analyzing conversations...');
  const conversations = analyzeConversations(filePath);

  console.log('[JURI-X TShark] Analyzing protocol hierarchy...');
  const protocolStats = analyzeProtocolHierarchy(filePath);

  console.log('[JURI-X TShark] Finding top talkers...');
  const topTalkers = analyzeTopTalkers(filePath);

  // Detect suspicious activity
  console.log('[JURI-X TShark] Detecting suspicious activity...');
  const suspiciousFindings = detectSuspiciousActivity(dnsQueries, httpRequests, tcpConnections, tlsHosts, credentials);

  console.log(`[JURI-X TShark] Analysis complete: ${dnsQueries.length} DNS, ${httpRequests.length} HTTP, ${tcpConnections.length} TCP, ${tlsHosts.length} TLS, ${credentials.length} creds, ${suspiciousFindings.length} findings`);

  return {
    available: true,
    totalPackets: stats.totalPackets,
    captureDuration: stats.duration,
    dnsQueries,
    httpRequests,
    tcpConnections,
    tlsHosts,
    credentials,
    conversations,
    protocolStats,
    suspiciousFindings,
    topTalkers,
    errors,
  };
}
