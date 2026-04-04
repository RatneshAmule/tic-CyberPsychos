/**
 * tool-tshark.ts — Deep PCAP Network Analysis
 *
 * Uses: tshark (Wireshark CLI) for comprehensive network capture analysis.
 * Extracts DNS queries, HTTP requests, TLS SNI, TCP streams, credentials,
 * and conversation summaries from PCAP files.
 *
 * Detects: DNS tunneling, suspicious user agents, cleartext credentials,
 * communication with known malicious ports, and anomalous traffic patterns.
 *
 * Falls back gracefully if tshark is not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DNSQuery {
  domain: string;
  address: string;
  type: string;
}

export interface HTTPRequest {
  host: string;
  uri: string;
  method: string;
  srcIP: string;
  dstIP: string;
}

export interface TLSSNI {
  serverName: string;
}

export interface TCPStream {
  srcIP: string;
  srcPort: number;
  dstIP: string;
  dstPort: number;
}

export interface CredentialEntry {
  frameNumber: number;
  srcIP: string;
  dstIP: string;
  protocol: string;
  command: string;
  argument: string;
}

export interface TopTalker {
  address: string;
  packets: number;
  bytes: number;
}

export interface TSharkSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface TSharkResult {
  available: boolean;
  filePath: string;
  totalPackets: number;
  captureDuration: number;
  dnsQueries: DNSQuery[];
  httpRequests: HTTPRequest[];
  tlsSni: TLSSNI[];
  tcpStreams: TCPStream[];
  credentials: CredentialEntry[];
  topTalkers: TopTalker[];
  suspiciousFindings: TSharkSuspiciousFinding[];
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
      console.warn(`[JURI-X TShark] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X TShark] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

/** Check if tshark is installed. */
function isTSharkAvailable(): boolean {
  const output = runTool('tshark --version 2>/dev/null | head -1');
  return output !== null;
}

// ─── tshark Extraction Functions ────────────────────────────────────────────

/** Get total packet count from PCAP. */
function getTotalPackets(filePath: string): number {
  const output = runTool(`tshark -r "${filePath}" -T fields -e frame.number 2>/dev/null | wc -l`);
  if (!output) return 0;
  const count = parseInt(output.trim(), 10);
  return isNaN(count) ? 0 : count;
}

/** Get capture duration in seconds. */
function getCaptureDuration(filePath: string): number {
  const firstFrame = runTool(`tshark -r "${filePath}" -T fields -e frame.time_epoch -c 1 2>/dev/null`);
  const lastFrame = runTool(`tshark -r "${filePath}" -T fields -e frame.time_epoch 2>/dev/null | tail -1`);

  if (!firstFrame || !lastFrame) return 0;

  const first = parseFloat(firstFrame.trim());
  const last = parseFloat(lastFrame.trim());

  if (isNaN(first) || isNaN(last)) return 0;
  return Math.round(last - first);
}

/** Extract DNS queries from PCAP. */
function extractDNSQueries(filePath: string): DNSQuery[] {
  const queries: DNSQuery[] = [];

  const output = runTool(
    `tshark -r "${filePath}" -Y "dns" -T fields -e dns.qry.name -e dns.a -E header=n -E separator="\\t" 2>/dev/null`
  );
  if (!output) return queries;

  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    if (parts.length < 1 || !parts[0].trim()) continue;

    queries.push({
      domain: parts[0].trim(),
      address: (parts[1] || '').trim(),
      type: 'A',
    });
  }

  return queries;
}

/** Extract HTTP requests from PCAP. */
function extractHTTPRequests(filePath: string): HTTPRequest[] {
  const requests: HTTPRequest[] = [];

  const output = runTool(
    `tshark -r "${filePath}" -Y "http.request" -T fields -e http.host -e http.request.uri -e http.request.method -e ip.src -e ip.dst -E header=n -E separator="\\t" 2>/dev/null`
  );
  if (!output) return requests;

  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    if (parts.length < 2) continue;

    requests.push({
      host: (parts[0] || '').trim(),
      uri: (parts[1] || '').trim(),
      method: (parts[2] || '').trim(),
      srcIP: (parts[3] || '').trim(),
      dstIP: (parts[4] || '').trim(),
    });
  }

  return requests;
}

/** Extract TLS SNI (Server Name Indication) from PCAP. */
function extractTLSSNI(filePath: string): TLSSNI[] {
  const sniList: TLSSNI[] = [];
  const seen = new Set<string>();

  const output = runTool(
    `tshark -r "${filePath}" -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name -E header=n 2>/dev/null`
  );
  if (!output) return sniList;

  for (const line of output.split('\n')) {
    const serverName = line.trim();
    if (!serverName) continue;
    if (seen.has(serverName)) continue;
    seen.add(serverName);

    sniList.push({ serverName });
  }

  return sniList;
}

/** Extract TCP connection streams (SYN packets) from PCAP. */
function extractTCPStreams(filePath: string): TCPStream[] {
  const streams: TCPStream[] = [];

  const output = runTool(
    `tshark -r "${filePath}" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.srcport -e ip.dst -e ip.dstport -E header=n -E separator="\\t" 2>/dev/null`
  );
  if (!output) return streams;

  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    if (parts.length < 4) continue;

    streams.push({
      srcIP: (parts[0] || '').trim(),
      srcPort: parseInt(parts[1], 10) || 0,
      dstIP: (parts[2] || '').trim(),
      dstPort: parseInt(parts[3], 10) || 0,
    });
  }

  return streams;
}

/** Extract cleartext credentials from PCAP (FTP, HTTP auth, POP, IMAP, Telnet). */
function extractCredentials(filePath: string): CredentialEntry[] {
  const credentials: CredentialEntry[] = [];

  const output = runTool(
    `tshark -r "${filePath}" -Y "ftp || http.authorization || pop || imap || telnet" -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg -E header=n -E separator="\\t" 2>/dev/null`
  );
  if (!output) return credentials;

  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    if (parts.length < 3) continue;

    credentials.push({
      frameNumber: parseInt(parts[0], 10) || 0,
      srcIP: (parts[1] || '').trim(),
      dstIP: (parts[2] || '').trim(),
      protocol: 'unknown',
      command: (parts[3] || '').trim(),
      argument: (parts[4] || '').trim(),
    });
  }

  // Also try to detect FTP USER/PASS commands specifically
  const ftpUserOutput = runTool(
    `tshark -r "${filePath}" -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg -E header=n -E separator="\\t" 2>/dev/null`
  );
  if (ftpUserOutput) {
    for (const line of ftpUserOutput.split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split('\t');
      if (parts.length < 5) continue;
      const cmd = parts[3].trim().toUpperCase();
      if (cmd === 'USER' || cmd === 'PASS') {
        // Avoid duplicates
        const frameNum = parseInt(parts[0], 10);
        if (!credentials.some(c => c.frameNumber === frameNum)) {
          credentials.push({
            frameNumber: frameNum || 0,
            srcIP: (parts[1] || '').trim(),
            dstIP: (parts[2] || '').trim(),
            protocol: 'FTP',
            command: cmd,
            argument: (parts[4] || '').trim(),
          });
        }
      }
    }
  }

  return credentials;
}

/** Extract conversation summary / top talkers from PCAP. */
function extractTopTalkers(filePath: string): TopTalker[] {
  const talkers: TopTalker[] = [];

  const output = runTool(
    `tshark -r "${filePath}" -q -z conv,ip 2>/dev/null | head -60`
  );
  if (!output) return talkers;

  // Parse tshark conv,ip output:
  // Format varies but typically:
  // |           |               |     Packets     |     Bytes      |
  // |  <Address>  |   <->   |  <Address>  |  <packets>  |  <bytes>  | ...
  // Filter out separator lines and header
  const lines = output.split('\n');
  for (const line of lines) {
    if (!line.trim() || line.includes('---') || line.includes('Address') || line.includes('Packets') || line.includes('Filter:')) {
      continue;
    }

    // Parse lines like: "192.168.1.1    <->    10.0.0.1     42    12345"
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;

    // Extract numeric fields from the end (packets, bytes)
    const numbers: number[] = [];
    for (let i = parts.length - 1; i >= 0; i--) {
      const num = parseInt(parts[i].replace(/,/g, ''), 10);
      if (!isNaN(num)) {
        numbers.unshift(num);
      } else {
        break;
      }
      if (numbers.length >= 2) break;
    }

    if (numbers.length >= 2) {
      // Try to extract the first IP address
      let address = '';
      for (const part of parts) {
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(part)) {
          address = part;
          break;
        }
      }

      if (address) {
        talkers.push({
          address,
          packets: numbers[0],
          bytes: numbers[1],
        });
      }
    }
  }

  // Sort by bytes descending, take top 20
  talkers.sort((a, b) => b.bytes - a.bytes);
  return talkers.slice(0, 20);
}

// ─── Suspicious Finding Detection ───────────────────────────────────────────

function detectSuspiciousNetwork(
  dnsQueries: DNSQuery[],
  httpRequests: HTTPRequest[],
  tlsSni: TLSSNI[],
  tcpStreams: TCPStream[],
  credentials: CredentialEntry[],
  topTalkers: TopTalker[],
  totalPackets: number,
): TSharkSuspiciousFinding[] {
  const findings: TSharkSuspiciousFinding[] = [];

  // 1. DNS tunneling detection (high volume to unusual domains)
  const dnsDomainCounts = new Map<string, number>();
  for (const q of dnsQueries) {
    if (!q.domain) continue;
    // Get the TLD+1 (second-level domain)
    const parts = q.domain.split('.');
    if (parts.length >= 2) {
      const sld = parts.slice(-2).join('.');
      dnsDomainCounts.set(sld, (dnsDomainCounts.get(sld) || 0) + 1);
    }
  }

  const highVolumeDomains = Array.from(dnsDomainCounts.entries())
    .filter(([, count]) => count > 50)
    .sort((a, b) => b[1] - a[1]);

  if (highVolumeDomains.length > 0) {
    // Check for DNS tunneling indicators: very long subdomains, high volume
    let tunnelingIndicators = 0;
    for (const q of dnsQueries) {
      // DNS tunneling often uses very long subdomain labels
      const labels = q.domain.split('.');
      const longLabel = labels.some(l => l.length > 30);
      if (longLabel) tunnelingIndicators++;
    }

    if (tunnelingIndicators > 10 || (highVolumeDomains.length > 0 && highVolumeDomains[0][1] > 100)) {
      findings.push({
        category: 'dns_tunneling',
        severity: 'highly_suspicious',
        title: `Possible DNS tunneling detected (${highVolumeDomains[0][1]} queries to ${highVolumeDomains[0][0]})`,
        description: `An unusually high volume of DNS queries to a single domain was detected, which may indicate DNS tunneling for data exfiltration or C2 communication.`,
        evidence: `Top queried domains: ${highVolumeDomains.slice(0, 5).map(([d, c]) => `${d} (${c} queries)`).join(', ')}`,
      });
    } else if (highVolumeDomains.length > 0) {
      findings.push({
        category: 'dns_anomaly',
        severity: 'suspicious',
        title: `High DNS query volume detected`,
        description: `Higher than expected DNS query volume to specific domains. May indicate data exfiltration or C2 communication via DNS.`,
        evidence: `Top queried domains: ${highVolumeDomains.slice(0, 5).map(([d, c]) => `${d} (${c} queries)`).join(', ')}`,
      });
    }
  }

  // 2. Suspicious HTTP user agents and suspicious URIs
  const suspiciousUserAgents = httpRequests.filter(r =>
    /curl|wget|python|powershell|nikto|nmap|sqlmap|dirbuster|gobuster|metasploit/i.test(r.host) ||
    /\.php\?.*=/i.test(r.uri) ||
    /\/admin|\/shell|\/cmd|\/exec|\/upload|\/eval/i.test(r.uri) ||
    /union.*select|exec\(|system\(|passthru|base64_decode/i.test(r.uri)
  );

  if (suspiciousUserAgents.length > 0) {
    findings.push({
      category: 'suspicious_http',
      severity: 'highly_suspicious',
      title: `Suspicious HTTP activity detected (${suspiciousUserAgents.length} requests)`,
      description: `HTTP requests with potentially malicious patterns were found, including known exploit tool signatures, suspicious URIs, or injection attempts.`,
      evidence: suspiciousUserAgents.slice(0, 10).map(r => `${r.method} ${r.host}${r.uri} (${r.srcIP} -> ${r.dstIP})`).join('\n'),
    });
  }

  // 3. Cleartext credentials
  const ftpCredentials = credentials.filter(c =>
    c.protocol === 'FTP' && (c.command === 'USER' || c.command === 'PASS')
  );

  if (ftpCredentials.length > 0) {
    findings.push({
      category: 'cleartext_credentials',
      severity: 'critical',
      title: `Cleartext credentials detected (${ftpCredentials.length} entries)`,
      description: `FTP or other protocol credentials transmitted in cleartext were captured. These credentials could be used for lateral movement.`,
      evidence: ftpCredentials.slice(0, 10).map(c => `Frame ${c.frameNumber}: ${c.command} ${c.argument} (${c.srcIP} -> ${c.dstIP})`).join('\n'),
    });
  } else if (credentials.length > 0) {
    findings.push({
      category: 'cleartext_credentials',
      severity: 'suspicious',
      title: `Potential cleartext credentials detected`,
      description: `Protocol activity that may contain cleartext credentials was observed.`,
      evidence: credentials.slice(0, 5).map(c => `Frame ${c.frameNumber}: ${c.command} (${c.srcIP} -> ${c.dstIP})`).join('\n'),
    });
  }

  // 4. Communication with known malicious ports
  const suspiciousPorts = [4444, 5555, 6666, 6667, 8888, 31337, 12345, 4443, 5554, 3389];
  const maliciousPortConnections = tcpStreams.filter(s =>
    suspiciousPorts.includes(s.dstPort) || suspiciousPorts.includes(s.srcPort)
  );

  if (maliciousPortConnections.length > 0) {
    findings.push({
      category: 'malicious_ports',
      severity: 'highly_suspicious',
      title: `Connections to suspicious ports detected (${maliciousPortConnections.length} connections)`,
      description: `TCP connections to ports commonly associated with malware, backdoors, or remote administration tools were found.`,
      evidence: maliciousPortConnections.slice(0, 10).map(s =>
        `${s.srcIP}:${s.srcPort} -> ${s.dstIP}:${s.dstPort}`
      ).join('\n'),
    });
  }

  // 5. Known suspicious TLS SNI domains
  const suspiciousSniPatterns = [
    /update|download|cdn/i,
    /\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/i,
    /tor|onion|proxy|vpn/i,
    /malware|exploit|c2|beacon/i,
  ];

  const suspiciousTLSHosts = tlsSni.filter(s => {
    return suspiciousSniPatterns.some(p => p.test(s.serverName));
  });

  if (suspiciousTLSHosts.length > 0) {
    findings.push({
      category: 'suspicious_tls',
      severity: 'suspicious',
      title: `Connections to suspicious TLS hosts (${suspiciousTLSHosts.length} domains)`,
      description: `TLS connections to domains matching suspicious patterns (free TLDs, proxy/VPN services, known malicious keywords) were detected.`,
      evidence: suspiciousTLSHosts.map(s => s.serverName).join(', '),
    });
  }

  // 6. Data exfiltration indicators (large uploads)
  const largeUploadStreams = tcpStreams.filter(s =>
    (s.dstPort === 80 || s.dstPort === 443) && topTalkers.some(t => t.address === s.dstIP && t.bytes > 10_000_000)
  );

  if (largeUploadStreams.length > 0) {
    findings.push({
      category: 'data_exfiltration',
      severity: 'highly_suspicious',
      title: `Potential data exfiltration detected`,
      description: `Large volume of data sent to external IP addresses, which may indicate data exfiltration.`,
      evidence: largeUploadStreams.slice(0, 5).map(s =>
        `${s.srcIP} -> ${s.dstIP} (port ${s.dstPort})`
      ).join('\n'),
    });
  }

  // 7. RDP/SSH brute force indicators (many connections to port 22, 3389)
  const sshConnections = tcpStreams.filter(s => s.dstPort === 22);
  const rdpConnections = tcpStreams.filter(s => s.dstPort === 3389);

  if (sshConnections.length > 100) {
    findings.push({
      category: 'brute_force',
      severity: 'highly_suspicious',
      title: `Possible SSH brute force attack (${sshConnections.length} connections)`,
      description: `An unusually high number of SSH connections suggests a brute force attack against SSH services.`,
      evidence: `Unique source IPs: ${new Set(sshConnections.map(s => s.srcIP)).size}, Total connections: ${sshConnections.length}`,
    });
  }

  if (rdpConnections.length > 50) {
    findings.push({
      category: 'brute_force',
      severity: 'highly_suspicious',
      title: `Possible RDP brute force attack (${rdpConnections.length} connections)`,
      description: `An unusually high number of RDP connections suggests a brute force attack against remote desktop services.`,
      evidence: `Unique source IPs: ${new Set(rdpConnections.map(s => s.srcIP)).size}, Total connections: ${rdpConnections.length}`,
    });
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeWithTShark(filePath: string): TSharkResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      totalPackets: 0,
      captureDuration: 0,
      dnsQueries: [],
      httpRequests: [],
      tlsSni: [],
      tcpStreams: [],
      credentials: [],
      topTalkers: [],
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];
  let toolUsed = 'none';

  console.log(`[JURI-X TShark] Analyzing ${fileName} (${fileStat.size} bytes)`);

  if (!isTSharkAvailable()) {
    console.log('[JURI-X TShark] tshark not available, returning unavailable result');
    return {
      available: false,
      filePath,
      totalPackets: 0,
      captureDuration: 0,
      dnsQueries: [],
      httpRequests: [],
      tlsSni: [],
      tcpStreams: [],
      credentials: [],
      topTalkers: [],
      suspiciousFindings: [],
      toolUsed: 'none',
      errors: ['tshark is not installed'],
    };
  }

  toolUsed = 'tshark';

  // Get packet count and duration
  const totalPackets = getTotalPackets(filePath);
  const captureDuration = getCaptureDuration(filePath);
  console.log(`[JURI-X TShark] PCAP info: ${totalPackets} packets, ${captureDuration}s duration`);

  // Extract DNS queries
  const dnsQueries = extractDNSQueries(filePath);
  console.log(`[JURI-X TShark] DNS queries: ${dnsQueries.length}`);

  // Extract HTTP requests
  const httpRequests = extractHTTPRequests(filePath);
  console.log(`[JURI-X TShark] HTTP requests: ${httpRequests.length}`);

  // Extract TLS SNI
  const tlsSni = extractTLSSNI(filePath);
  console.log(`[JURI-X TShark] TLS SNI hosts: ${tlsSni.length}`);

  // Extract TCP streams
  const tcpStreams = extractTCPStreams(filePath);
  console.log(`[JURI-X TShark] TCP connections: ${tcpStreams.length}`);

  // Extract credentials
  const credentials = extractCredentials(filePath);
  console.log(`[JURI-X TShark] Credentials found: ${credentials.length}`);

  // Extract top talkers
  const topTalkers = extractTopTalkers(filePath);
  console.log(`[JURI-X TShark] Top talkers: ${topTalkers.length}`);

  // Detect suspicious findings
  const suspiciousFindings = detectSuspiciousNetwork(
    dnsQueries, httpRequests, tlsSni, tcpStreams, credentials, topTalkers, totalPackets
  );

  console.log(`[JURI-X TShark] Analysis complete: ${suspiciousFindings.length} suspicious findings`);

  return {
    available: true,
    filePath,
    totalPackets,
    captureDuration,
    dnsQueries,
    httpRequests,
    tlsSni,
    tcpStreams,
    credentials,
    topTalkers,
    suspiciousFindings,
    toolUsed,
    errors,
  };
}
