'use client';

import { useState, useMemo, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Fingerprint,
  Search,
  Shield,
  AlertTriangle,
  ExternalLink,
  Loader2,
  CheckCircle,
  XCircle,
  Globe,
  Skull,
  Copy,
  Check,
  Bug,
  Clock,
  FileText,
} from 'lucide-react';

interface HashLookupResult {
  hash: string;
  results: {
    virustotal: any;
    malwarebazaar: any;
    urlhaus?: any;
  };
  checkedAt: string;
}

interface HashLookupProps {
  data?: any; // AnalysisResult - to auto-populate hashes from evidence
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function formatDate(timestamp: number | string | null | undefined): string {
  if (!timestamp) return 'N/A';
  const d = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp);
  if (isNaN(d.getTime())) return 'N/A';
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
    + ' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

function detectHashType(hash: string): string {
  const h = hash.trim();
  if (/^[a-fA-F0-9]{64}$/.test(h)) return 'SHA-256';
  if (/^[a-fA-F0-9]{40}$/.test(h)) return 'SHA-1';
  if (/^[a-fA-F0-9]{32}$/.test(h)) return 'MD5';
  return 'Unknown';
}

function truncateHash(hash: string, chars = 12): string {
  if (hash.length <= chars * 2 + 3) return hash;
  return `${hash.slice(0, chars)}...${hash.slice(-chars)}`;
}

function formatFileSize(bytes: number): string {
  if (!bytes || bytes === 0) return 'N/A';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let size = bytes;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return `${size.toFixed(1)} ${units[i]}`;
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                    */
/* ------------------------------------------------------------------ */

function StatBar({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-muted-foreground w-24 shrink-0">{label}</span>
      <div className="flex-1 h-2 rounded-full bg-muted/60 overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="font-mono text-foreground w-16 text-right">{value} <span className="text-muted-foreground">({pct}%)</span></span>
    </div>
  );
}

function SectionHeader({ icon: Icon, title, status, href }: { icon: React.ElementType; title: string; status: 'success' | 'error' | 'loading'; href?: string }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <div className="p-1.5 rounded-md bg-cyan/10">
        <Icon className="h-4 w-4 text-cyan" />
      </div>
      <h4 className="text-sm font-semibold text-foreground flex-1">{title}</h4>
      {status === 'success' && <CheckCircle className="h-4 w-4 text-emerald-400" />}
      {status === 'error' && <XCircle className="h-4 w-4 text-red-400" />}
      {status === 'loading' && <Loader2 className="h-4 w-4 text-cyan animate-spin" />}
      {href && status === 'success' && (
        <a href={href} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-cyan transition-colors">
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main component                                                    */
/* ------------------------------------------------------------------ */

export default function HashLookup({ data }: HashLookupProps) {
  const [hashInput, setHashInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<HashLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  /* Extract hashes from evidence in the analysis data */
  const evidenceHashes = useMemo(() => {
    if (!data?.evidence || !Array.isArray(data.evidence)) return [];
    const hashes: { hash: string; name: string }[] = [];
    for (const ev of data.evidence) {
      if (ev.hash && /^[a-fA-F0-9]{32,64}$/.test(ev.hash)) {
        if (!hashes.some((h) => h.hash === ev.hash)) {
          hashes.push({ hash: ev.hash, name: ev.name || 'Unknown' });
        }
      }
    }
    return hashes;
  }, [data]);

  /* Copy to clipboard */
  const copyHash = useCallback(async (hash: string) => {
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* noop */ }
  }, []);

  /* Perform lookup */
  const performLookup = useCallback(async (hash: string) => {
    const clean = hash.trim().replace(/^(sha256|sha1|md5|sha512):/i, '').trim();
    if (!/^[a-fA-F0-9]{32,64}$/.test(clean)) {
      setError('Invalid hash format. Provide an MD5 (32), SHA-1 (40), or SHA-256 (64) hex string.');
      return;
    }

    setHashInput(clean);
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/api/forensic/hash-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: clean }),
      });

      const json = await res.json();
      if (!res.ok) {
        setError(json.error || `Lookup failed (${res.status})`);
        return;
      }

      setResult(json);
    } catch (err: any) {
      setError(err.message || 'Network error while contacting lookup services.');
    } finally {
      setLoading(false);
    }
  }, []);

  /* Determine overall threat verdict from VT stats */
  const verdict = useMemo(() => {
    const vtData = result?.results?.virustotal?.data;
    if (!vtData?.last_analysis_stats) return null;
    const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0 } = vtData.last_analysis_stats;
    if (malicious > 0) return { level: 'malicious' as const, color: '#ef4444', label: 'Malicious', icon: Skull, count: malicious };
    if (suspicious > 0) return { level: 'suspicious' as const, color: '#f59e0b', label: 'Suspicious', icon: AlertTriangle, count: suspicious };
    if (harmless > undetected) return { level: 'clean' as const, color: '#22c55e', label: 'Likely Clean', icon: CheckCircle, count: harmless };
    return { level: 'unknown' as const, color: '#64748b', label: 'No Detections', icon: Shield, count: 0 };
  }, [result]);

  const hashType = hashInput ? detectHashType(hashInput) : '';

  return (
    <div className="space-y-4">
      {/* ──── Hash Input Card ──── */}
      <Card className="forensic-card">
        <CardHeader className="pb-3 pt-4 px-4">
          <div className="flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-cyan" />
            <CardTitle className="text-sm font-semibold text-foreground">Hash Reputation Lookup</CardTitle>
            <Badge variant="secondary" className="font-mono text-[10px] ml-auto">
              <Globe className="h-3 w-3 mr-1" />
              3 Sources
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          {/* Input row */}
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Fingerprint className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="SHA-256, SHA-1, or MD5 hash…"
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !loading && performLookup(hashInput)}
                className="pl-9 pr-20 bg-muted/50 border-border/50 font-mono text-sm"
                spellCheck={false}
                autoComplete="off"
              />
              {/* Hash type badge */}
              {hashType && (
                <span className="absolute right-12 top-1/2 -translate-y-1/2 text-[10px] font-mono text-muted-foreground pointer-events-none">
                  {hashType}
                </span>
              )}
            </div>

            {/* Copy button */}
            {hashInput && (
              <Button
                variant="ghost"
                size="icon"
                className="shrink-0 h-9 w-9"
                onClick={() => copyHash(hashInput)}
                title="Copy hash"
              >
                {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4 text-muted-foreground" />}
              </Button>
            )}

            {/* Lookup button */}
            <Button
              variant="default"
              size="sm"
              disabled={loading || !hashInput.trim()}
              onClick={() => performLookup(hashInput)}
              className="bg-cyan hover:bg-cyan/80 text-background shrink-0 px-4"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Search className="h-4 w-4 mr-1.5" />
              )}
              {loading ? 'Looking up…' : 'Lookup'}
            </Button>
          </div>

          {/* Auto-detected hashes from evidence */}
          {evidenceHashes.length > 0 && (
            <div className="mt-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
                Evidence Hashes
              </p>
              <div className="flex flex-wrap gap-1.5">
                {evidenceHashes.map(({ hash, name }) => (
                  <Button
                    key={hash}
                    variant="secondary"
                    size="sm"
                    className={`h-6 text-xs font-mono gap-1 ${hashInput === hash ? 'bg-cyan text-background' : ''}`}
                    onClick={() => performLookup(hash)}
                    disabled={loading}
                  >
                    <Fingerprint className="h-3 w-3" />
                    <span className="truncate max-w-[100px]">{name}</span>
                    <span className="text-muted-foreground opacity-60">{truncateHash(hash, 6)}</span>
                  </Button>
                ))}
              </div>
            </div>
          )}

          {/* Error message */}
          {error && (
            <div className="mt-3 flex items-center gap-2 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30">
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              <p className="text-xs text-red-300">{error}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ──── Results ──── */}
      {result && (
        <ScrollArea className="h-[calc(100vh-340px)] scrollbar-forensic">
          <div className="space-y-4 pr-4">
            {/* Verdict Banner */}
            {verdict && (
              <Card
                className="forensic-card overflow-hidden"
                style={{ borderColor: `${verdict.color}40` }}
              >
                <CardContent className="p-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl" style={{ backgroundColor: `${verdict.color}15` }}>
                      <verdict.icon className="h-5 w-5" style={{ color: verdict.color }} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-base font-bold" style={{ color: verdict.color }}>
                          {verdict.label}
                        </span>
                        {verdict.count > 0 && (
                          <Badge
                            className="text-[10px] px-1.5 py-0"
                            style={{
                              backgroundColor: `${verdict.color}20`,
                              color: verdict.color,
                              borderColor: `${verdict.color}40`,
                            }}
                            variant="outline"
                          >
                            {verdict.count} detection{verdict.count !== 1 ? 's' : ''}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground font-mono">
                        {result.hash}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* ──── VirusTotal ──── */}
            <Card className="forensic-card">
              <CardContent className="p-4">
                <SectionHeader
                  icon={Shield}
                  title="VirusTotal"
                  status={result.results.virustotal?.status || 'error'}
                  href={result.results.virustotal?.data?.sha256
                    ? `https://www.virustotal.com/gui/file/${result.results.virustotal.data.sha256}`
                    : undefined}
                />

                {result.results.virustotal?.status === 'error' && (
                  <div className="flex items-center gap-2 text-xs text-red-400 p-2 rounded-md bg-red-500/10">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    {result.results.virustotal.error}
                  </div>
                )}

                {result.results.virustotal?.data && (() => {
                  const vt = result.results.virustotal.data;
                  const stats = vt.last_analysis_stats || {};
                  const total = Object.values(stats).reduce((a: number, b: any) => a + (b || 0), 0);

                  return (
                    <div className="space-y-3">
                      {/* File info */}
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">Type</span>
                          <p className="text-foreground font-mono mt-0.5 truncate">{vt.type_description}</p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">Analyzed</span>
                          <p className="text-foreground font-mono mt-0.5">{formatDate(vt.last_analysis_date)}</p>
                        </div>
                      </div>

                      {/* File names */}
                      {vt.names && vt.names.length > 0 && (
                        <div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">File Names</p>
                          <div className="flex flex-wrap gap-1">
                            {vt.names.slice(0, 8).map((name: string, i: number) => (
                              <Badge key={i} variant="secondary" className="text-[10px] font-mono max-w-[200px] truncate">
                                <FileText className="h-3 w-3 mr-1 shrink-0" />
                                {name}
                              </Badge>
                            ))}
                            {vt.names.length > 8 && (
                              <Badge variant="outline" className="text-[10px]">+{vt.names.length - 8} more</Badge>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Detection stats */}
                      <div>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">
                          Detection Stats <span className="text-foreground">({total} engines)</span>
                        </p>
                        <div className="space-y-1.5 p-2.5 rounded-lg bg-muted/20 border border-border/20">
                          <StatBar label="Harmless" value={stats.harmless || 0} total={total} color="#22c55e" />
                          <StatBar label="Undetected" value={stats.undetected || 0} total={total} color="#64748b" />
                          <StatBar label="Suspicious" value={stats.suspicious || 0} total={total} color="#f59e0b" />
                          <StatBar label="Malicious" value={stats.malicious || 0} total={total} color="#ef4444" />
                          <StatBar label="Timeout" value={stats.timeout || 0} total={total} color="#8b5cf6" />
                        </div>
                      </div>

                      {/* Community votes */}
                      {(vt.total_votes?.harmful || vt.total_votes?.harmless) && (
                        <div className="flex items-center gap-3 text-xs">
                          <span className="text-muted-foreground">Community:</span>
                          {vt.total_votes.harmless > 0 && (
                            <Badge variant="secondary" className="text-[10px] gap-1" style={{ backgroundColor: '#22c55e20', color: '#22c55e', borderColor: '#22c55e40' }}>
                              <CheckCircle className="h-3 w-3" /> {vt.total_votes.harmless} harmless
                            </Badge>
                          )}
                          {vt.total_votes.harmful > 0 && (
                            <Badge variant="secondary" className="text-[10px] gap-1" style={{ backgroundColor: '#ef444420', color: '#ef4444', borderColor: '#ef444440' }}>
                              <XCircle className="h-3 w-3" /> {vt.total_votes.harmful} harmful
                            </Badge>
                          )}
                        </div>
                      )}

                      {/* Signatures */}
                      {vt.signatures && vt.signatures.length > 0 && (
                        <div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">
                            Signatures <Badge variant="destructive" className="text-[9px] px-1 py-0 ml-1">{vt.signatures.length}</Badge>
                          </p>
                          <div className="space-y-1">
                            {vt.signatures.slice(0, 10).map((sig: any, i: number) => (
                              <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-red-500/5 border border-red-500/10">
                                <Bug className="h-3 w-3 text-red-400 shrink-0" />
                                <span className="font-mono text-red-300 truncate flex-1">{sig.result}</span>
                                <span className="text-muted-foreground font-mono shrink-0">{sig.engine}</span>
                              </div>
                            ))}
                            {vt.signatures.length > 10 && (
                              <p className="text-[10px] text-muted-foreground text-center">
                                +{vt.signatures.length - 10} more signatures
                              </p>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Tags */}
                      {vt.tags && vt.tags.length > 0 && (
                        <div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Tags</p>
                          <div className="flex flex-wrap gap-1">
                            {vt.tags.map((tag: string, i: number) => (
                              <Badge key={i} variant="outline" className="text-[10px] font-mono">{tag}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* No data found */}
                      {vt.names.length === 0 && !vt.last_analysis_date && (
                        <div className="text-center py-4 text-muted-foreground">
                          <Shield className="h-6 w-6 mx-auto mb-1.5 opacity-40" />
                          <p className="text-xs">Hash not found in VirusTotal database</p>
                        </div>
                      )}
                    </div>
                  );
                })()}
              </CardContent>
            </Card>

            {/* ──── MalwareBazaar ──── */}
            <Card className="forensic-card">
              <CardContent className="p-4">
                <SectionHeader
                  icon={Skull}
                  title="MalwareBazaar"
                  status={result.results.malwarebazaar?.status || 'error'}
                  href={result.results.malwarebazaar?.data?.sha256
                    ? `https://bazaar.abuse.ch/browse.php?search=${result.results.malwarebazaar.data.sha256}`
                    : undefined}
                />

                {result.results.malwarebazaar?.status === 'error' && (
                  <div className="flex items-center gap-2 text-xs text-red-400 p-2 rounded-md bg-red-500/10">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                    {result.results.malwarebazaar.error}
                  </div>
                )}

                {result.results.malwarebazaar?.data && (() => {
                  const mb = result.results.malwarebazaar.data;
                  const isMalware = mb.malware_family !== 'Unknown' || mb.signature !== 'Unknown';

                  return (
                    <div className="space-y-3">
                      {/* Verdict */}
                      <div className={`flex items-center gap-2 p-2.5 rounded-lg border ${isMalware ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
                        {isMalware ? (
                          <>
                            <Skull className="h-4 w-4 text-red-400" />
                            <span className="text-xs font-semibold text-red-300">Malware Detected</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle className="h-4 w-4 text-emerald-400" />
                            <span className="text-xs font-semibold text-emerald-300">No Known Malware</span>
                          </>
                        )}
                      </div>

                      {/* Details grid */}
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">Family</span>
                          <p className={`font-mono mt-0.5 ${isMalware ? 'text-red-300' : 'text-foreground'}`}>
                            {mb.malware_family}
                          </p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">Signature</span>
                          <p className={`font-mono mt-0.5 truncate ${isMalware ? 'text-amber-300' : 'text-foreground'}`}>
                            {mb.signature}
                          </p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" /> First Seen</span>
                          <p className="text-foreground font-mono mt-0.5">{formatDate(mb.first_seen)}</p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" /> Last Seen</span>
                          <p className="text-foreground font-mono mt-0.5">{formatDate(mb.last_seen)}</p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">File</span>
                          <p className="text-foreground font-mono mt-0.5 truncate">{mb.file_name}</p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">Size</span>
                          <p className="text-foreground font-mono mt-0.5">{formatFileSize(mb.file_size)}</p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">MIME Type</span>
                          <p className="text-foreground font-mono mt-0.5 truncate">{mb.file_type_mime}</p>
                        </div>
                        <div className="p-2 rounded-lg bg-muted/30 border border-border/20">
                          <span className="text-muted-foreground">Delivery</span>
                          <p className="text-foreground font-mono mt-0.5 truncate">{mb.delivery_method}</p>
                        </div>
                      </div>

                      {/* Tags */}
                      {mb.tags && mb.tags.length > 0 && (
                        <div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">Tags</p>
                          <div className="flex flex-wrap gap-1">
                            {mb.tags.map((tag: string, i: number) => (
                              <Badge key={i} variant="outline" className="text-[10px] font-mono text-amber-300 border-amber-500/30">{tag}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Reporter */}
                      {mb.reporter && mb.reporter !== 'Unknown' && (
                        <p className="text-[10px] text-muted-foreground">
                          Reported by: <span className="text-foreground font-mono">{mb.reporter}</span>
                        </p>
                      )}
                    </div>
                  );
                })()}

                {/* No malware found */}
                {result.results.malwarebazaar?.data === null &&
                 result.results.malwarebazaar?.query_status === 'no_results' && (
                  <div className="text-center py-4 text-muted-foreground">
                    <CheckCircle className="h-6 w-6 mx-auto mb-1.5 opacity-40" />
                    <p className="text-xs">Hash not found in MalwareBazaar</p>
                    <p className="text-[10px] mt-0.5">No known malware associations</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* ──── URLhaus ──── */}
            {result.results.urlhaus && result.results.urlhaus.status === 'success' && (
              <Card className="forensic-card">
                <CardContent className="p-4">
                  <SectionHeader
                    icon={Globe}
                    title="URLhaus"
                    status="success"
                    href={result.results.urlhaus.urlhaus_reference}
                  />
                  <div className="space-y-2 text-xs">
                    <div className="flex items-center gap-2 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30">
                      <AlertTriangle className="h-4 w-4 text-red-400" />
                      <span className="text-red-300 font-semibold">Threat: {result.results.urlhaus.threat}</span>
                    </div>
                    <p className="text-muted-foreground">
                      Reference:{' '}
                      <a
                        href={result.results.urlhaus.urlhaus_reference}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan hover:underline font-mono inline-flex items-center gap-1"
                      >
                        URLhaus Link <ExternalLink className="h-3 w-3" />
                      </a>
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* ──── Timestamp ──── */}
            <div className="text-center py-2">
              <p className="text-[10px] text-muted-foreground font-mono">
                Checked at {result.checkedAt}
              </p>
            </div>
          </div>
        </ScrollArea>
      )}

      {/* ──── Empty State ──── */}
      {!result && !loading && !error && (
        <div className="text-center py-16 text-muted-foreground">
          <Fingerprint className="h-10 w-10 mx-auto mb-3 opacity-30" />
          <p className="text-sm font-medium">Hash Reputation Lookup</p>
          <p className="text-xs mt-1 max-w-xs mx-auto">
            Enter a file hash above or click an evidence hash to check its reputation against VirusTotal, MalwareBazaar, and URLhaus threat intelligence sources.
          </p>
          <div className="flex items-center justify-center gap-4 mt-4 text-[10px]">
            <span className="flex items-center gap-1"><Shield className="h-3 w-3 text-cyan" /> VirusTotal</span>
            <span className="flex items-center gap-1"><Skull className="h-3 w-3 text-cyan" /> MalwareBazaar</span>
            <span className="flex items-center gap-1"><Globe className="h-3 w-3 text-cyan" /> URLhaus</span>
          </div>
        </div>
      )}
    </div>
  );
}
