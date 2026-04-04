'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from '@/components/ui/table';
import {
  Globe,
  Globe2,
  Link,
  Mail,
  Fingerprint,
  ShieldAlert,
  Wifi,
  Search,
  Copy,
  Download,
  Crosshair,
  AlertTriangle,
  Hash,
  FileText,
  CheckCircle2,
  Filter,
  Database,
  CircleDot,
} from 'lucide-react';
import type { AnalysisResult, IOCItem } from '@/lib/forensic/types';

// ── Color maps ──────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<IOCItem['severity'], string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
};

const TYPE_COLORS: Record<IOCItem['type'], string> = {
  ip: '#06b6d4',
  domain: '#8b5cf6',
  url: '#3b82f6',
  email: '#ec4899',
  hash: '#64748b',
  bitcoin: '#f59e0b',
  cve: '#ef4444',
  mac: '#22c55e',
  file_path: '#f97316',
};

const TYPE_LABELS: Record<IOCItem['type'], string> = {
  ip: 'IP',
  domain: 'Domain',
  url: 'URL',
  email: 'Email',
  hash: 'Hash',
  bitcoin: 'Bitcoin',
  cve: 'CVE',
  mac: 'MAC',
  file_path: 'File Path',
};

// ── Icon helper ─────────────────────────────────────────────────────────

function IOCTypeIcon({ type, size = 14 }: { type: IOCItem['type']; size?: number }) {
  const props = { width: size, height: size };
  switch (type) {
    case 'ip':
      return <Globe {...props} />;
    case 'domain':
      return <Globe2 {...props} />;
    case 'url':
      return <Link {...props} />;
    case 'email':
      return <Mail {...props} />;
    case 'hash':
      return <Fingerprint {...props} />;
    case 'bitcoin':
      return <Hash {...props} />;
    case 'cve':
      return <ShieldAlert {...props} />;
    case 'mac':
      return <Wifi {...props} />;
    case 'file_path':
      return <FileText {...props} />;
    default:
      return <Crosshair {...props} />;
  }
}

// ── Filter types ────────────────────────────────────────────────────────

type TypeFilter = 'all' | IOCItem['type'];
type SeverityFilter = 'all' | IOCItem['severity'];

const TYPE_FILTERS: { value: TypeFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'ip', label: 'IPs' },
  { value: 'domain', label: 'Domains' },
  { value: 'url', label: 'URLs' },
  { value: 'email', label: 'Emails' },
  { value: 'hash', label: 'Hashes' },
  { value: 'bitcoin', label: 'Bitcoin' },
  { value: 'cve', label: 'CVEs' },
  { value: 'mac', label: 'MACs' },
  { value: 'file_path', label: 'Files' },
];

const SEVERITY_FILTERS: { value: SeverityFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

// ── Props ───────────────────────────────────────────────────────────────

interface IOCDashboardProps {
  data: AnalysisResult;
}

// ── Component ───────────────────────────────────────────────────────────

export default function IOCDashboard({ data }: IOCDashboardProps) {
  const iocs = data.iocs ?? [];

  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  // ── Computed stats ──────────────────────────────────────────────────

  const stats = useMemo(() => {
    const total = iocs.length;
    const critical = iocs.filter((i) => i.severity === 'critical').length;
    const ips = iocs.filter((i) => i.type === 'ip').length;
    const domains = iocs.filter((i) => i.type === 'domain').length;
    return { total, critical, ips, domains };
  }, [iocs]);

  // ── Filtered data ───────────────────────────────────────────────────

  const filteredIOCs = useMemo(() => {
    return iocs.filter((ioc) => {
      if (typeFilter !== 'all' && ioc.type !== typeFilter) return false;
      if (severityFilter !== 'all' && ioc.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        if (
          !ioc.value.toLowerCase().includes(q) &&
          !ioc.context.toLowerCase().includes(q) &&
          !ioc.source.toLowerCase().includes(q) &&
          !ioc.tags.some((t) => t.toLowerCase().includes(q))
        )
          return false;
      }
      return true;
    });
  }, [iocs, typeFilter, severityFilter, searchQuery]);

  // ── Actions ─────────────────────────────────────────────────────────

  const handleCopyAll = async () => {
    const text = iocs
      .map(
        (ioc) =>
          `[${ioc.type.toUpperCase()}] ${ioc.value}  |  Severity: ${ioc.severity}  |  Source: ${ioc.source}  |  Context: ${ioc.context}`
      )
      .join('\n');
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(iocs, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iocs-${data.caseId}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // ── Empty state ─────────────────────────────────────────────────────

  if (!iocs.length) {
    return (
      <div className="forensic-card p-12 flex flex-col items-center justify-center text-center gap-4">
        <div className="h-16 w-16 rounded-2xl bg-cyan/10 flex items-center justify-center">
          <Database className="h-8 w-8 text-cyan/60" />
        </div>
        <div>
          <p className="text-muted-foreground text-sm">
            No IOCs extracted. Upload evidence to auto-extract indicators.
          </p>
        </div>
      </div>
    );
  }

  // ── Render ──────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      {/* ── Stats Row ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total IOCs */}
        <Card className="forensic-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest">
                  Total IOCs
                </p>
                <p className="text-2xl font-bold font-mono text-foreground mt-1">
                  {stats.total}
                </p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-cyan/10 flex items-center justify-center">
                <Crosshair className="h-5 w-5 text-cyan" />
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
              <CircleDot className="h-3 w-3 text-cyan" />
              <span>Indicators extracted</span>
            </div>
          </CardContent>
        </Card>

        {/* Critical */}
        <Card className="forensic-card forensic-glow-red">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest">
                  Critical
                </p>
                <p className="text-2xl font-bold font-mono text-foreground mt-1">
                  {stats.critical}
                </p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <AlertTriangle className="h-5 w-5 text-red-500" />
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-red-400">
              <ShieldAlert className="h-3 w-3" />
              <span>Immediate attention</span>
            </div>
          </CardContent>
        </Card>

        {/* IPs */}
        <Card className="forensic-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest">
                  IPs
                </p>
                <p className="text-2xl font-bold font-mono text-foreground mt-1">
                  {stats.ips}
                </p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-cyan/10 flex items-center justify-center">
                <Globe className="h-5 w-5 text-cyan" />
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
              <span>Unique addresses</span>
            </div>
          </CardContent>
        </Card>

        {/* Domains */}
        <Card className="forensic-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest">
                  Domains
                </p>
                <p className="text-2xl font-bold font-mono text-foreground mt-1">
                  {stats.domains}
                </p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
                <Globe2 className="h-5 w-5 text-purple-400" />
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
              <span>Unique domains</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Main Table Card ───────────────────────────────────────────── */}
      <Card className="forensic-card">
        <CardHeader className="pb-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Filter className="h-4 w-4 text-cyan" />
              Indicators of Compromise
              <Badge
                variant="outline"
                className="border-cyan/30 text-cyan bg-cyan/5 text-[10px] font-mono ml-1"
              >
                {filteredIOCs.length} / {iocs.length}
              </Badge>
            </CardTitle>

            {/* Action buttons */}
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-xs border-border hover:border-cyan/40 hover:bg-cyan/5 hover:text-cyan transition-colors"
                onClick={handleCopyAll}
              >
                {copied ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copied ? 'Copied!' : 'Copy All'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 text-xs border-border hover:border-cyan/40 hover:bg-cyan/5 hover:text-cyan transition-colors"
                onClick={handleExportJSON}
              >
                <Download className="h-3.5 w-3.5" />
                Export JSON
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* ── Search & Filters ───────────────────────────────────────── */}
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search IOCs by value, context, source, or tag..."
              className="h-9 pl-9 bg-[#0a0a14] border-border/60 text-sm placeholder:text-muted-foreground/60 focus:border-cyan/50 focus:ring-cyan/20 font-mono"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {/* Type Filter */}
          <div className="flex flex-wrap gap-1.5">
            {TYPE_FILTERS.map((filter) => {
              const isActive = typeFilter === filter.value;
              const color =
                filter.value === 'all'
                  ? '#06b6d4'
                  : TYPE_COLORS[filter.value as IOCItem['type']] ?? '#64748b';
              return (
                <button
                  key={filter.value}
                  onClick={() => setTypeFilter(filter.value)}
                  className="px-2.5 py-1 rounded-md text-[11px] font-medium transition-all border"
                  style={{
                    backgroundColor: isActive ? `${color}18` : 'transparent',
                    borderColor: isActive ? `${color}50` : 'rgba(30, 41, 59, 0.5)',
                    color: isActive ? color : '#64748b',
                  }}
                >
                  {filter.label}
                </button>
              );
            })}
          </div>

          {/* Severity Filter */}
          <div className="flex flex-wrap gap-1.5">
            {SEVERITY_FILTERS.map((filter) => {
              const isActive = severityFilter === filter.value;
              const color =
                filter.value === 'all'
                  ? '#06b6d4'
                  : SEVERITY_COLORS[filter.value as IOCItem['severity']];
              return (
                <button
                  key={filter.value}
                  onClick={() => setSeverityFilter(filter.value)}
                  className="px-2.5 py-1 rounded-md text-[11px] font-medium transition-all border"
                  style={{
                    backgroundColor: isActive ? `${color}18` : 'transparent',
                    borderColor: isActive ? `${color}50` : 'rgba(30, 41, 59, 0.5)',
                    color: isActive ? color : '#64748b',
                  }}
                >
                  {filter.label}
                </button>
              );
            })}
          </div>

          {/* ── Table ──────────────────────────────────────────────────── */}
          <ScrollArea className="max-h-[520px] scrollbar-forensic">
            <Table>
              <TableHeader>
                <TableRow className="border-border/40 hover:bg-transparent">
                  <TableHead className="w-[48px] text-[10px] uppercase tracking-wider text-muted-foreground">
                    Type
                  </TableHead>
                  <TableHead className="min-w-[200px] text-[10px] uppercase tracking-wider text-muted-foreground">
                    Value
                  </TableHead>
                  <TableHead className="w-[140px] text-[10px] uppercase tracking-wider text-muted-foreground">
                    Source
                  </TableHead>
                  <TableHead className="w-[200px] text-[10px] uppercase tracking-wider text-muted-foreground">
                    Context
                  </TableHead>
                  <TableHead className="w-[88px] text-[10px] uppercase tracking-wider text-muted-foreground">
                    Severity
                  </TableHead>
                  <TableHead className="w-[160px] text-[10px] uppercase tracking-wider text-muted-foreground">
                    Tags
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredIOCs.length === 0 ? (
                  <TableRow className="border-border/20">
                    <TableCell
                      colSpan={6}
                      className="h-24 text-center text-muted-foreground text-sm"
                    >
                      <Database className="h-5 w-5 mx-auto mb-2 text-muted-foreground/40" />
                      No IOCs match the current filters.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredIOCs.map((ioc, idx) => {
                    const typeColor = TYPE_COLORS[ioc.type];
                    const sevColor = SEVERITY_COLORS[ioc.severity];

                    return (
                      <TableRow
                        key={`${ioc.type}-${ioc.value}-${idx}`}
                        className="border-border/20 hover:bg-cyan/[0.03] transition-colors"
                      >
                        {/* Type badge */}
                        <TableCell className="py-2.5">
                          <div
                            className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-semibold uppercase tracking-wider"
                            style={{
                              backgroundColor: `${typeColor}15`,
                              color: typeColor,
                            }}
                          >
                            <IOCTypeIcon type={ioc.type} size={12} />
                            <span>{TYPE_LABELS[ioc.type]}</span>
                          </div>
                        </TableCell>

                        {/* Value */}
                        <TableCell className="py-2.5">
                          <span
                            className="font-mono text-xs text-foreground block max-w-[320px] truncate"
                            title={ioc.value}
                          >
                            {ioc.value}
                          </span>
                        </TableCell>

                        {/* Source */}
                        <TableCell className="py-2.5">
                          <span
                            className="text-[11px] text-muted-foreground block max-w-[140px] truncate"
                            title={ioc.source}
                          >
                            {ioc.source}
                          </span>
                        </TableCell>

                        {/* Context */}
                        <TableCell className="py-2.5">
                          <span
                            className="text-[11px] text-muted-foreground block max-w-[200px] truncate"
                            title={ioc.context}
                          >
                            {ioc.context || '—'}
                          </span>
                        </TableCell>

                        {/* Severity */}
                        <TableCell className="py-2.5">
                          <Badge
                            variant="outline"
                            className="text-[10px] font-semibold px-1.5 py-0 border-current"
                            style={{
                              color: sevColor,
                              borderColor: `${sevColor}50`,
                              backgroundColor: `${sevColor}12`,
                            }}
                          >
                            {ioc.severity.toUpperCase()}
                          </Badge>
                        </TableCell>

                        {/* Tags */}
                        <TableCell className="py-2.5">
                          <div className="flex flex-wrap gap-1 max-w-[160px]">
                            {ioc.tags.slice(0, 3).map((tag) => (
                              <Badge
                                key={tag}
                                variant="outline"
                                className="text-[9px] font-mono px-1.5 py-0 border-border/50 text-muted-foreground bg-[#0a0a14]"
                              >
                                {tag}
                              </Badge>
                            ))}
                            {ioc.tags.length > 3 && (
                              <span className="text-[9px] text-muted-foreground self-center">
                                +{ioc.tags.length - 3}
                              </span>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
