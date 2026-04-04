'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from '@/components/ui/table';
import {
  FileText,
  Download,
  FileJson,
  Printer,
  Eye,
  Shield,
  AlertTriangle,
  Clock,
  Loader2,
} from 'lucide-react';
import { format } from 'date-fns';
import type { AnalysisResult, Evidence, SuspiciousFinding, TimelineEvent, IOCItem } from '@/lib/forensic/types';

function safeFormat(timestamp: string | undefined | null, fmt: string): string {
  if (!timestamp) return '--:--';
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return '--:--';
  return format(d, fmt);
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  highly_suspicious: '#f97316',
  suspicious: '#f59e0b',
  benign: '#22c55e',
};

interface ReportGeneratorProps {
  data: AnalysisResult | null;
}

export default function ReportGenerator({ data }: ReportGeneratorProps) {
  const [showPreview, setShowPreview] = useState(true);

  if (!data) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-280px)]">
        <div className="text-center text-muted-foreground">
          <Loader2 className="h-8 w-8 mx-auto mb-2 animate-spin" />
          <p className="text-sm">Loading report data...</p>
        </div>
      </div>
    );
  }

  const caseInfo = data?.caseInfo;
  const evidence = data?.evidence || [];
  const timeline = data?.timeline || [];
  const suspiciousFindings = data?.suspiciousFindings || [];
  const rewindSequence = data?.rewindSequence || [];
  const iocs = data?.iocs || [];
  const custody = data?.custody || [];
  const stats = data?.stats || { totalEvents: 0, suspiciousCount: 0, criticalCount: 0, timeRange: { start: '', end: '' }, topCategories: [] };

  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `JURI-X-Report-${caseInfo.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadReport = () => {
    const report = generateTextReport(data);
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `JURI-X-Forensic-Report-${caseInfo.id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadPDF = () => {
    const reportHTML = generateHTMLReport(data);
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(reportHTML);
      printWindow.document.close();
      setTimeout(() => printWindow.print(), 500);
    }
  };

  return (
    <div className="space-y-4">
      {/* Actions */}
      <Card className="forensic-card">
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-cyan" />
              <div>
                <h3 className="text-sm font-semibold text-foreground">Court-Ready Report</h3>
                <p className="text-xs text-muted-foreground">Generated {safeFormat(new Date().toISOString(), "yyyy-MM-dd HH:mm:ss")} UTC</p>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                variant="default"
                size="sm"
                className="bg-cyan hover:bg-cyan/80 text-background"
                onClick={downloadReport}
              >
                <Download className="h-3.5 w-3.5 mr-1" />
                Download Report
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="border-border/50"
                onClick={downloadPDF}
              >
                <Printer className="h-3.5 w-3.5 mr-1" />
                Print PDF
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="border-border/50"
                onClick={downloadJSON}
              >
                <FileJson className="h-3.5 w-3.5 mr-1" />
                Download JSON
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowPreview(!showPreview)}
              >
                <Eye className="h-3.5 w-3.5 mr-1" />
                {showPreview ? 'Hide' : 'Preview'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Report Preview */}
      {showPreview && (
        <ScrollArea className="h-[calc(100vh-360px)] scrollbar-forensic">
          <div className="space-y-4 pr-4">
            {/* Header */}
            <Card className="forensic-card">
              <CardContent className="p-6">
                <div className="text-center border-b border-border/50 pb-4 mb-4">
                  <div className="flex items-center justify-center gap-2 mb-2">
                    <Shield className="h-6 w-6 text-cyan" />
                    <h1 className="text-lg font-bold tracking-wider text-foreground">JURI-X FORENSIC REPORT</h1>
                  </div>
                  <p className="text-xs text-muted-foreground">Autonomous Forensic Intelligence Platform</p>
                  <p className="text-[10px] text-muted-foreground font-mono mt-1">
                    Generated: {safeFormat(new Date().toISOString(), "yyyy-MM-dd HH:mm:ss")} UTC | Classification: CONFIDENTIAL
                  </p>
                </div>

                {/* Case Info */}
                <div className="space-y-3">
                  <h2 className="text-sm font-bold text-foreground uppercase tracking-wider">1. Case Information</h2>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Case ID:</span>{' '}
                      <span className="font-mono text-cyan">{caseInfo.id}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Status:</span>{' '}
                      <Badge variant="outline" className="border-cyan/50 text-cyan bg-cyan/10 text-[10px]">
                        {caseInfo.status.toUpperCase()}
                      </Badge>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Case Name:</span>{' '}
                      <span className="text-foreground">{caseInfo.name}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Analyst:</span>{' '}
                      <span className="text-foreground">{caseInfo.analyst}</span>
                    </div>
                    <div className="col-span-2">
                      <span className="text-muted-foreground">Description:</span>{' '}
                      <span className="text-foreground">{caseInfo.description}</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Evidence Summary */}
            <Card className="forensic-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                  2. Evidence Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="rounded-lg border border-border/50 overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted/30 hover:bg-muted/30">
                        <TableHead className="text-[10px] uppercase tracking-wider">Name</TableHead>
                        <TableHead className="text-[10px] uppercase tracking-wider">Type</TableHead>
                        <TableHead className="text-[10px] uppercase tracking-wider">Size</TableHead>
                        <TableHead className="text-[10px] uppercase tracking-wider">Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {evidence.map((ev: Evidence) => (
                        <TableRow key={ev.id} className="border-border/30">
                          <TableCell className="text-xs font-mono text-cyan py-2">{ev.name}</TableCell>
                          <TableCell className="text-xs py-2">
                            <Badge variant="secondary" className="text-[10px] capitalize">
                              {ev.type.replace(/_/g, ' ')}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs font-mono text-foreground py-2">
                            {(ev.size / (1024 * 1024 * 1024)).toFixed(2)} GB
                          </TableCell>
                          <TableCell className="text-xs py-2">
                            <Badge
                              variant="outline"
                              className="text-[10px]"
                              style={{
                                borderColor: ev.status === 'analyzed' ? '#22c55e' : '#f59e0b',
                                color: ev.status === 'analyzed' ? '#22c55e' : '#f59e0b',
                              }}
                            >
                              {ev.status}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>

            {/* Timeline Summary */}
            <Card className="forensic-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                  3. Timeline Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="grid grid-cols-3 gap-3 mb-3">
                  <div className="p-2 rounded-lg bg-muted/30 text-center">
                    <p className="text-lg font-bold font-mono text-foreground">{stats.totalEvents}</p>
                    <p className="text-[10px] text-muted-foreground">Total Events</p>
                  </div>
                  <div className="p-2 rounded-lg bg-red-500/10 text-center">
                    <p className="text-lg font-bold font-mono text-red-400">{stats.criticalCount}</p>
                    <p className="text-[10px] text-muted-foreground">Critical</p>
                  </div>
                  <div className="p-2 rounded-lg bg-amber-500/10 text-center">
                    <p className="text-lg font-bold font-mono text-amber-400">{stats.suspiciousCount}</p>
                    <p className="text-[10px] text-muted-foreground">Suspicious</p>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  Time Range:{' '}
                  <span className="font-mono text-foreground">
                    {safeFormat(stats.timeRange?.start, 'yyyy-MM-dd HH:mm:ss')} → {safeFormat(stats.timeRange?.end, 'HH:mm:ss')}
                  </span>
                </p>
              </CardContent>
            </Card>

            {/* Key Findings */}
            <Card className="forensic-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                  4. Key Findings
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="space-y-2">
                  {suspiciousFindings.slice(0, 5).map((finding: SuspiciousFinding) => (
                    <div
                      key={finding.id}
                      className="p-3 rounded-lg border border-border/50"
                      style={{ borderLeftColor: SEVERITY_COLORS[finding.severity], borderLeftWidth: '3px' }}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Badge
                          variant="outline"
                          className="text-[10px]"
                          style={{
                            borderColor: SEVERITY_COLORS[finding.severity],
                            color: SEVERITY_COLORS[finding.severity],
                          }}
                        >
                          {finding.severity.replace(/_/g, ' ')}
                        </Badge>
                        <span className="text-xs font-semibold text-foreground">{finding.title}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{finding.description}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* IOCs */}
            {iocs.length > 0 && (
              <Card className="forensic-card">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                    5. Indicators of Compromise
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 pt-0">
                  <div className="rounded-lg border border-border/50 overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-muted/30 hover:bg-muted/30">
                          <TableHead className="text-[10px] uppercase tracking-wider">Type</TableHead>
                          <TableHead className="text-[10px] uppercase tracking-wider">Value</TableHead>
                          <TableHead className="text-[10px] uppercase tracking-wider">Source</TableHead>
                          <TableHead className="text-[10px] uppercase tracking-wider">Severity</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {iocs.slice(0, 10).map((ioc: IOCItem, idx: number) => (
                          <TableRow key={`${ioc.type}-${ioc.value}-${idx}`} className="border-border/30">
                            <TableCell className="text-xs py-2">
                              <Badge variant="secondary" className="text-[10px] uppercase">
                                {ioc.type}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-xs font-mono text-cyan py-2 max-w-[240px] truncate">
                              {ioc.value}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground py-2 max-w-[160px] truncate">
                              {ioc.source}
                            </TableCell>
                            <TableCell className="text-xs py-2">
                              <Badge
                                variant="outline"
                                className="text-[10px]"
                                style={{
                                  borderColor: ioc.severity === 'critical' ? '#ef4444'
                                    : ioc.severity === 'high' ? '#f97316'
                                    : ioc.severity === 'medium' ? '#f59e0b'
                                    : '#22c55e',
                                  color: ioc.severity === 'critical' ? '#ef4444'
                                    : ioc.severity === 'high' ? '#f97316'
                                    : ioc.severity === 'medium' ? '#f59e0b'
                                    : '#22c55e',
                                }}
                              >
                                {ioc.severity.toUpperCase()}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {iocs.length > 10 && (
                    <p className="text-[10px] text-muted-foreground mt-2">
                      Showing 10 of {iocs.length} IOCs. Export full list from IOC Dashboard.
                    </p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Rewind Sequence */}
            <Card className="forensic-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                  6. Forensic Rewind Sequence
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="space-y-1">
                  {rewindSequence.map((event, idx) => (
                    <div key={event.id} className="flex items-start gap-2 text-xs py-1">
                      <span className="text-muted-foreground font-mono shrink-0 w-6">{String(idx + 1).padStart(2, '0')}</span>
                      <span className="text-muted-foreground font-mono shrink-0">
                        {safeFormat(event.timestamp, 'HH:mm:ss')}
                      </span>
                      <span className="text-foreground capitalize shrink-0">{event.action.replace(/_/g, ' ')}</span>
                      <span className="text-muted-foreground truncate">{event.description}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Chain of Custody */}
            <Card className="forensic-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                  7. Chain of Custody
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="space-y-2">
                  {custody.map((entry) => (
                    <div key={entry.id} className="flex items-start gap-3 p-2 rounded-lg bg-muted/20">
                      <Badge variant="secondary" className="text-[10px] capitalize shrink-0 mt-0.5">
                        {entry.action}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-foreground">{entry.details}</p>
                        <div className="flex items-center gap-3 mt-0.5 text-[10px] text-muted-foreground">
                          <span>{entry.performedBy}</span>
                          <span className="font-mono">{safeFormat(entry.timestamp, 'yyyy-MM-dd HH:mm')}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Footer */}
            <Card className="forensic-card">
              <CardContent className="p-4 text-center">
                <Separator className="mb-3 bg-border/50" />
                <p className="text-[10px] text-muted-foreground">
                  This report was generated by JURI-X Autonomous Forensic Intelligence Platform.
                </p>
                <p className="text-[10px] text-muted-foreground mt-1">
                  All findings are based on automated analysis and should be verified by a qualified forensic examiner.
                </p>
                <p className="text-[10px] text-muted-foreground font-mono mt-2">
                  Report ID: {caseInfo.id}-{Date.now()} | Classification: CONFIDENTIAL
                </p>
              </CardContent>
            </Card>
          </div>
        </ScrollArea>
      )}
    </div>
  );
}

function generateHTMLReport(data: AnalysisResult): string {
  const caseInfo = data.caseInfo;
  const evidence = data.evidence || [];
  const stats = data.stats || { totalEvents: 0, suspiciousCount: 0, criticalCount: 0, timeRange: { start: '', end: '' } };
  const findings = data.suspiciousFindings || [];
  const rewind = data.rewindSequence || [];
  const custody = data.custody || [];
  const iocs = data.iocs || [];

  function esc(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  const evidenceRows = evidence.map((ev, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${esc(ev.name)}</td>
      <td>${esc(ev.type.replace(/_/g, ' '))}</td>
      <td>${(ev.size / 1024 / 1024 / 1024).toFixed(2)} GB</td>
      <td>${esc(ev.status)}</td>
      <td><code>${esc(ev.hash)}</code></td>
    </tr>`).join('');

  const findingRows = findings.map((f, i) => `
    <tr style="border-left: 3px solid ${SEVERITY_COLORS[f.severity] || '#64748b'}">
      <td>${i + 1}</td>
      <td><strong>${esc(f.severity.replace(/_/g, ' ').toUpperCase())}</strong></td>
      <td>${esc(f.title)}</td>
      <td>${esc(f.category)}</td>
      <td>${(f.confidence * 100).toFixed(0)}%</td>
      <td>${esc(f.description)}</td>
      <td>${esc(f.recommendation)}</td>
    </tr>`).join('');

  const rewindRows = rewind.map((e, i) => `
    <tr>
      <td>${String(i + 1).padStart(2, '0')}</td>
      <td>${esc(e.timestamp)}</td>
      <td>${esc(e.action.replace(/_/g, ' '))}</td>
      <td>${esc(e.entity)}</td>
      <td>${esc(e.description)}</td>
    </tr>`).join('');

  const custodyRows = custody.map((c) => `
    <tr>
      <td>${esc(c.action)}</td>
      <td>${esc(c.details)}</td>
      <td>${esc(c.performedBy)}</td>
      <td>${esc(c.timestamp)}</td>
    </tr>`).join('');

  const iocRows = iocs.map((ioc, i) => `
    <tr>
      <td>${i + 1}</td>
      <td>${esc((ioc.type || 'unknown').toUpperCase())}</td>
      <td><code>${esc(ioc.value)}</code></td>
      <td>${esc(ioc.source)}</td>
      <td>${esc(ioc.context || '')}</td>
      <td><strong>${esc((ioc.severity || 'medium').toUpperCase())}</strong></td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>JURI-X Forensic Report - ${esc(caseInfo.id)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #111; background: #fff; padding: 40px; line-height: 1.5; font-size: 13px; }
    .header { text-align: center; border-bottom: 3px solid #1a1a2e; padding-bottom: 20px; margin-bottom: 30px; }
    .header h1 { font-size: 22px; letter-spacing: 3px; color: #1a1a2e; margin-bottom: 4px; }
    .header .subtitle { font-size: 11px; color: #666; }
    .header .meta { font-size: 10px; color: #888; margin-top: 8px; font-family: monospace; }
    .classification { display: inline-block; background: #dc2626; color: white; padding: 2px 10px; border-radius: 3px; font-size: 10px; font-weight: bold; letter-spacing: 1px; margin-top: 8px; }
    h2 { font-size: 15px; color: #1a1a2e; border-bottom: 1px solid #ddd; padding-bottom: 6px; margin: 28px 0 14px 0; letter-spacing: 1px; }
    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 20px; margin-bottom: 10px; }
    .info-grid .label { color: #666; font-size: 12px; }
    .info-grid .value { font-weight: 500; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0 20px 0; font-size: 12px; }
    th { background: #f3f4f6; text-align: left; padding: 8px 10px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #555; border-bottom: 2px solid #ddd; }
    td { padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
    tr:hover { background: #f9fafb; }
    code { background: #f3f4f6; padding: 1px 5px; border-radius: 3px; font-size: 11px; }
    .stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 14px 0; }
    .stat-box { text-align: center; padding: 14px; border: 1px solid #ddd; border-radius: 6px; }
    .stat-box .number { font-size: 24px; font-weight: bold; font-family: monospace; }
    .stat-box .label { font-size: 10px; color: #666; text-transform: uppercase; }
    .footer { margin-top: 40px; border-top: 1px solid #ddd; padding-top: 16px; text-align: center; font-size: 10px; color: #888; }
    @media print { body { padding: 20px; } .no-print { display: none; } }
  </style>
</head>
<body>
  <div class="header">
    <h1>&#x1F6E1; JURI-X FORENSIC REPORT</h1>
    <div class="subtitle">Autonomous Forensic Intelligence Platform</div>
    <div class="meta">Generated: ${new Date().toISOString()} | Case: ${esc(caseInfo.id)}</div>
    <div class="classification">CONFIDENTIAL</div>
  </div>

  <h2>1. CASE INFORMATION</h2>
  <div class="info-grid">
    <div><span class="label">Case ID:</span> <span class="value">${esc(caseInfo.id)}</span></div>
    <div><span class="label">Status:</span> <span class="value">${esc(caseInfo.status.toUpperCase())}</span></div>
    <div><span class="label">Case Name:</span> <span class="value">${esc(caseInfo.name)}</span></div>
    <div><span class="label">Analyst:</span> <span class="value">${esc(caseInfo.analyst)}</span></div>
    <div style="grid-column: span 2"><span class="label">Description:</span> <span class="value">${esc(caseInfo.description)}</span></div>
  </div>

  <h2>2. EVIDENCE SUMMARY</h2>
  <table>
    <thead><tr><th>#</th><th>Name</th><th>Type</th><th>Size</th><th>Status</th><th>Hash</th></tr></thead>
    <tbody>${evidenceRows}</tbody>
  </table>

  <h2>3. ANALYSIS STATISTICS</h2>
  <div class="stats-row">
    <div class="stat-box"><div class="number">${stats.totalEvents}</div><div class="label">Total Events</div></div>
    <div class="stat-box"><div class="number" style="color:#ef4444">${stats.criticalCount}</div><div class="label">Critical</div></div>
    <div class="stat-box"><div class="number" style="color:#f59e0b">${stats.suspiciousCount}</div><div class="label">Suspicious</div></div>
    <div class="stat-box"><div class="number">${evidence.length}</div><div class="label">Evidence Items</div></div>
  </div>
  <p style="font-size:12px;color:#666;">Time Range: ${esc(stats.timeRange?.start || 'N/A')} &rarr; ${esc(stats.timeRange?.end || 'N/A')}</p>

  <h2>4. KEY FINDINGS</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Category</th><th>Confidence</th><th>Description</th><th>Recommendation</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>

  ${iocs.length > 0 ? `
  <h2>5. INDICATORS OF COMPROMISE</h2>
  <table>
    <thead><tr><th>#</th><th>Type</th><th>Value</th><th>Source</th><th>Context</th><th>Severity</th></tr></thead>
    <tbody>${iocRows}</tbody>
  </table>
  ` : ''}

  <h2>${iocs.length > 0 ? '6' : '5'}. FORENSIC REWIND SEQUENCE</h2>
  <table>
    <thead><tr><th>#</th><th>Timestamp</th><th>Action</th><th>Entity</th><th>Description</th></tr></thead>
    <tbody>${rewindRows}</tbody>
  </table>

  <h2>${iocs.length > 0 ? '7' : '6'}. CHAIN OF CUSTODY</h2>
  <table>
    <thead><tr><th>Action</th><th>Details</th><th>Performed By</th><th>Timestamp</th></tr></thead>
    <tbody>${custodyRows}</tbody>
  </table>

  <div class="footer">
    <p>This report was generated by JURI-X Autonomous Forensic Intelligence Platform.</p>
    <p style="margin-top:4px;">All findings are based on automated analysis and should be verified by a qualified forensic examiner.</p>
    <p style="margin-top:6px;font-family:monospace;">Report ID: ${esc(caseInfo.id)}-${Date.now()} | Classification: CONFIDENTIAL</p>
  </div>
</body>
</html>`;
}

function generateTextReport(data: AnalysisResult): string {
  const lines: string[] = [];
  const sep = '═'.repeat(60);

  lines.push(sep);
  lines.push('  JURI-X FORENSIC INTELLIGENCE REPORT');
  lines.push('  Autonomous Digital Forensics & Incident Response');
  lines.push(sep);
  lines.push('');
  lines.push(`Report Generated: ${new Date().toISOString()}`);
  lines.push(`Classification: CONFIDENTIAL`);
  lines.push('');
  lines.push('─'.repeat(60));
  lines.push('1. CASE INFORMATION');
  lines.push('─'.repeat(60));
  lines.push(`Case ID:         ${data.caseInfo.id}`);
  lines.push(`Case Name:       ${data.caseInfo.name}`);
  lines.push(`Status:          ${data.caseInfo.status}`);
  lines.push(`Analyst:         ${data.caseInfo.analyst}`);
  lines.push(`Created:         ${data.caseInfo.createdAt}`);
  lines.push(`Description:     ${data.caseInfo.description}`);
  lines.push('');

  lines.push('─'.repeat(60));
  lines.push('2. EVIDENCE SUMMARY');
  lines.push('─'.repeat(60));
  data.evidence.forEach((ev, i) => {
    lines.push(`  [${i + 1}] ${ev.name}`);
    lines.push(`      Type: ${ev.type} | Size: ${(ev.size / 1024 / 1024 / 1024).toFixed(2)} GB | Status: ${ev.status}`);
    lines.push(`      Hash: ${ev.hash}`);
    lines.push('');
  });

  lines.push('─'.repeat(60));
  lines.push('3. ANALYSIS STATISTICS');
  lines.push('─'.repeat(60));
  lines.push(`Total Events:    ${data.stats.totalEvents}`);
  lines.push(`Critical:        ${data.stats.criticalCount}`);
  lines.push(`Suspicious:      ${data.stats.suspiciousCount}`);
  lines.push(`Time Range:      ${data.stats.timeRange.start} → ${data.stats.timeRange.end}`);
  lines.push('');

  lines.push('─'.repeat(60));
  lines.push('4. SUSPICIOUS FINDINGS');
  lines.push('─'.repeat(60));
  data.suspiciousFindings.forEach((f, i) => {
    lines.push(`  [${i + 1}] [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`      Category: ${f.category}`);
    lines.push(`      Evidence: ${f.evidence}`);
    lines.push(`      Confidence: ${(f.confidence * 100).toFixed(0)}%`);
    lines.push(`      Description: ${f.description}`);
    lines.push(`      Recommendation: ${f.recommendation}`);
    lines.push('');
  });

  lines.push('─'.repeat(60));
  lines.push('5. REWIND SEQUENCE');
  lines.push('─'.repeat(60));
  data.rewindSequence.forEach((e, i) => {
    lines.push(`  ${String(i + 1).padStart(2, '0')} | ${e.timestamp} | ${e.action} | ${e.entity}`);
    lines.push(`      ${e.description}`);
  });
  lines.push('');

  lines.push(sep);
  lines.push('  END OF REPORT');
  lines.push(sep);

  return lines.join('\n');
}
