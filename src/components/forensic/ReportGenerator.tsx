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
import type { AnalysisResult, Evidence, SuspiciousFinding, TimelineEvent } from '@/lib/forensic/types';

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

            {/* Rewind Sequence */}
            <Card className="forensic-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider">
                  5. Forensic Rewind Sequence
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
                  6. Chain of Custody
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
