'use client';

import { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Shield,
  AlertTriangle,
  Activity,
  FileSearch,
  Clock,
  TrendingUp,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { format } from 'date-fns';
import type { AnalysisResult, ActivityHeatmap, TimelineEvent } from '@/lib/forensic/types';

function safeFormat(timestamp: string | undefined | null, fmt: string): string {
  if (!timestamp) return '--:--';
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return '--:--';
  return format(d, fmt);
}

interface DashboardProps {
  data: AnalysisResult;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  highly_suspicious: '#f97316',
  suspicious: '#f59e0b',
  benign: '#22c55e',
};

function AnimatedCounter({ target, suffix = '' }: { target: number; suffix?: string }) {
  const formatted = useMemo(() => {
    if (target >= 1000) return `${(target / 1000).toFixed(1)}K`;
    return target.toString();
  }, [target]);

  return (
    <span className="text-3xl font-bold font-mono text-foreground">
      {formatted}
      {suffix}
    </span>
  );
}

function HeatmapGrid({ data }: { data: ActivityHeatmap[] }) {
  const maxCount = useMemo(() => {
    if (!data.length) return 1;
    return Math.max(...data.map((d) => d.count), 1);
  }, [data]);

  const getColor = (count: number) => {
    if (count === 0) return 'bg-[#0a0a14]';
    const intensity = count / maxCount;
    if (intensity < 0.15) return 'bg-emerald-900/60';
    if (intensity < 0.3) return 'bg-emerald-700/70';
    if (intensity < 0.5) return 'bg-emerald-500/80';
    if (intensity < 0.75) return 'bg-emerald-400/90';
    return 'bg-emerald-300';
  };

  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  return (
    <div className="font-mono text-xs">
      <div className="flex gap-1 mb-1 pl-10">
        {Array.from({ length: 24 }, (_, i) => (
          <div key={i} className="w-[26px] text-center text-muted-foreground">
            {i % 4 === 0 ? i : ''}
          </div>
        ))}
      </div>
      {days.map((day, dayIdx) => (
        <div key={day} className="flex gap-1 mb-1 items-center">
          <div className="w-9 text-right text-muted-foreground pr-1">{day}</div>
          {Array.from({ length: 24 }, (_, hour) => {
            const cell = data.find((d) => d.day === dayIdx + 1 && d.hour === hour);
            const count = cell?.count ?? 0;
            return (
              <div
                key={hour}
                className={`w-[26px] h-[18px] rounded-[2px] ${getColor(count)} hover:ring-1 hover:ring-cyan-400/50 cursor-default transition-all`}
                title={`${day} ${hour}:00 - ${count} events`}
              />
            );
          })}
        </div>
      ))}
      <div className="flex items-center gap-2 mt-2 pl-10">
        <span className="text-muted-foreground">Less</span>
        <div className="w-[26px] h-[18px] rounded-[2px] bg-[#0a0a14]" />
        <div className="w-[26px] h-[18px] rounded-[2px] bg-emerald-900/60" />
        <div className="w-[26px] h-[18px] rounded-[2px] bg-emerald-700/70" />
        <div className="w-[26px] h-[18px] rounded-[2px] bg-emerald-500/80" />
        <div className="w-[26px] h-[18px] rounded-[2px] bg-emerald-400/90" />
        <div className="w-[26px] h-[18px] rounded-[2px] bg-emerald-300" />
        <span className="text-muted-foreground">More</span>
      </div>
    </div>
  );
}

export default function Dashboard({ data }: DashboardProps) {
  const { stats, timeline, suspiciousFindings, heatmap } = data;

  const severityData = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, highly_suspicious: 0, suspicious: 0, benign: 0 };
    timeline.forEach((e) => {
      if (counts[e.severity] !== undefined) counts[e.severity]++;
    });
    return Object.entries(counts)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => ({ name: k.replace(/_/g, ' '), value: v, color: SEVERITY_COLORS[k] }));
  }, [timeline]);

  const categoryData = useMemo(() => {
    return stats.topCategories.map((c) => ({
      ...c,
      fill: '#06b6d4',
    }));
  }, [stats]);

  const recentEvents = useMemo(() => {
    return [...timeline]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 8);
  }, [timeline]);

  const topFindings = useMemo(() => {
    return [...suspiciousFindings]
      .sort((a, b) => {
        const sevOrder = { critical: 0, highly_suspicious: 1, suspicious: 2, benign: 3 };
        return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
      })
      .slice(0, 5);
  }, [suspiciousFindings]);

  return (
    <div className="space-y-6">
      {/* Case Header */}
      <div className="forensic-card p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Shield className="h-6 w-6 text-cyan" />
              <h2 className="text-xl font-bold text-foreground">{data.caseInfo.name}</h2>
              <Badge
                variant="outline"
                className="border-cyan/50 text-cyan bg-cyan/10"
              >
                {data.caseInfo.status.toUpperCase()}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground max-w-3xl">{data.caseInfo.description}</p>
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground font-mono">
              <span>Analyst: {data.caseInfo.analyst}</span>
              <span>Created: {safeFormat(data.caseInfo.createdAt, 'MMM dd, yyyy')}</span>
              <span>Time Range: {safeFormat(stats.timeRange.start, 'HH:mm')} — {safeFormat(stats.timeRange.end, 'HH:mm')}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="font-mono text-xs">
              {data.evidence.length} Evidence Items
            </Badge>
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="forensic-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Events</p>
                <AnimatedCounter target={stats.totalEvents} />
              </div>
              <div className="h-10 w-10 rounded-lg bg-cyan/10 flex items-center justify-center">
                <Activity className="h-5 w-5 text-cyan" />
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1 text-xs text-emerald-400">
              <TrendingUp className="h-3 w-3" />
              <span>Full timeline reconstructed</span>
            </div>
          </CardContent>
        </Card>

        <Card className="forensic-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Suspicious</p>
                <AnimatedCounter target={stats.suspiciousCount} />
              </div>
              <div className="h-10 w-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
                <AlertTriangle className="h-5 w-5 text-amber-500" />
              </div>
            </div>
            <div className="mt-2 text-xs text-amber-400">
              Requires further investigation
            </div>
          </CardContent>
        </Card>

        <Card className="forensic-card forensic-glow-red">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Critical</p>
                <AnimatedCounter target={stats.criticalCount} />
              </div>
              <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <Shield className="h-5 w-5 text-red-500" />
              </div>
            </div>
            <div className="mt-2 text-xs text-red-400 animate-pulse-glow">
              Immediate action required
            </div>
          </CardContent>
        </Card>

        <Card className="forensic-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Evidence</p>
                <AnimatedCounter target={data.evidence.length} />
              </div>
              <div className="h-10 w-10 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                <FileSearch className="h-5 w-5 text-emerald-500" />
              </div>
            </div>
            <div className="mt-2 text-xs text-emerald-400">
              All items analyzed
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Heatmap & Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Activity Heatmap */}
        <Card className="forensic-card lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan" />
              Activity Heatmap
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0 overflow-x-auto">
            <HeatmapGrid data={heatmap} />
          </CardContent>
        </Card>

        {/* Severity Distribution */}
        <Card className="forensic-card">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan" />
              Severity Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f0f1a',
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                    fontSize: '12px',
                  }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap gap-2 mt-2">
              {severityData.map((item) => (
                <div key={item.name} className="flex items-center gap-1 text-xs text-muted-foreground">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="capitalize">{item.name}</span>
                  <span className="text-foreground font-mono">({item.value})</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Category Chart & Top Findings & Recent Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Category Distribution */}
        <Card className="forensic-card">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-cyan" />
              Category Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={categoryData} layout="vertical">
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="category"
                  width={80}
                  tick={{ fill: '#64748b', fontSize: 11 }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f0f1a',
                    border: '1px solid #1e293b',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                    fontSize: '12px',
                  }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Top Suspicious Findings */}
        <Card className="forensic-card">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              Top Findings
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <ScrollArea className="h-[240px] scrollbar-forensic">
              <div className="space-y-2">
                {topFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="p-2 rounded-lg border border-border/50 hover:border-cyan/30 transition-colors cursor-default"
                  >
                    <div className="flex items-start gap-2">
                      <Badge
                        variant="outline"
                        className="text-[10px] px-1 py-0 shrink-0"
                        style={{
                          borderColor: SEVERITY_COLORS[finding.severity],
                          color: SEVERITY_COLORS[finding.severity],
                          backgroundColor: `${SEVERITY_COLORS[finding.severity]}15`,
                        }}
                      >
                        {finding.severity.replace(/_/g, ' ')}
                      </Badge>
                      <span className="text-xs text-foreground font-medium leading-tight">
                        {finding.title}
                      </span>
                    </div>
                    <div className="mt-1 text-[10px] text-muted-foreground font-mono">
                      Confidence: {(finding.confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Recent Timeline Events */}
        <Card className="forensic-card">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan" />
              Recent Events
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <ScrollArea className="h-[240px] scrollbar-forensic">
              <div className="space-y-2">
                {recentEvents.map((event: TimelineEvent) => (
                  <div
                    key={event.id}
                    className="p-2 rounded-lg border border-border/50 hover:border-cyan/30 transition-colors cursor-default"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono text-muted-foreground">
                        {safeFormat(event.timestamp, 'HH:mm:ss')}
                      </span>
                      <Badge
                        variant="outline"
                        className="text-[10px] px-1 py-0"
                        style={{
                          borderColor: SEVERITY_COLORS[event.severity],
                          color: SEVERITY_COLORS[event.severity],
                        }}
                      >
                        {event.severity.replace(/_/g, ' ')}
                      </Badge>
                    </div>
                    <p className="text-xs text-foreground leading-tight">{event.entity}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5 leading-tight">
                      {event.description}
                    </p>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="forensic-card p-6">
        <Skeleton className="h-6 w-64 mb-2" />
        <Skeleton className="h-4 w-full max-w-3xl mb-2" />
        <Skeleton className="h-3 w-48" />
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i} className="forensic-card">
            <CardContent className="p-4">
              <Skeleton className="h-3 w-24 mb-2" />
              <Skeleton className="h-8 w-16" />
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Skeleton className="h-64 lg:col-span-2 rounded-xl" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    </div>
  );
}
