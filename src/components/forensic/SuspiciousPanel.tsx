'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  AlertTriangle,
  Shield,
  AlertCircle,
  CheckCircle,
  ChevronDown,
  Search,
  SortAsc,
  Filter,
} from 'lucide-react';
import { format } from 'date-fns';
import type { SuspiciousFinding, SeverityLevel } from '@/lib/forensic/types';

function safeFormat(timestamp: string | undefined | null, fmt: string): string {
  if (!timestamp) return '--:--';
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return '--:--';
  return format(d, fmt);
}

interface SuspiciousPanelProps {
  findings: SuspiciousFinding[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  highly_suspicious: '#f97316',
  suspicious: '#f59e0b',
  benign: '#22c55e',
};

const SEVERITY_ICONS: Record<string, typeof AlertTriangle> = {
  critical: AlertTriangle,
  highly_suspicious: Shield,
  suspicious: AlertCircle,
  benign: CheckCircle,
};

type SortKey = 'severity' | 'timestamp' | 'confidence';

export default function SuspiciousPanel({ findings }: SuspiciousPanelProps) {
  const [activeTab, setActiveTab] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [sortBy, setSortBy] = useState<SortKey>('severity');

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: findings.length, critical: 0, highly_suspicious: 0, suspicious: 0, benign: 0 };
    findings.forEach((f) => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return c;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    let result = [...findings];

    if (activeTab !== 'all') {
      result = result.filter((f) => f.severity === activeTab);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q) ||
          f.evidence.toLowerCase().includes(q)
      );
    }

    const sevOrder: Record<SeverityLevel, number> = { critical: 0, highly_suspicious: 1, suspicious: 2, benign: 3 };

    result.sort((a, b) => {
      switch (sortBy) {
        case 'severity':
          return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
        case 'timestamp':
          return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
        case 'confidence':
          return b.confidence - a.confidence;
        default:
          return 0;
      }
    });

    return result;
  }, [findings, activeTab, searchQuery, sortBy]);

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const cycleSort = () => {
    const order: SortKey[] = ['severity', 'timestamp', 'confidence'];
    const idx = order.indexOf(sortBy);
    setSortBy(order[(idx + 1) % order.length]);
  };

  const sortLabels: Record<SortKey, string> = {
    severity: 'Severity',
    timestamp: 'Time',
    confidence: 'Confidence',
  };

  return (
    <div className="space-y-4">
      {/* Filters & Search */}
      <Card className="forensic-card">
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-muted/50 border-border/50 font-mono text-sm"
              />
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={cycleSort}
              className="shrink-0 text-xs"
            >
              <SortAsc className="h-3.5 w-3.5 mr-1" />
              Sort: {sortLabels[sortBy]}
            </Button>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-3">
            <TabsList className="bg-muted/50">
              <TabsTrigger value="all" className="text-xs data-[state=active]:bg-cyan data-[state=active]:text-background">
                All ({counts.all})
              </TabsTrigger>
              <TabsTrigger value="critical" className="text-xs data-[state=active]:bg-red-500 data-[state=active]:text-white">
                Critical ({counts.critical})
              </TabsTrigger>
              <TabsTrigger value="highly_suspicious" className="text-xs data-[state=active]:bg-orange-500 data-[state=active]:text-white">
                High ({counts.highly_suspicious})
              </TabsTrigger>
              <TabsTrigger value="suspicious" className="text-xs data-[state=active]:bg-amber-500 data-[state=active]:text-background">
                Suspicious ({counts.suspicious})
              </TabsTrigger>
              <TabsTrigger value="benign" className="text-xs data-[state=active]:bg-emerald-500 data-[state=active]:text-white">
                Benign ({counts.benign})
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </CardContent>
      </Card>

      {/* Findings List */}
      <ScrollArea className="h-[calc(100vh-320px)] scrollbar-forensic">
        <div className="space-y-3 pr-4">
          {filteredFindings.map((finding) => {
            const isExpanded = expandedIds.has(finding.id);
            const SevIcon = SEVERITY_ICONS[finding.severity] || AlertCircle;
            const color = SEVERITY_COLORS[finding.severity];
            const isCritical = finding.severity === 'critical';

            return (
              <Collapsible
                key={finding.id}
                open={isExpanded}
                onOpenChange={() => toggleExpanded(finding.id)}
              >
                <Card
                  className={`forensic-card overflow-hidden cursor-pointer transition-all hover:border-opacity-60 ${
                    isCritical ? 'forensic-glow-red' : ''
                  }`}
                  style={{ borderColor: `${color}30` }}
                >
                  <CollapsibleTrigger className="w-full text-left">
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div
                          className="p-2 rounded-lg shrink-0 mt-0.5"
                          style={{ backgroundColor: `${color}15` }}
                        >
                          <SevIcon className="h-4 w-4" style={{ color }} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <Badge
                              variant="outline"
                              className="text-[10px] px-1.5 py-0"
                              style={{
                                borderColor: color,
                                color,
                                backgroundColor: `${color}10`,
                              }}
                            >
                              {finding.severity.replace(/_/g, ' ')}
                            </Badge>
                            <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                              {finding.category}
                            </Badge>
                            <span className="text-[10px] font-mono text-muted-foreground ml-auto">
                              {safeFormat(finding.timestamp, 'MMM dd, HH:mm')}
                            </span>
                          </div>
                          <h4 className="text-sm font-semibold text-foreground mb-1">
                            {finding.title}
                          </h4>
                          <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                            {finding.description}
                          </p>

                          {/* Confidence bar */}
                          <div className="flex items-center gap-2 mt-2">
                            <span className="text-[10px] text-muted-foreground">Confidence:</span>
                            <div className="flex-1 max-w-[120px] h-1.5 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${finding.confidence * 100}%`,
                                  backgroundColor: color,
                                }}
                              />
                            </div>
                            <span className="text-[10px] font-mono text-foreground">
                              {(finding.confidence * 100).toFixed(0)}%
                            </span>
                          </div>
                        </div>
                        <ChevronDown
                          className={`h-4 w-4 text-muted-foreground shrink-0 transition-transform ${
                            isExpanded ? 'rotate-180' : ''
                          }`}
                        />
                      </div>
                    </CardContent>
                  </CollapsibleTrigger>

                  <CollapsibleContent>
                    <div className="px-4 pb-4 pt-0">
                      <div className="border-t border-border/50 pt-3 space-y-3">
                        {/* Evidence Source */}
                        <div className="flex items-start gap-2 text-xs">
                          <span className="text-muted-foreground shrink-0">Evidence:</span>
                          <span className="font-mono text-cyan">{finding.evidence}</span>
                        </div>

                        {/* Related Artifacts */}
                        {finding.relatedArtifacts.length > 0 && (
                          <div>
                            <span className="text-xs text-muted-foreground">Related Artifacts:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {finding.relatedArtifacts.map((artifact) => (
                                <Badge key={artifact} variant="secondary" className="text-[10px] font-mono">
                                  {artifact}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Recommendation */}
                        <div className="p-3 rounded-lg bg-muted/50 border border-border/30">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                            Recommendation
                          </p>
                          <p className="text-xs text-foreground/90 leading-relaxed">
                            {finding.recommendation}
                          </p>
                        </div>
                      </div>
                    </div>
                  </CollapsibleContent>
                </Card>
              </Collapsible>
            );
          })}

          {filteredFindings.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              <Filter className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No findings match the current filters</p>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
