'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  Clock,
  Filter,
  ChevronRight,
  AlertTriangle,
  Shield,
  FileText,
  Trash2,
  Globe,
  Wifi,
  Download,
  Terminal,
  Search,
  Play,
  EyeOff,
  Upload,
  LogIn,
  Settings,
  Cpu,
  HardDrive,
  Usb,
  Power,
  HelpCircle,
  Circle,
  FilePlus,
  FileEdit,
  X,
} from 'lucide-react';
import { format, formatDistanceToNow } from 'date-fns';
import type { TimelineEvent, ActionCategory, SeverityLevel } from '@/lib/forensic/types';

function safeFormat(timestamp: string | undefined | null, fmt: string): string {
  if (!timestamp) return '--:--';
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return '--:--';
  return format(d, fmt);
}

interface TimelineViewProps {
  events: TimelineEvent[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  highly_suspicious: '#f97316',
  suspicious: '#f59e0b',
  benign: '#22c55e',
};

function getActionIcon(action: ActionCategory) {
  switch (action) {
    case 'file_opened': return <FileText className="h-4 w-4" />;
    case 'file_created': return <FilePlus className="h-4 w-4" />;
    case 'file_modified': return <FileEdit className="h-4 w-4" />;
    case 'file_deleted': return <Trash2 className="h-4 w-4" />;
    case 'file_downloaded': return <Download className="h-4 w-4" />;
    case 'file_executed': return <Play className="h-4 w-4" />;
    case 'file_hidden': return <EyeOff className="h-4 w-4" />;
    case 'file_copied': return <Upload className="h-4 w-4" />;
    case 'program_run': return <Terminal className="h-4 w-4" />;
    case 'browser_opened': return <Globe className="h-4 w-4" />;
    case 'web_page_visited': return <Globe className="h-4 w-4" />;
    case 'search_query': return <Search className="h-4 w-4" />;
    case 'network_connection': return <Wifi className="h-4 w-4" />;
    case 'data_exfiltration': return <Upload className="h-4 w-4" />;
    case 'login_attempt': return <LogIn className="h-4 w-4" />;
    case 'registry_change': return <Settings className="h-4 w-4" />;
    case 'service_start': return <Settings className="h-4 w-4" />;
    case 'process_created': return <Cpu className="h-4 w-4" />;
    case 'driver_loaded': return <HardDrive className="h-4 w-4" />;
    case 'usb_connected': return <Usb className="h-4 w-4" />;
    case 'system_shutdown': return <Power className="h-4 w-4" />;
    default: return <Circle className="h-4 w-4" />;
  }
}

function getActionColor(action: ActionCategory): string {
  switch (action) {
    case 'file_opened': return '#6366f1';
    case 'file_created': return '#3b82f6';
    case 'file_modified': return '#8b5cf6';
    case 'file_deleted': return '#ef4444';
    case 'file_downloaded': return '#3b82f6';
    case 'file_executed': return '#dc2626';
    case 'file_hidden': return '#7c3aed';
    case 'file_copied': return '#6366f1';
    case 'program_run': return '#f97316';
    case 'browser_opened': return '#06b6d4';
    case 'web_page_visited': return '#06b6d4';
    case 'search_query': return '#f59e0b';
    case 'network_connection': return '#ec4899';
    case 'data_exfiltration': return '#dc2626';
    case 'login_attempt': return '#22c55e';
    case 'registry_change': return '#d97706';
    case 'service_start': return '#f97316';
    case 'process_created': return '#f97316';
    case 'driver_loaded': return '#8b5cf6';
    case 'usb_connected': return '#059669';
    case 'system_shutdown': return '#6b7280';
    default: return '#64748b';
  }
}

const SEVERITY_LEVELS: SeverityLevel[] = ['critical', 'highly_suspicious', 'suspicious', 'benign'];

export default function TimelineView({ events }: TimelineViewProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Set<SeverityLevel>>(
    new Set(SEVERITY_LEVELS)
  );
  const [showFilters, setShowFilters] = useState(false);

  const sortedEvents = useMemo(() => {
    return [...events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }, [events]);

  const filteredEvents = useMemo(() => {
    return sortedEvents.filter((e) => severityFilter.has(e.severity));
  }, [sortedEvents, severityFilter]);

  const uniqueActions = useMemo(() => {
    const actions = new Set(events.map((e) => e.action));
    return Array.from(actions).sort();
  }, [events]);

  const timeRange = useMemo(() => {
    if (!sortedEvents.length) return { start: 0, end: 0, span: 0 };
    const start = new Date(sortedEvents[0].timestamp).getTime();
    const end = new Date(sortedEvents[sortedEvents.length - 1].timestamp).getTime();
    return { start, end, span: end - start };
  }, [sortedEvents]);

  const toggleSeverity = (level: SeverityLevel) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(level)) next.delete(level);
      else next.add(level);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      {/* Timeline bar */}
      <Card className="forensic-card">
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan" />
              Timeline Overview
            </h3>
            <div className="flex items-center gap-2">
              <Badge variant="secondary" className="font-mono text-xs">
                {filteredEvents.length}/{events.length} events
              </Badge>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 text-xs"
                onClick={() => setShowFilters(!showFilters)}
              >
                <Filter className="h-3 w-3 mr-1" />
                Filter
              </Button>
            </div>
          </div>

          {/* Horizontal timeline */}
          <div className="relative h-8 mb-2">
            <div className="absolute top-3 left-0 right-0 h-[2px] bg-border" />
            <div className="absolute top-0 left-0 right-0 flex justify-between">
              {timeRange.span > 0 && (
                <>
                  <span className="text-[10px] font-mono text-muted-foreground">
                    {safeFormat(String(timeRange.start || ''), 'HH:mm')}
                  </span>
                  <span className="text-[10px] font-mono text-muted-foreground">
                    {safeFormat(String(timeRange.end || ''), 'HH:mm')}
                  </span>
                </>
              )}
            </div>
            {timeRange.span > 0 &&
              sortedEvents.map((event) => {
                const pos =
                  ((new Date(event.timestamp).getTime() - timeRange.start) / timeRange.span) * 100;
                const isFiltered = severityFilter.has(event.severity);
                return (
                  <div
                    key={event.id}
                    className="absolute top-1.5 -translate-x-1/2 group"
                    style={{ left: `${pos}%` }}
                  >
                    <div
                      className={`w-3 h-3 rounded-full border-2 border-background transition-opacity ${
                        isFiltered ? 'opacity-100' : 'opacity-20'
                      }`}
                      style={{ backgroundColor: SEVERITY_COLORS[event.severity] }}
                      title={`${safeFormat(event.timestamp, 'HH:mm:ss')} - ${event.entity}`}
                    />
                  </div>
                );
              })}
          </div>

          {/* Filters */}
          {showFilters && (
            <div className="mt-3 pt-3 border-t border-border/50">
              <p className="text-xs text-muted-foreground mb-2">Severity Filter:</p>
              <div className="flex flex-wrap gap-3">
                {SEVERITY_LEVELS.map((level) => (
                  <label key={level} className="flex items-center gap-1.5 cursor-pointer">
                    <Checkbox
                      checked={severityFilter.has(level)}
                      onCheckedChange={() => toggleSeverity(level)}
                      className="data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                    />
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: SEVERITY_COLORS[level] }}
                    />
                    <span className="text-xs capitalize text-foreground">
                      {level.replace(/_/g, ' ')}
                    </span>
                    <span className="text-[10px] text-muted-foreground font-mono">
                      ({sortedEvents.filter((e) => e.severity === level).length})
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Event List */}
      <ScrollArea className="h-[calc(100vh-340px)] scrollbar-forensic">
        <div className="relative pl-6 space-y-0">
          {/* Vertical line */}
          <div className="absolute left-[11px] top-0 bottom-0 w-[2px] bg-border/50" />

          {filteredEvents.map((event, idx) => {
            const isExpanded = expandedId === event.id;
            const prevEvent = idx > 0 ? filteredEvents[idx - 1] : null;
            const gap = prevEvent
              ? new Date(event.timestamp).getTime() - new Date(prevEvent.timestamp).getTime()
              : 0;
            const gapMinutes = Math.round(gap / 60000);

            return (
              <div key={event.id} className="relative">
                {/* Time gap indicator */}
                {gapMinutes > 15 && (
                  <div className="flex items-center gap-2 py-2">
                    <div className="absolute left-[11px] w-[2px] h-full bg-dashed border-l-2 border-dashed border-muted-foreground/30" />
                    <div className="relative z-10 flex items-center gap-1 text-[10px] font-mono text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span>{gapMinutes} min gap</span>
                    </div>
                  </div>
                )}

                <Collapsible open={isExpanded} onOpenChange={(open) => setExpandedId(open ? event.id : null)}>
                  <div className="flex gap-3 pb-3 relative">
                    {/* Dot */}
                    <div
                      className="absolute -left-6 top-1 w-5 h-5 rounded-full border-[3px] border-background z-10 flex items-center justify-center"
                      style={{ backgroundColor: getActionColor(event.action) }}
                    >
                      <div className="w-1.5 h-1.5 rounded-full bg-background/50" />
                    </div>

                    {/* Card */}
                    <div
                      className="flex-1 forensic-card p-3 cursor-pointer hover:border-cyan/40 transition-all"
                      onClick={() => setExpandedId(isExpanded ? null : event.id)}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-start gap-2 flex-1 min-w-0">
                          <div className="mt-0.5 shrink-0" style={{ color: getActionColor(event.action) }}>
                            {getActionIcon(event.action as ActionCategory)}
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-mono text-muted-foreground">
                                {safeFormat(event.timestamp, 'HH:mm:ss')}
                              </span>
                              <Badge
                                variant="outline"
                                className="text-[10px] px-1 py-0 shrink-0"
                                style={{
                                  borderColor: SEVERITY_COLORS[event.severity],
                                  color: SEVERITY_COLORS[event.severity],
                                }}
                              >
                                {event.severity.replace(/_/g, ' ')}
                              </Badge>
                            </div>
                            <p className="text-sm font-medium text-foreground mt-0.5 truncate">
                              {event.entity}
                            </p>
                            <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                              {event.description}
                            </p>
                          </div>
                        </div>
                        <ChevronRight
                          className={`h-4 w-4 text-muted-foreground shrink-0 transition-transform ${
                            isExpanded ? 'rotate-90' : ''
                          }`}
                        />
                      </div>

                      {/* Confidence bar */}
                      <div className="mt-2 flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground">Confidence:</span>
                        <div className="flex-1 max-w-[100px] h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${event.confidence * 100}%`,
                              backgroundColor:
                                event.confidence > 0.9
                                  ? '#22c55e'
                                  : event.confidence > 0.7
                                    ? '#f59e0b'
                                    : '#ef4444',
                            }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-foreground">
                          {(event.confidence * 100).toFixed(0)}%
                        </span>
                      </div>

                      {/* Expanded details */}
                      <CollapsibleContent>
                        <div className="mt-3 pt-3 border-t border-border/50 space-y-2">
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div>
                              <span className="text-muted-foreground">Source:</span>{' '}
                              <span className="text-foreground font-mono">{event.source}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Action:</span>{' '}
                              <span className="text-foreground capitalize">{event.action.replace(/_/g, ' ')}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Full Time:</span>{' '}
                              <span className="text-foreground font-mono">
                                {safeFormat(event.timestamp, "yyyy-MM-dd HH:mm:ss")} UTC
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Relative:</span>{' '}
                              <span className="text-foreground">
                                {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
                              </span>
                            </div>
                          </div>
                          {event.relatedEvents && event.relatedEvents.length > 0 && (
                            <div className="text-xs">
                              <span className="text-muted-foreground">Related Events: </span>
                              <span className="text-cyan font-mono">{event.relatedEvents.join(', ')}</span>
                            </div>
                          )}
                        </div>
                      </CollapsibleContent>
                    </div>
                  </div>
                </Collapsible>
              </div>
            );
          })}

          {filteredEvents.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              <HelpCircle className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No events match the current filter</p>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
