'use client';

import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Slider } from '@/components/ui/slider';
import {
  Play,
  Pause,
  SkipBack,
  SkipForward,
  FastForward,
  Clock,
  FileText,
  Trash2,
  Globe,
  Wifi,
  Download,
  Terminal,
  Search,
  PlayCircle,
  EyeOff,
  Upload,
  LogIn,
  Settings,
  Cpu,
  HardDrive,
  Usb,
  Power,
  Circle,
  FilePlus,
  FileEdit,
  Zap,
  Shield,
  Activity,
  AlertTriangle,
} from 'lucide-react';
import { format } from 'date-fns';
import { motion, AnimatePresence } from 'framer-motion';
import type { RewindEvent, ActionCategory } from '@/lib/forensic/types';

interface RewindPlayerProps {
  events: RewindEvent[];
}

function getActionIcon(action: ActionCategory) {
  switch (action) {
    case 'file_opened': return <FileText className="h-4 w-4" />;
    case 'file_created': return <FilePlus className="h-4 w-4" />;
    case 'file_modified': return <FileEdit className="h-4 w-4" />;
    case 'file_deleted': return <Trash2 className="h-4 w-4" />;
    case 'file_downloaded': return <Download className="h-4 w-4" />;
    case 'file_executed': return <PlayCircle className="h-4 w-4" />;
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

const SPEEDS = [0.5, 1, 2, 4];
const INTERVALS: Record<number, number> = { 0.5: 4000, 1: 2000, 2: 1000, 4: 500 };

// Safe date formatter — never crashes on invalid timestamps
function safeFormat(timestamp: string | undefined, fmt: string): string {
  if (!timestamp) return '--:--';
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return '--:--';
  return format(d, fmt);
}

export default function RewindPlayer({ events }: RewindPlayerProps) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [direction, setDirection] = useState<1 | -1>(1);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const eventListRef = useRef<HTMLDivElement>(null);
  const activeCardRef = useRef<HTMLDivElement>(null);

  const sortedEvents = useMemo(
    () => [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    [events]
  );

  const currentEvent = sortedEvents[currentIndex];
  const totalEvents = sortedEvents.length;
  const progress = totalEvents > 1 ? (currentIndex / (totalEvents - 1)) * 100 : 0;

  const actionBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    sortedEvents.forEach((e) => {
      const raw = e.action || 'unknown';
      const label = raw.replace(/_/g, ' ');
      counts[label] = (counts[label] || 0) + 1;
    });
    return Object.entries(counts).sort(([, a], [, b]) => b - a).slice(0, 6);
  }, [sortedEvents]);

  const riskEvents = useMemo(
    () =>
      sortedEvents.filter(
        (e) =>
          e.action === 'data_exfiltration' ||
          e.action === 'file_deleted' ||
          e.action === 'file_executed' ||
          e.action === 'registry_change' ||
          e.action === 'process_created'
      ),
    [sortedEvents]
  );

  const advance = useCallback(
    (dir: 1 | -1) => {
      setCurrentIndex((prev) => {
        const next = prev + dir;
        if (next < 0 || next >= totalEvents) {
          // Stop playing at boundaries
          setIsPlaying(false);
          return prev;
        }
        return next;
      });
    },
    [totalEvents]
  );

  useEffect(() => {
    if (isPlaying) {
      timerRef.current = setInterval(() => {
        advance(direction);
      }, INTERVALS[speed]);
    } else {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, speed, direction, advance]);

  useEffect(() => {
    if (activeCardRef.current && eventListRef.current) {
      activeCardRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [currentIndex]);

  const togglePlay = () => {
    if (currentIndex >= totalEvents - 1 && direction === 1) {
      setCurrentIndex(0);
    }
    if (currentIndex <= 0 && direction === -1) {
      setCurrentIndex(totalEvents - 1);
    }
    setIsPlaying(!isPlaying);
  };

  const goToIndex = (idx: number) => {
    setCurrentIndex(Math.max(0, Math.min(idx, totalEvents - 1)));
  };

  return (
    <div className="h-[calc(100vh-200px)] flex flex-col gap-3">
      {/* Header */}
      <div className="forensic-header px-4 py-3 rounded-lg flex items-center justify-between relative overflow-hidden">
        {/* Scan line animation */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-cyan/50 to-transparent animate-scan" />
        </div>
        <div className="flex items-center gap-3 relative z-10">
          <Zap className="h-5 w-5 text-cyan animate-pulse-glow" />
          <h2 className="text-sm font-bold tracking-widest text-foreground uppercase">
            Forensic Rewind Mode
          </h2>
          <Badge variant="outline" className="border-cyan/50 text-cyan bg-cyan/10 font-mono text-xs">
            {isPlaying ? '● PLAYING' : '■ PAUSED'}
          </Badge>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted-foreground font-mono relative z-10">
          <span>
            Event {currentIndex + 1}/{totalEvents}
          </span>
          <span>
            {currentEvent?.timestamp && !isNaN(new Date(currentEvent.timestamp).getTime())
              ? format(new Date(currentEvent.timestamp), 'HH:mm:ss')
              : '--:--:--'}
          </span>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex gap-3 min-h-0 overflow-hidden">
        {/* Left: Event Timeline */}
        <div className="flex-1 flex flex-col min-w-0">
          <Card className="forensic-card flex-1 flex flex-col overflow-hidden">
            <CardContent className="p-0 flex-1 flex flex-col min-h-0">
              <div ref={eventListRef} className="flex-1 overflow-y-auto scrollbar-forensic p-4 space-y-2">
                {sortedEvents.map((event, idx) => {
                  const isActive = idx === currentIndex;
                  const isPast = idx < currentIndex;
                  const isFuture = idx > currentIndex;
                  const color = getActionColor(event.action as ActionCategory);

                  return (
                    <motion.div
                      key={event.id}
                      ref={isActive ? activeCardRef : undefined}
                      layout
                      initial={{ opacity: 0.3 }}
                      animate={{
                        opacity: isPast ? 0.5 : isFuture ? 0.35 : 1,
                        scale: isActive ? 1.02 : 1,
                      }}
                      transition={{ duration: 0.3 }}
                      className={`
                        relative p-3 rounded-lg border cursor-pointer transition-all
                        ${isActive ? 'rewind-active border-cyan/60 bg-cyan/5' : 'border-border/30 bg-card/50 hover:border-border/60'}
                      `}
                      onClick={() => {
                        setIsPlaying(false);
                        goToIndex(idx);
                      }}
                    >
                      {/* Left accent bar */}
                      <div
                        className="absolute left-0 top-0 bottom-0 w-1 rounded-l-lg"
                        style={{ backgroundColor: color }}
                      />

                      <div className="flex items-start gap-2 pl-2">
                        <div className="mt-0.5 shrink-0" style={{ color }}>
                          {getActionIcon(event.action as ActionCategory)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-[11px] font-mono text-muted-foreground">
                              {event.timestamp && !isNaN(new Date(event.timestamp).getTime()) ? format(new Date(event.timestamp), 'HH:mm:ss') : '--:--:--'}
                            </span>
                            {isActive && (
                              <motion.div
                                className="w-1.5 h-1.5 rounded-full bg-cyan"
                                animate={{ scale: [1, 1.5, 1] }}
                                transition={{ duration: 1.5, repeat: Infinity }}
                              />
                            )}
                          </div>
                          <p className={`text-xs ${isActive ? 'text-foreground font-semibold' : 'text-foreground/80'}`}>
                            {event.entity}
                          </p>
                          <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">
                            {event.description}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            {event.user && (
                              <span className="text-[10px] font-mono text-cyan/70">User: {event.user}</span>
                            )}
                            {event.process && (
                              <span className="text-[10px] font-mono text-amber-500/70">Process: {event.process}</span>
                            )}
                          </div>
                        </div>
                        {isActive && (
                          <motion.div
                            className="shrink-0 w-2 h-2 rounded-full bg-cyan"
                            animate={{ opacity: [1, 0.3, 1] }}
                            transition={{ duration: 1, repeat: Infinity }}
                          />
                        )}
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right: Current Event Details */}
        <div className="w-full lg:w-[380px] shrink-0 flex flex-col gap-3">
          {/* Active Event */}
          <AnimatePresence mode="wait">
            <motion.div
              key={currentEvent?.id}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.25 }}
            >
              <Card className="forensic-card forensic-glow">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <div
                      className="p-2 rounded-lg"
                      style={{ backgroundColor: `${getActionColor(currentEvent?.action as ActionCategory)}20` }}
                    >
                      <div style={{ color: getActionColor(currentEvent?.action as ActionCategory) }}>
                        {getActionIcon(currentEvent?.action as ActionCategory)}
                      </div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-muted-foreground">Current Event</p>
                      <p className="text-sm font-semibold text-foreground truncate">
                        {currentEvent?.entity}
                      </p>
                    </div>
                    <Badge variant="outline" className="font-mono text-xs text-cyan border-cyan/50 bg-cyan/10">
                      {currentEvent?.timestamp && !isNaN(new Date(currentEvent.timestamp).getTime())
              ? format(new Date(currentEvent.timestamp), 'HH:mm:ss')
              : '--:--:--'}
                    </Badge>
                  </div>

                  <Separator className="mb-3 bg-border/50" />

                  <p className="text-sm text-foreground/90 leading-relaxed mb-3">
                    {currentEvent?.description}
                  </p>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 rounded-md bg-muted/50">
                      <span className="text-muted-foreground block text-[10px]">Source</span>
                      <span className="text-foreground font-mono">{currentEvent?.source}</span>
                    </div>
                    <div className="p-2 rounded-md bg-muted/50">
                      <span className="text-muted-foreground block text-[10px]">Action</span>
                      <span className="text-foreground capitalize">{currentEvent?.action?.replace(/_/g, ' ')}</span>
                    </div>
                    {currentEvent?.user && (
                      <div className="p-2 rounded-md bg-muted/50">
                        <span className="text-muted-foreground block text-[10px]">User</span>
                        <span className="text-cyan font-mono">{currentEvent.user}</span>
                      </div>
                    )}
                    {currentEvent?.process && (
                      <div className="p-2 rounded-md bg-muted/50">
                        <span className="text-muted-foreground block text-[10px]">Process</span>
                        <span className="text-amber-400 font-mono">{currentEvent.process}</span>
                      </div>
                    )}
                  </div>

                  {/* Confidence */}
                  <div className="mt-3 flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Confidence:</span>
                    <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                      <motion.div
                        className="h-full rounded-full"
                        style={{
                          backgroundColor: (currentEvent?.confidence ?? 0) > 0.9 ? '#22c55e' : (currentEvent?.confidence ?? 0) > 0.7 ? '#f59e0b' : '#ef4444',
                        }}
                        initial={{ width: 0 }}
                        animate={{ width: `${(currentEvent?.confidence ?? 0) * 100}%` }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>
                    <span className="text-xs font-mono text-foreground">
                      {((currentEvent?.confidence ?? 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </AnimatePresence>

          {/* Summary Stats */}
          <Card className="forensic-card">
            <CardContent className="p-4">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
                Session Summary
              </h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-foreground">
                    <Activity className="h-3.5 w-3.5 text-cyan" />
                    Total Events
                  </div>
                  <span className="font-mono text-sm text-foreground">{totalEvents}</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-foreground">
                    <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                    Risk Events
                  </div>
                  <span className="font-mono text-sm text-red-400">{riskEvents.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-foreground">
                    <Shield className="h-3.5 w-3.5 text-amber-500" />
                    Time Span
                  </div>
                  <span className="font-mono text-xs text-foreground">
                    {sortedEvents.length > 1
                      ? `${safeFormat(sortedEvents[0]?.timestamp, 'HH:mm')} → ${safeFormat(sortedEvents[sortedEvents.length - 1]?.timestamp, 'HH:mm')}`
                      : 'N/A'}
                  </span>
                </div>

                <Separator className="bg-border/50" />

                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
                    Action Breakdown
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {actionBreakdown.map(([action, count]) => (
                      <Badge
                        key={action}
                        variant="secondary"
                        className="text-[10px] font-mono"
                      >
                        {action}: {count}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Playback Controls */}
      <Card className="forensic-card">
        <CardContent className="p-4">
          {/* Progress Slider */}
          <div className="mb-3">
            <Slider
              value={[progress]}
              max={100}
              step={totalEvents > 1 ? 100 / (totalEvents - 1) : 100}
              onValueChange={(val) => {
                const idx = Math.round((val[0] / 100) * (totalEvents - 1));
                setIsPlaying(false);
                goToIndex(idx);
              }}
              className="cursor-pointer"
            />
            <div className="flex justify-between mt-1">
              <span className="text-[10px] font-mono text-muted-foreground">
                {sortedEvents[0]?.timestamp && !isNaN(new Date(sortedEvents[0].timestamp).getTime()) ? format(new Date(sortedEvents[0].timestamp), 'HH:mm:ss') : '--:--:--'}
              </span>
              <span className="text-[10px] font-mono text-muted-foreground">
                {sortedEvents[totalEvents - 1]?.timestamp && !isNaN(new Date(sortedEvents[totalEvents - 1].timestamp).getTime()) ? format(new Date(sortedEvents[totalEvents - 1].timestamp), 'HH:mm:ss') : '--:--:--'}
              </span>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center justify-center gap-3">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => {
                setDirection(-1);
                goToIndex(0);
              }}
              title="Go to start"
            >
              <SkipBack className="h-4 w-4" />
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => {
                setIsPlaying(false);
                advance(-1);
              }}
              title="Step back"
            >
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M11 19l-7-7 7-7" />
                <path d="M18 19l-7-7 7-7" />
              </svg>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className={`h-10 w-10 rounded-full ${direction === -1 ? 'text-cyan bg-cyan/10' : ''}`}
              onClick={() => {
                setDirection(-1);
                if (isPlaying && direction === -1) setIsPlaying(false);
                else if (!isPlaying) setIsPlaying(true);
                else {
                  setIsPlaying(false);
                  setTimeout(() => setIsPlaying(true), 50);
                }
              }}
              title="Rewind"
            >
              <FastForward className="h-5 w-5 rotate-180" />
            </Button>

            <Button
              variant="default"
              size="icon"
              className="h-12 w-12 rounded-full bg-cyan hover:bg-cyan/80 text-background"
              onClick={togglePlay}
              title={isPlaying ? 'Pause' : 'Play'}
            >
              {isPlaying ? (
                <Pause className="h-5 w-5" />
              ) : (
                <Play className="h-5 w-5 ml-0.5" />
              )}
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className={`h-10 w-10 rounded-full ${direction === 1 ? 'text-cyan bg-cyan/10' : ''}`}
              onClick={() => {
                setDirection(1);
                if (isPlaying && direction === 1) setIsPlaying(false);
                else if (!isPlaying) setIsPlaying(true);
                else {
                  setIsPlaying(false);
                  setTimeout(() => setIsPlaying(true), 50);
                }
              }}
              title="Forward"
            >
              <FastForward className="h-5 w-5" />
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => {
                setIsPlaying(false);
                advance(1);
              }}
              title="Step forward"
            >
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M13 5l7 7-7 7" />
                <path d="M6 5l7 7-7 7" />
              </svg>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => {
                setDirection(1);
                goToIndex(totalEvents - 1);
              }}
              title="Go to end"
            >
              <SkipForward className="h-4 w-4" />
            </Button>
          </div>

          {/* Speed control */}
          <div className="flex items-center justify-center gap-2 mt-3">
            <Clock className="h-3 w-3 text-muted-foreground" />
            {SPEEDS.map((s) => (
              <Button
                key={s}
                variant={speed === s ? 'default' : 'ghost'}
                size="sm"
                className={`h-6 px-2 text-[10px] font-mono ${speed === s ? 'bg-cyan text-background' : 'text-muted-foreground'}`}
                onClick={() => setSpeed(s)}
              >
                {s}x
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
