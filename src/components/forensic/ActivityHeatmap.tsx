'use client';

import { useMemo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Grid3x3 } from 'lucide-react';
import type { ActivityHeatmap } from '@/lib/forensic/types';

interface ActivityHeatmapProps {
  data: ActivityHeatmap[];
}

export default function ActivityHeatmap({ data }: ActivityHeatmapProps) {
  const [hoveredCell, setHoveredCell] = useState<{ day: number; hour: number; count: number } | null>(null);

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

  const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const daysShort = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  const totalActivity = useMemo(() => data.reduce((sum, d) => sum + d.count, 0), [data]);
  const peakDay = useMemo(() => {
    const dayTotals = new Array(7).fill(0);
    data.forEach((d) => { dayTotals[d.day - 1] += d.count; });
    const maxIdx = dayTotals.indexOf(Math.max(...dayTotals));
    return { day: days[maxIdx], count: dayTotals[maxIdx] };
  }, [data]);

  const peakHour = useMemo(() => {
    const hourTotals = new Array(24).fill(0);
    data.forEach((d) => { hourTotals[d.hour] += d.count; });
    const maxIdx = hourTotals.indexOf(Math.max(...hourTotals));
    return { hour: maxIdx, count: hourTotals[maxIdx] };
  }, [data]);

  return (
    <div className="space-y-4">
      <Card className="forensic-card">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Grid3x3 className="h-4 w-4 text-cyan" />
            Activity Heatmap
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4 pt-0">
          {/* Stats */}
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="p-2 rounded-lg bg-muted/30 text-center">
              <p className="text-lg font-bold font-mono text-foreground">{totalActivity}</p>
              <p className="text-[10px] text-muted-foreground">Total Events</p>
            </div>
            <div className="p-2 rounded-lg bg-cyan/10 text-center">
              <p className="text-sm font-bold font-mono text-cyan">{peakDay.day}</p>
              <p className="text-[10px] text-muted-foreground">Peak Day ({peakDay.count})</p>
            </div>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-center">
              <p className="text-lg font-bold font-mono text-emerald-400">{peakHour.hour}:00</p>
              <p className="text-[10px] text-muted-foreground">Peak Hour ({peakHour.count})</p>
            </div>
          </div>

          {/* Heatmap Grid */}
          <div className="overflow-x-auto scrollbar-forensic">
            <div className="font-mono text-xs inline-block min-w-full">
              {/* Hour labels */}
              <div className="flex gap-1 mb-1 ml-[80px]">
                {Array.from({ length: 24 }, (_, i) => (
                  <div key={i} className="w-[32px] text-center text-[10px] text-muted-foreground">
                    {i % 3 === 0 ? `${String(i).padStart(2, '0')}` : ''}
                  </div>
                ))}
              </div>

              {/* Rows */}
              {daysShort.map((day, dayIdx) => (
                <div key={day} className="flex gap-1 mb-1 items-center">
                  <div className="w-[76px] text-right text-[11px] text-muted-foreground pr-2 shrink-0">
                    {day}
                  </div>
                  {Array.from({ length: 24 }, (_, hour) => {
                    const cell = data.find((d) => d.day === dayIdx + 1 && d.hour === hour);
                    const count = cell?.count ?? 0;
                    const isHovered = hoveredCell?.day === dayIdx + 1 && hoveredCell?.hour === hour;

                    return (
                      <Tooltip key={hour}>
                        <TooltipTrigger asChild>
                          <div
                            className={`w-[32px] h-[24px] rounded-[3px] ${getColor(count)} cursor-default transition-all hover:ring-1 hover:ring-cyan-400/60 hover:scale-110 ${
                              isHovered ? 'ring-1 ring-cyan-400 scale-110' : ''
                            }`}
                            onMouseEnter={() =>
                              setHoveredCell({ day: dayIdx + 1, hour, count })
                            }
                            onMouseLeave={() => setHoveredCell(null)}
                          />
                        </TooltipTrigger>
                        <TooltipContent
                          side="top"
                          className="bg-[#0f0f1a] border border-border text-xs font-mono"
                        >
                          <p>{days[dayIdx]} {String(hour).padStart(2, '0')}:00</p>
                          <p className="text-cyan">{count} events</p>
                        </TooltipContent>
                      </Tooltip>
                    );
                  })}
                </div>
              ))}

              {/* Legend */}
              <div className="flex items-center gap-2 mt-3 ml-[80px]">
                <span className="text-[10px] text-muted-foreground">Less</span>
                <div className="w-[32px] h-[24px] rounded-[3px] bg-[#0a0a14]" />
                <div className="w-[32px] h-[24px] rounded-[3px] bg-emerald-900/60" />
                <div className="w-[32px] h-[24px] rounded-[3px] bg-emerald-700/70" />
                <div className="w-[32px] h-[24px] rounded-[3px] bg-emerald-500/80" />
                <div className="w-[32px] h-[24px] rounded-[3px] bg-emerald-400/90" />
                <div className="w-[32px] h-[24px] rounded-[3px] bg-emerald-300" />
                <span className="text-[10px] text-muted-foreground">More</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
