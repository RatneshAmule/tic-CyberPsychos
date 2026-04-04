// =============================================================================
// JURI-X — Timeline Reconstruction Engine
// =============================================================================

import type { TimelineEvent } from './types';
import { getSampleAnalysisResult } from './sample-data';

export function buildTimeline(_events: unknown[]): TimelineEvent[] {
  const result = getSampleAnalysisResult();
  return result.timeline;
}

export function detectAnomalies(events: TimelineEvent[]): {
  timeGaps: { start: string; end: string; duration: number }[];
  activitySpikes: { timestamp: string; count: number }[];
  deletedFiles: TimelineEvent[];
} {
  const sortedEvents = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  // Find time gaps > 2 hours
  const timeGaps: { start: string; end: string; duration: number }[] = [];
  for (let i = 1; i < sortedEvents.length; i++) {
    const diff =
      new Date(sortedEvents[i].timestamp).getTime() -
      new Date(sortedEvents[i - 1].timestamp).getTime();
    const hours = diff / (1000 * 60 * 60);
    if (hours > 2) {
      timeGaps.push({
        start: sortedEvents[i - 1].timestamp,
        end: sortedEvents[i].timestamp,
        duration: Math.round(hours),
      });
    }
  }

  // Find activity spikes (more than 5 events in 10 minutes)
  const spikeMap = new Map<string, number>();
  for (let i = 0; i < sortedEvents.length; i++) {
    const windowStart = new Date(sortedEvents[i].timestamp).getTime();
    const windowEnd = windowStart + 10 * 60 * 1000;
    const count = sortedEvents.filter((e) => {
      const t = new Date(e.timestamp).getTime();
      return t >= windowStart && t <= windowEnd;
    }).length;
    if (count >= 5) {
      spikeMap.set(sortedEvents[i].timestamp, count);
    }
  }
  const activitySpikes = Array.from(spikeMap.entries()).map(
    ([timestamp, count]) => ({ timestamp, count })
  );

  const deletedFiles = events.filter((e) => e.action === 'file_deleted');

  return { timeGaps, activitySpikes, deletedFiles };
}
