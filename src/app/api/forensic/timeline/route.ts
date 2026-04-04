import { NextResponse } from 'next/server';
import { getSampleAnalysisResult } from '@/lib/forensic/sample-data';

export async function GET() {
  try {
    const result = getSampleAnalysisResult();
    return NextResponse.json({
      events: result.timeline,
      anomalies: {
        timeGaps: [
          {
            start: '2026-03-15T12:00:00Z',
            end: '2026-03-15T14:15:00Z',
            duration: 2,
          },
          {
            start: '2026-03-16T11:30:00Z',
            end: '2026-03-16T15:00:00Z',
            duration: 4,
          },
        ],
        activitySpikes: [
          { timestamp: '2026-03-15T09:00:00Z', count: 8 },
          { timestamp: '2026-03-15T15:00:00Z', count: 12 },
          { timestamp: '2026-03-16T14:00:00Z', count: 15 },
        ],
        deletedFiles: result.timeline.filter(
          (e) => e.action === 'file_deleted'
        ),
      },
    });
  } catch (error) {
    console.error('Timeline generation failed:', error);
    return NextResponse.json(
      { error: 'Timeline generation failed' },
      { status: 500 }
    );
  }
}
