import { NextResponse } from 'next/server';
import { getSampleAnalysisResult } from '@/lib/forensic/sample-data';

export async function GET() {
  try {
    const result = getSampleAnalysisResult();
    return NextResponse.json({
      sequence: result.rewindSequence,
      summary: {
        totalEvents: result.rewindSequence.length,
        startTime: result.rewindSequence[0]?.timestamp,
        endTime:
          result.rewindSequence[result.rewindSequence.length - 1]
            ?.timestamp,
      },
    });
  } catch (error) {
    console.error('Rewind data failed:', error);
    return NextResponse.json(
      { error: 'Rewind data failed' },
      { status: 500 }
    );
  }
}
