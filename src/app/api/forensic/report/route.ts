import { NextResponse } from 'next/server';
import { generateReport } from '@/lib/forensic/reporting';

export async function GET() {
  try {
    const report = generateReport();
    return NextResponse.json(report);
  } catch (error) {
    console.error('Report generation failed:', error);
    return NextResponse.json(
      { error: 'Report generation failed' },
      { status: 500 }
    );
  }
}
