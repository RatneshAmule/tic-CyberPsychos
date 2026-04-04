import { NextResponse } from 'next/server';
import { generateReport } from '@/lib/forensic/reporting';

export async function GET() {
  try {
    const report = generateReport();
    return NextResponse.json({ entries: report.chainOfCustody });
  } catch (error) {
    console.error('Custody data retrieval failed:', error);
    return NextResponse.json(
      { error: 'Custody data retrieval failed' },
      { status: 500 }
    );
  }
}
