import { NextResponse } from 'next/server';
import { getSampleAnalysisResult } from '@/lib/forensic/sample-data';

export async function GET() {
  try {
    const result = getSampleAnalysisResult();
    return NextResponse.json({ results: result.geoIPResults });
  } catch (error) {
    console.error('GeoIP lookup failed:', error);
    return NextResponse.json(
      { error: 'GeoIP lookup failed' },
      { status: 500 }
    );
  }
}
