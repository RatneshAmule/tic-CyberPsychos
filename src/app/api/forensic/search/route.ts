import { NextResponse } from 'next/server';
import { getSampleAnalysisResult } from '@/lib/forensic/sample-data';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const keyword = searchParams.get('q') || '';
    const result = getSampleAnalysisResult();

    const filteredResults = keyword
      ? result.keywordResults.filter(
          (k) =>
            k.keyword.toLowerCase().includes(keyword.toLowerCase()) ||
            keyword.toLowerCase().includes(k.keyword.toLowerCase())
        )
      : result.keywordResults;

    return NextResponse.json({ results: filteredResults });
  } catch (error) {
    console.error('Search failed:', error);
    return NextResponse.json(
      { error: 'Search failed' },
      { status: 500 }
    );
  }
}
