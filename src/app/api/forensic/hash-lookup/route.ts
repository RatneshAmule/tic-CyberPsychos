import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try {
    const { hash } = await request.json();

    if (!hash || typeof hash !== 'string') {
      return NextResponse.json({ error: 'Hash is required' }, { status: 400 });
    }

    // Clean hash - remove algorithm prefix if present
    const cleanHash = hash.replace(/^(sha256|sha1|md5|sha512):/i, '').trim();

    if (!/^[a-fA-F0-9]{32,64}$/.test(cleanHash)) {
      return NextResponse.json({ error: 'Invalid hash format' }, { status: 400 });
    }

    const results: Record<string, any> = {};

    // 1. VirusTotal (free, no API key needed for unauth check)
    try {
      const vtResponse = await fetch(`https://www.virustotal.com/api/v3/search?query=${cleanHash}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      if (vtResponse.ok) {
        const vtData = await vtResponse.json();
        results.virustotal = {
          status: 'success',
          data: vtData.data ? {
            sha256: vtData.data.attributes?.sha256 || cleanHash,
            names: vtData.data.attributes?.names || [],
            last_analysis_date: vtData.data.attributes?.last_analysis_date,
            last_analysis_stats: vtData.data.attributes?.last_analysis_stats || {},
            type_description: vtData.data.attributes?.type_description || 'Unknown',
            reputation: vtData.data.attributes?.reputation || 0,
            total_votes: vtData.data.attributes?.total_votes || {},
            tags: vtData.data.attributes?.tags || [],
            signatures: vtData.data.attributes?.last_analysis_results
              ? Object.values(vtData.data.attributes.last_analysis_results).map((r: any) => ({
                  engine: r.engine_name,
                  result: r.result,
                  category: r.category,
                })).filter((r: any) => r.result !== null && r.result !== 'Clean')
              : [],
          } : null,
        };
      } else {
        results.virustotal = { status: 'error', error: `HTTP ${vtResponse.status}` };
      }
    } catch (err: any) {
      results.virustotal = { status: 'error', error: err.message };
    }

    // 2. MalwareBazaar (free, no API key)
    try {
      const mbResponse = await fetch(`https://mb-api.abuse.ch/v1/query/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_info', hash: cleanHash }),
        signal: AbortSignal.timeout(10000),
      });
      if (mbResponse.ok) {
        const mbData = await mbResponse.json();
        results.malwarebazaar = {
          status: 'success',
          data: mbData.query_status === 'ok' ? {
            sha256: mbData.data?.[0]?.sha256_hash || cleanHash,
            tags: mbData.data?.[0]?.tags || [],
            signature: mbData.data?.[0]?.signature || 'Unknown',
            malware_family: mbData.data?.[0]?.malware_family || 'Unknown',
            first_seen: mbData.data?.[0]?.first_seen || 'Unknown',
            last_seen: mbData.data?.[0]?.last_seen || 'Unknown',
            file_name: mbData.data?.[0]?.file_name || 'Unknown',
            file_type_mime: mbData.data?.[0]?.file_type_mime || 'Unknown',
            file_size: mbData.data?.[0]?.file_size || 0,
            delivery_method: mbData.data?.[0]?.delivery_method || 'Unknown',
            reporter: mbData.data?.[0]?.reporter || 'Unknown',
          } : null,
          query_status: mbData.query_status,
        };
      } else {
        results.malwarebazaar = { status: 'error', error: `HTTP ${mbResponse.status}` };
      }
    } catch (err: any) {
      results.malwarebazaar = { status: 'error', error: err.message };
    }

    // 3. abuse.ch Threat Intelligence (IP/URL/domain check for IOCs that aren't hashes)
    try {
      const urlhausResponse = await fetch(`https://urlhaus-api.abuse.ch/v1/url/${cleanHash}`, {
        signal: AbortSignal.timeout(10000),
      });
      if (urlhausResponse.ok) {
        const urlhausData = await urlhausResponse.json();
        if (urlhausData.query_status === 'ok') {
          results.urlhaus = { status: 'success', threat: urlhausData.threat, urlhaus_reference: urlhausData.urlhaus_reference };
        }
      }
    } catch { /* ignore - only relevant for URLs */ }

    return NextResponse.json({
      hash: cleanHash,
      results,
      checkedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
