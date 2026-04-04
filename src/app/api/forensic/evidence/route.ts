import { NextResponse } from 'next/server';
import { getSampleEvidence } from '@/lib/forensic/sample-data';
import type { Evidence, EvidenceType, EvidenceStatus } from '@/lib/forensic/types';

// =============================================================================
// Extension to evidence type mapping (mirrors frontend logic)
// =============================================================================

const EXTENSION_MAP: Record<string, EvidenceType> = {
  '.dd': 'disk_image', '.img': 'disk_image', '.e01': 'disk_image', '.raw': 'disk_image',
  '.log': 'log_file', '.txt': 'log_file', '.evtx': 'log_file', '.xml': 'log_file', '.json': 'log_file',
  '.sqlite': 'browser_data', '.db': 'browser_data', '.dat': 'browser_data',
  '.pf': 'prefetch', '.lnk': 'windows_artifact', '.reg': 'registry_hive', '.hive': 'registry_hive',
  '.pcap': 'network_capture', '.pcapng': 'network_capture',
  '.apk': 'apk', '.dmp': 'memory_dump', '.vmem': 'memory_dump',
  '.pdf': 'document', '.doc': 'document', '.docx': 'document', '.xls': 'document', '.xlsx': 'document',
  '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
  '.zip': 'filesystem', '.tar': 'filesystem', '.7z': 'filesystem',
};

function detectType(filename: string): EvidenceType {
  const lower = filename.toLowerCase();
  for (const [ext, type] of Object.entries(EXTENSION_MAP)) {
    if (lower.endsWith(ext)) return type;
  }
  return 'filesystem';
}

function generateHash(): string {
  const chars = '0123456789abcdef';
  let hash = 'sha256:';
  for (let i = 0; i < 64; i++) hash += chars[Math.floor(Math.random() * 16)];
  return hash;
}

// =============================================================================
// GET — Return evidence list
// =============================================================================

export async function GET() {
  try {
    const evidence = getSampleEvidence();
    return NextResponse.json({ evidence });
  } catch (error) {
    console.error('Evidence retrieval failed:', error);
    return NextResponse.json({ error: 'Evidence retrieval failed' }, { status: 500 });
  }
}

// =============================================================================
// POST — Accept uploaded evidence files
// =============================================================================

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const files = formData.getAll('files') as File[];
    const caseId = formData.get('caseId') as string || 'case-unknown';

    if (!files || files.length === 0) {
      return NextResponse.json({ error: 'No files provided' }, { status: 400 });
    }

    const evidenceItems: Evidence[] = files.map((file, index) => ({
      id: `evid-${Date.now()}-${index}`,
      caseId,
      name: file.name,
      type: detectType(file.name),
      path: `/evidence/${caseId}/${file.name}`,
      size: file.size,
      hash: generateHash(),
      status: 'pending' as EvidenceStatus,
      uploadedAt: new Date().toISOString(),
      metadata: {
        mimeType: file.type || 'application/octet-stream',
        originalName: file.name,
      },
    }));

    // In production: save files to /evidence/{caseId}/, run forensic tools, update status
    // For now: simulate analysis delay and return analyzed status

    return NextResponse.json({
      success: true,
      evidence: evidenceItems,
      message: `${files.length} evidence file(s) received for case ${caseId}`,
      caseId,
    });
  } catch (error) {
    console.error('Evidence upload failed:', error);
    return NextResponse.json({ error: 'Evidence upload failed' }, { status: 500 });
  }
}
