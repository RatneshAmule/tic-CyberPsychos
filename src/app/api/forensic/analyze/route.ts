import { NextResponse } from 'next/server';
import { existsSync, mkdirSync, createWriteStream, readdirSync, statSync, readFileSync } from 'fs';
import { join } from 'path';
import { spawn } from 'child_process';
import { pipeline } from 'stream/promises';
import { Readable } from 'stream';
import { createHash } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// JURI-X Forensic Analysis API Route
//
// PERMANENT FIX: This route has ZERO native module imports.
// It only uses Node.js builtins (fs, path, child_process, stream, crypto).
// All forensic analysis is delegated to a SEPARATE worker process:
//   node scripts/analyze-worker.mjs <caseDir>
//
// The worker uses ONLY CLI tools (sqlite3, exiftool, identify, binwalk, etc.)
// — no native C++ modules whatsoever. Turbopack will never crash.
// ─────────────────────────────────────────────────────────────────────────────

const EVIDENCE_DIR = '/tmp/recon-x/evidence';
const MAX_WORKER_TIMEOUT = 600000; // 10 minutes

export const maxDuration = 600; // 10 minutes
export const dynamic = 'force-dynamic';

function getWorkerPath(): string {
  return join(process.cwd(), 'scripts', 'analyze-worker.mjs');
}

// GET — health check: verify worker script exists and is readable
export async function GET() {
  try {
    const workerPath = getWorkerPath();
    const workerExists = existsSync(workerPath);

    // Quick smoke test: check node version and that key directories exist
    const nodeVersion = process.version;
    const evidenceDirExists = existsSync(EVIDENCE_DIR);

    return NextResponse.json({
      status: workerExists ? 'healthy' : 'degraded',
      workerPath,
      workerExists,
      nodeVersion,
      evidenceDir: evidenceDirExists ? 'exists' : 'missing',
      architecture: 'external_worker',
      timestamp: new Date().toISOString(),
    });
  } catch (error: any) {
    return NextResponse.json({ status: 'error', error: error.message }, { status: 500 });
  }
}

// POST — save uploaded files, spawn worker, return analysis result
export async function POST(request: Request) {
  let caseDir = '';

  try {
    const formData = await request.formData();
    const files = formData.getAll('files') as File[];
    const caseId = (formData.get('caseId') as string) || `case-${Date.now().toString(36)}`;

    if (!files || files.length === 0) {
      // Allow re-analysis of existing case
      const existingCaseId = formData.get('caseId') as string;
      if (existingCaseId && existsSync(join(EVIDENCE_DIR, existingCaseId))) {
        const result = await runWorker(existingCaseId);
        return NextResponse.json(result);
      }
      return NextResponse.json({ error: 'No files provided' }, { status: 400 });
    }

    caseDir = join(EVIDENCE_DIR, caseId);
    if (!existsSync(caseDir)) mkdirSync(caseDir, { recursive: true });

    // Save uploaded files to disk
    const savedFiles: { name: string; path: string; size: number }[] = [];
    for (const file of files) {
      const filePath = join(caseDir, file.name);
      try {
        if (file.size > 50 * 1024 * 1024) {
          // Stream large files (>50MB) to avoid RAM issues
          const nodeStream = Readable.fromWeb(file.stream() as any);
          const writeStream = createWriteStream(filePath);
          await pipeline(nodeStream, writeStream);
          savedFiles.push({ name: file.name, path: filePath, size: file.size });
          console.log(`[JURI-X API] Streamed: ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)`);
        } else {
          const buffer = Buffer.from(await file.arrayBuffer());
          const { writeFileSync } = await import('fs');
          writeFileSync(filePath, buffer);
          savedFiles.push({ name: file.name, path: filePath, size: buffer.length });
          console.log(`[JURI-X API] Saved: ${file.name} (${(buffer.length / 1024).toFixed(1)} KB)`);
        }
      } catch (saveErr: any) {
        console.error(`[JURI-X API] Failed to save ${file.name}:`, saveErr.message);
      }
    }

    if (savedFiles.length === 0) {
      return NextResponse.json({ error: 'Failed to save any files' }, { status: 500 });
    }

    // Run analysis via external worker
    console.log(`[JURI-X API] Spawning worker for case ${caseId} (${savedFiles.length} files)`);
    const result = await runWorker(caseId);
    return NextResponse.json(result);

  } catch (error: any) {
    console.error('[JURI-X API] Error:', error.message);

    // Fallback: return basic file info if worker fails
    if (caseDir && existsSync(caseDir)) {
      try {
        const partialResult = await buildFallbackResult(caseDir);
        return NextResponse.json({
          ...partialResult,
          _partial: true,
          _error: error.message,
        });
      } catch {
        // fallback also failed
      }
    }

    return NextResponse.json(
      { error: 'Analysis failed', details: error.message },
      { status: 500 }
    );
  }
}

// ─── Worker Process Spawner ───────────────────────────────────────────────────

function runWorker(caseId: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const workerPath = getWorkerPath();
    const caseDir = join(EVIDENCE_DIR, caseId);

    if (!existsSync(workerPath)) {
      reject(new Error(`Worker script not found: ${workerPath}`));
      return;
    }

    if (!existsSync(caseDir)) {
      reject(new Error(`Case directory not found: ${caseDir}`));
      return;
    }

    console.log(`[JURI-X API] Starting worker: node "${workerPath}" "${caseDir}"`);

    let stdout = '';
    let stderr = '';
    const worker = spawn('node', [workerPath, caseDir], {
      cwd: process.cwd(),
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });

    const timeout = setTimeout(() => {
      console.error(`[JURI-X API] Worker timeout (${MAX_WORKER_TIMEOUT / 1000}s)`);
      worker.kill('SIGKILL');
      reject(new Error(`Worker timed out after ${MAX_WORKER_TIMEOUT / 1000} seconds`));
    }, MAX_WORKER_TIMEOUT);

    worker.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    worker.stderr.on('data', (chunk: Buffer) => {
      const text = chunk.toString();
      stderr += text;
      // Forward worker logs to our console for debugging
      for (const line of text.split('\n')) {
        if (line.trim()) console.log(`[WORKER] ${line.trim()}`);
      }
    });

    worker.on('close', (code) => {
      clearTimeout(timeout);

      if (code !== 0 && !stdout.trim()) {
        console.error(`[JURI-X API] Worker exited with code ${code}`);
        reject(new Error(`Worker failed (exit code ${code}): ${stderr.substring(0, 500)}`));
        return;
      }

      try {
        // Worker outputs JSON between ---JSON-RESULT-START--- and ---JSON-RESULT-END--- markers
        let jsonStr = stdout.trim();
        const startMarker = '---JSON-RESULT-START---';
        const endMarker = '---JSON-RESULT-END---';
        const startIdx = jsonStr.indexOf(startMarker);
        const endIdx = jsonStr.indexOf(endMarker);
        if (startIdx !== -1 && endIdx !== -1) {
          jsonStr = jsonStr.substring(startIdx + startMarker.length, endIdx).trim();
        }
        const result = JSON.parse(jsonStr);
        console.log(`[JURI-X API] Worker completed. Output: ${(jsonStr.length / 1024).toFixed(1)} KB`);
        resolve(result);
      } catch (parseErr: any) {
        console.error(`[JURI-X API] Failed to parse worker output:`, parseErr.message);
        console.error(`[JURI-X API] stdout (first 500 chars):`, stdout.substring(0, 500));
        console.error(`[JURI-X API] stderr (first 500 chars):`, stderr.substring(0, 500));
        reject(new Error(`Worker output parse error: ${parseErr.message}`));
      }
    });

    worker.on('error', (err) => {
      clearTimeout(timeout);
      reject(new Error(`Worker spawn error: ${err.message}`));
    });
  });
}

// ─── Fallback Result Builder ──────────────────────────────────────────────────

async function buildFallbackResult(caseId: string): Promise<any> {
  const caseDir = join(EVIDENCE_DIR, caseId);
  const fileNames = readdirSync(caseDir);
  const evidenceList: any[] = [];

  for (const name of fileNames) {
    const filePath = join(caseDir, name);
    try {
      const stat = statSync(filePath);
      let hash = 'error';
      try {
        const data = readFileSync(filePath);
        hash = `sha256:${createHash('sha256').update(data).digest('hex')}`;
      } catch { /* ignore */ }

      evidenceList.push({
        id: name,
        caseId,
        name,
        type: 'filesystem',
        path: filePath,
        size: stat.size,
        hash,
        status: 'analyzed',
        uploadedAt: new Date().toISOString(),
        analyzedAt: new Date().toISOString(),
        metadata: { note: 'Basic analysis only — worker failed' },
      });
    } catch {
      evidenceList.push({
        id: name, caseId, name, type: 'filesystem', path: filePath,
        size: 0, hash: 'error', status: 'error', uploadedAt: new Date().toISOString(),
      });
    }
  }

  return {
    caseId,
    caseInfo: {
      id: caseId,
      name: `Case ${caseId}`,
      description: 'Partial analysis — worker process failed',
      createdAt: new Date().toISOString(),
      status: 'active',
      evidenceIds: fileNames,
      analyst: 'JURI-X (fallback)',
    },
    evidence: evidenceList,
    custody: evidenceList.map(e => ({
      id: `cust-${e.name}`,
      evidenceId: e.name,
      action: 'uploaded',
      performedBy: 'JURI-X',
      timestamp: new Date().toISOString(),
      details: `File: ${e.name}`,
      hash: e.hash,
    })),
    timeline: [],
    rewindSequence: [],
    suspiciousFindings: [],
    correlations: { nodes: [], edges: [] },
    heatmap: [],
    keywordResults: [],
    geoIPResults: [],
    stats: {
      totalEvents: 0,
      suspiciousCount: 0,
      criticalCount: 0,
      timeRange: { start: new Date().toISOString(), end: new Date().toISOString() },
      topCategories: [],
    },
  };
}
