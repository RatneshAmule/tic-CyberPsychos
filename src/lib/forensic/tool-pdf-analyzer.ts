/**
 * tool-pdf-analyzer.ts — PDF Forensic Analysis
 *
 * Uses: pdfid.py, pdf-parser.py, pdfinfo for PDF forensics.
 * Detects embedded JavaScript, launch actions, embedded files,
 * form fields with auto-submit, potential exploits, and extracts metadata.
 *
 * Every tool call is wrapped in try/catch — gracefully degrades if tools are not installed.
 */

import { execSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PDFMetadata {
  title: string;
  author: string;
  subject: string;
  keywords: string;
  creator: string;
  producer: string;
  creationDate: string;
  modificationDate: string;
  pdfVersion: string;
  pages: string;
  pageWidth: string;
  pageHeight: string;
  encryption: string;
  fileSize: string;
  linearized: string;
  tagged: string;
  form: string;
  javascript: string;
}

export interface PDFStreamInfo {
  id: string;
  type: string;
  filter: string;
  length: number;
  hasJS: boolean;
  content: string;
}

export interface PDFAction {
  type: string;
  subtype: string;
  target: string;
  action: string;
  page: string;
}

export interface PDFEmbeddedFile {
  name: string;
  size: number;
  mimeType: string;
  description: string;
}

export interface PDFFormField {
  name: string;
  type: string;
  value: string;
  flags: string;
  hasSubmitAction: boolean;
}

export interface PDFSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface PDFAnalysisResult {
  available: boolean;
  pdfPath: string;
  metadata: PDFMetadata;
  hasJS: boolean;
  hasActions: boolean;
  hasEmbeddedFiles: boolean;
  hasFormFields: boolean;
  hasAutoSubmit: boolean;
  streams: PDFStreamInfo[];
  actions: PDFAction[];
  embeddedFiles: PDFEmbeddedFile[];
  formFields: PDFFormField[];
  suspiciousKeywords: string[];
  findings: PDFSuspiciousFinding[];
  pdfidResult: Record<string, number>;
  errors: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 30_000,
};

const LONG_EXEC_OPTIONS = {
  encoding: 'utf-8' as const,
  maxBuffer: 50 * 1024 * 1024,
  timeout: 60_000,
};

function runTool(cmd: string, longTimeout = false): string | null {
  try {
    const out = execSync(cmd, longTimeout ? LONG_EXEC_OPTIONS : EXEC_OPTIONS);
    return (out as string).trim();
  } catch (err: any) {
    const msg = err?.message || String(err);
    if (msg.includes('ENOENT') || msg.includes('not found') || msg.includes('command not found')) {
      console.warn(`[JURI-X PDF] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X PDF] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

// ─── pdfinfo Analysis ───────────────────────────────────────────────────────

function analyzeWithPdfInfo(filePath: string): Partial<PDFMetadata> {
  const metadata: Partial<PDFMetadata> = {};
  const output = runTool(`pdfinfo "${filePath}" 2>/dev/null`);
  if (!output) return metadata;

  for (const line of output.split('\n')) {
    const match = line.match(/^([^:]+):\s*(.*)/);
    if (!match) continue;

    const key = match[1].trim().toLowerCase().replace(/\s+/g, '');
    const value = match[2].trim();

    const keyMap: Record<string, keyof PDFMetadata> = {
      'title': 'title',
      'author': 'author',
      'subject': 'subject',
      'keywords': 'keywords',
      'creator': 'creator',
      'producer': 'producer',
      'creationdate': 'creationDate',
      'moddate': 'modificationDate',
      'pdfversion': 'pdfVersion',
      'pages': 'pages',
      'pagesize': 'pageWidth',
      'encrypted': 'encryption',
      'filesize': 'fileSize',
      'pagecustom': 'pageWidth',
    };

    if (keyMap[key]) {
      metadata[keyMap[key]] = value;
    }
  }

  return metadata;
}

// ─── pdfid.py Analysis ──────────────────────────────────────────────────────

function analyzeWithPdfId(filePath: string): Record<string, number> {
  const result: Record<string, number> = {};

  // Try pdfid.py
  const output = runTool(`pdfid.py "${filePath}" 2>/dev/null`);
  if (!output) {
    // Try with python3 explicitly
    const altOutput = runTool(`python3 pdfid.py "${filePath}" 2>/dev/null`);
    if (!altOutput) return result;
    return parsePdfIdOutput(altOutput);
  }

  return parsePdfIdOutput(output);
}

function parsePdfIdOutput(output: string): Record<string, number> {
  const result: Record<string, number> = {};

  for (const line of output.split('\n')) {
    const match = line.match(/(\w+)\s+(\d+)/);
    if (match) {
      result[match[1]] = parseInt(match[2], 10);
    }
  }

  return result;
}

// ─── pdf-parser.py Analysis ─────────────────────────────────────────────────

function analyzeWithPdfParser(filePath: string): {
  streams: PDFStreamInfo[];
  actions: PDFAction[];
  embeddedFiles: PDFEmbeddedFile[];
  formFields: PDFFormField[];
  jsCode: string[];
} {
  const streams: PDFStreamInfo[] = [];
  const actions: PDFAction[] = [];
  const embeddedFiles: PDFEmbeddedFile[] = [];
  const formFields: PDFFormField[] = [];
  const jsCode: string[] = [];

  // List all objects
  const listOutput = runTool(`pdf-parser.py --objects "${filePath}" 2>/dev/null | grep -E "obj|stream|dict|JavaScript|Action|EmbeddedFile|AcroForm"`, true);
  if (!listOutput) {
    // Try with python3
    const altOutput = runTool(`python3 pdf-parser.py --objects "${filePath}" 2>/dev/null`, true);
    if (!altOutput) return { streams, actions, embeddedFiles, formFields, jsCode };
  }

  // Extract JavaScript streams
  const jsOutput = runTool(`pdf-parser.py --search JavaScript --raw "${filePath}" 2>/dev/null`, true)
    || runTool(`python3 pdf-parser.py --search JavaScript --raw "${filePath}" 2>/dev/null`, true);
  if (jsOutput) {
    const jsContent = decodePdfStream(jsOutput);
    if (jsContent) {
      jsCode.push(jsContent);
    }
  }

  // Extract all streams
  const streamsOutput = runTool(`pdf-parser.py --streams "${filePath}" 2>/dev/null`, true)
    || runTool(`python3 pdf-parser.py --streams "${filePath}" 2>/dev/null`, true);
  if (streamsOutput) {
    parsePdfParserStreams(streamsOutput, streams);
  }

  // Extract actions
  const actionsOutput = runTool(`pdf-parser.py --search Action "${filePath}" 2>/dev/null`, true)
    || runTool(`python3 pdf-parser.py --search Action "${filePath}" 2>/dev/null`, true);
  if (actionsOutput) {
    parsePdfParserActions(actionsOutput, actions);
  }

  // Extract embedded files
  const embeddedOutput = runTool(`pdf-parser.py --search EmbeddedFile "${filePath}" 2>/dev/null`, true)
    || runTool(`python3 pdf-parser.py --search EmbeddedFile "${filePath}" 2>/dev/null`, true);
  if (embeddedOutput) {
    parsePdfParserEmbeddedFiles(embeddedOutput, embeddedFiles);
  }

  // Extract form fields (AcroForm)
  const formOutput = runTool(`pdf-parser.py --search AcroForm "${filePath}" 2>/dev/null`, true)
    || runTool(`python3 pdf-parser.py --search AcroForm "${filePath}" 2>/dev/null`, true);
  if (formOutput) {
    parsePdfParserFormFields(formOutput, formFields);
  }

  // Mark streams that contain JS
  for (const stream of streams) {
    stream.hasJS = jsCode.some(js => js.includes(stream.content.substring(0, 50)));
  }

  return { streams, actions, embeddedFiles, formFields, jsCode };
}

function decodePdfStream(raw: string): string {
  // Try to extract readable content from a PDF stream
  // PDF streams are often compressed (FlateDecode), but we can look for JS patterns
  const jsMatch = raw.match(/(?:\/JavaScript|\/JS)\s*\(\?\s*([\s\S]+?)\)?/);
  if (jsMatch) return jsMatch[1];

  // Look for stream content between "stream" and "endstream"
  const streamMatch = raw.match(/stream\s*\r?\n([\s\S]*?)\r?\nendstream/i);
  if (streamMatch) {
    const content = streamMatch[1];
    // Check if it's readable text
    const printable = content.replace(/[^\x20-\x7E]/g, '').length / content.length;
    if (printable > 0.6) return content.trim();
  }

  return '';
}

function parsePdfParserStreams(output: string, streams: PDFStreamInfo[]): void {
  const streamRegex = /obj\s+(\d+)\s+.*?Filter:\s*(\w+).*?Length:\s*(\d+)/g;
  let match;
  let id = 0;

  while ((match = streamRegex.exec(output)) !== null) {
    const filter = match[2];
    const length = parseInt(match[3], 10);
    const content = '';

    streams.push({
      id: `obj_${match[1]}`,
      type: 'stream',
      filter,
      length,
      hasJS: false,
      content,
    });
    id++;
  }

  // Also look for /JS entries
  const jsRegex = /obj\s+(\d+).*?\/JS\s+(\S+)/g;
  while ((match = jsRegex.exec(output)) !== null) {
    streams.push({
      id: `js_obj_${match[1]}`,
      type: 'javascript',
      filter: '',
      length: 0,
      hasJS: true,
      content: match[2],
    });
  }
}

function parsePdfParserActions(output: string, actions: PDFAction[]): void {
  const actionRegex = /\/(\w+)\s*(?:\(?\s*(?:\/(\w+)\s+(\S+))|\/A\s*<<([^>]+)>>)/g;
  let match;

  while ((match = actionRegex.exec(output)) !== null) {
    if (match[2]) {
      actions.push({
        type: match[1],
        subtype: match[2],
        target: match[3],
        action: `${match[2]}: ${match[3]}`,
        page: '',
      });
    }
  }

  // Look for Launch, Submit, Reset actions
  const launchMatch = output.match(/\/Launch\s*<<([^>]+)>>/);
  if (launchMatch) {
    actions.push({
      type: 'Launch',
      subtype: '',
      target: launchMatch[1],
      action: `Launch: ${launchMatch[1]}`,
      page: '',
    });
  }

  const submitMatch = output.match(/\/SubmitForm\s*<<([^>]+)>>/);
  if (submitMatch) {
    actions.push({
      type: 'SubmitForm',
      subtype: '',
      target: submitMatch[1],
      action: `SubmitForm: ${submitMatch[1]}`,
      page: '',
    });
  }
}

function parsePdfParserEmbeddedFiles(output: string, embeddedFiles: PDFEmbeddedFile[]): void {
  const fileRegex = /\/F\s*\(([^)]+)\).*?\/Length\s+(\d+).*?\/Subtype\s*\/(\w+)/g;
  let match;

  while ((match = fileRegex.exec(output)) !== null) {
    embeddedFiles.push({
      name: match[1],
      size: parseInt(match[2], 10),
      mimeType: match[3] || 'application/octet-stream',
      description: '',
    });
  }

  // Also look for file specifications
  const efMatch = output.match(/\/EF\s*<<([^>]+)>>/);
  if (efMatch) {
    const nameMatch = efMatch[1].match(/\/F\s*\(([^)]+)\)/);
    embeddedFiles.push({
      name: nameMatch ? nameMatch[1] : 'embedded_file',
      size: 0,
      mimeType: 'unknown',
      description: efMatch[1],
    });
  }
}

function parsePdfParserFormFields(output: string, formFields: PDFFormField[]): void {
  const fieldRegex = /\/T\s*\(([^)]+)\).*?\/V\s*\(([^)]*)\).*?\/FT\s*\/(\w+)/g;
  let match;

  while ((match = fieldRegex.exec(output)) !== null) {
    const hasSubmit = output.includes('SubmitForm') || output.includes('/Submit');
    formFields.push({
      name: match[1],
      type: match[3],
      value: match[2],
      flags: '',
      hasSubmitAction: hasSubmit,
    });
  }
}

// ─── Suspicious Keyword Detection ───────────────────────────────────────────

function detectSuspiciousKeywords(
  pdfidResult: Record<string, number>,
  jsCode: string[],
  pdfParserOutput: string,
): { keywords: string[]; findings: PDFSuspiciousFinding[] } {
  const keywords: string[] = [];
  const findings: PDFSuspiciousFinding[] = [];

  // Keywords from pdfid counts
  const suspiciousPdfIdKeywords: Record<string, { severity: PDFSuspiciousFinding['severity']; desc: string }> = {
    'JS': { severity: 'highly_suspicious', desc: 'JavaScript found in PDF — may execute malicious code' },
    'JavaScript': { severity: 'highly_suspicious', desc: 'JavaScript found in PDF — may execute malicious code' },
    'AA': { severity: 'critical', desc: 'Auto Action (AA) found — code executes automatically when PDF is opened' },
    'OpenAction': { severity: 'critical', desc: 'Open Action found — code executes when PDF is opened' },
    'Launch': { severity: 'critical', desc: 'Launch action found — may execute programs or files' },
    'EmbeddedFile': { severity: 'suspicious', desc: 'Embedded files found — may contain malware' },
    'RichMedia': { severity: 'suspicious', desc: 'Rich Media annotations found — may contain Flash/ActionScript exploits' },
    'XFA': { severity: 'suspicious', desc: 'XFA form found — XML Forms Architecture can be abused' },
    'ObjStm': { severity: 'suspicious', desc: 'Object streams found — can be used to obfuscate PDF structure' },
    'JS_HTML': { severity: 'critical', desc: 'JavaScript with HTML found — potential for DOM-based attacks' },
    'AcroForm': { severity: 'benign', desc: 'Form fields found — check for auto-submit actions' },
    'GoTo': { severity: 'benign', desc: 'GoTo actions found (normal navigation)' },
    'GoToR': { severity: 'suspicious', desc: 'Remote GoTo found — links to external resources' },
    'URI': { severity: 'benign', desc: 'URI links found' },
    'Catalog': { severity: 'benign', desc: 'PDF catalog found (normal structure)' },
    'Encrypt': { severity: 'suspicious', desc: 'Encryption found — document is password protected' },
  };

  for (const [keyword, info] of Object.entries(suspiciousPdfIdKeywords)) {
    if (pdfidResult[keyword] && pdfidResult[keyword] > 0) {
      keywords.push(`${keyword} (${pdfidResult[keyword]} occurrences)`);
      if (info.severity !== 'benign') {
        findings.push({
          category: 'pdf_keyword',
          severity: info.severity,
          title: `PDF contains: ${keyword}`,
          description: info.desc + (pdfidResult[keyword] > 1 ? ` (${pdfidResult[keyword]} occurrences)` : ''),
          evidence: `pdfid detected ${keyword}: ${pdfidResult[keyword]}`,
        });
      }
    }
  }

  // Analyze JavaScript code for suspicious patterns
  const jsPatterns: { pattern: RegExp; severity: PDFSuspiciousFinding['severity']; desc: string }[] = [
    { pattern: /eval\s*\(/i, severity: 'critical', desc: 'eval() in PDF JavaScript — dynamic code execution' },
    { pattern: /this\.getURL|app\.launchURL/i, severity: 'critical', desc: 'URL fetching in PDF JavaScript — potential data exfiltration' },
    { pattern: /util\.printd|app\.alert|app\.mailMsg/i, severity: 'suspicious', desc: 'System interaction in PDF JavaScript' },
    { pattern: /data\:image|data\:text/i, severity: 'highly_suspicious', desc: 'Data URI in PDF JavaScript — potential payload delivery' },
    { pattern: /unescape|atob|String\.fromCharCode/i, severity: 'highly_suspicious', desc: 'Obfuscation technique in PDF JavaScript' },
    { pattern: /XMLHttpRequest|ActiveXObject/i, severity: 'critical', desc: 'Network request in PDF JavaScript — potential C2 communication' },
    { pattern: /WScript\.Shell|Shell\.Application/i, severity: 'critical', desc: 'Shell access in PDF JavaScript' },
    { pattern: /FileSystemObject|ADODB/i, severity: 'critical', desc: 'File system access in PDF JavaScript' },
    { pattern: /powershell|cmd\.exe|calc\.exe/i, severity: 'critical', desc: 'Process execution in PDF JavaScript' },
    { pattern: /base64|btoa/i, severity: 'suspicious', desc: 'Base64 encoding in PDF JavaScript — possible payload' },
  ];

  for (const js of jsCode) {
    for (const sp of jsPatterns) {
      if (sp.pattern.test(js)) {
        keywords.push(`JS: ${sp.desc.substring(0, 80)}`);
        findings.push({
          category: 'javascript',
          severity: sp.severity,
          title: `Suspicious JavaScript: ${sp.desc}`,
          description: `${sp.desc}. Code excerpt: ${js.substring(0, 200).replace(/\s+/g, ' ')}`,
          evidence: js.substring(0, 300),
        });
      }
    }
  }

  return { keywords, findings };
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzePDF(filePath: string): PDFAnalysisResult {
  const emptyMetadata: PDFMetadata = {
    title: '',
    author: '',
    subject: '',
    keywords: '',
    creator: '',
    producer: '',
    creationDate: '',
    modificationDate: '',
    pdfVersion: '',
    pages: '',
    pageWidth: '',
    pageHeight: '',
    encryption: '',
    fileSize: '',
    linearized: '',
    tagged: '',
    form: '',
    javascript: '',
  };

  if (!existsSync(filePath)) {
    return {
      available: false,
      pdfPath: filePath,
      metadata: emptyMetadata,
      hasJS: false,
      hasActions: false,
      hasEmbeddedFiles: false,
      hasFormFields: false,
      hasAutoSubmit: false,
      streams: [],
      actions: [],
      embeddedFiles: [],
      formFields: [],
      suspiciousKeywords: [],
      findings: [],
      pdfidResult: {},
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const pdfName = basename(filePath);
  const errors: string[] = [];

  console.log(`[JURI-X PDF] Analyzing ${pdfName} (${fileStat.size} bytes)`);

  // Verify it's actually a PDF
  try {
    const head = execSync(`head -c 5 "${filePath}" 2>/dev/null`, { encoding: 'buffer', timeout: 5_000 });
    if (head.toString('utf-8') !== '%PDF-') {
      errors.push('File does not appear to be a valid PDF (missing %PDF- header)');
    }
  } catch {
    /* cannot read file */
  }

  // Get metadata from pdfinfo
  const metadata = { ...emptyMetadata };
  const pdfInfoData = analyzeWithPdfInfo(filePath);
  Object.assign(metadata, pdfInfoData);
  metadata.fileSize = `${fileStat.size} bytes`;

  // Get pdfid results
  const pdfidResult = analyzeWithPdfId(filePath);

  // Get pdf-parser results
  const { streams, actions, embeddedFiles, formFields, jsCode } = analyzeWithPdfParser(filePath);

  // Detect suspicious keywords and findings
  const { keywords, findings } = detectSuspiciousKeywords(pdfidResult, jsCode, '');

  // Determine flags
  const hasJS = pdfidResult['JS'] > 0 || pdfidResult['JavaScript'] > 0 || jsCode.length > 0;
  const hasActions = pdfidResult['AA'] > 0 || pdfidResult['OpenAction'] > 0 || actions.length > 0;
  const hasEmbeddedFiles = pdfidResult['EmbeddedFile'] > 0 || embeddedFiles.length > 0;
  const hasFormFields = pdfidResult['AcroForm'] > 0 || formFields.length > 0;
  const hasAutoSubmit = formFields.some(f => f.hasSubmitAction) || actions.some(a => a.type === 'SubmitForm');

  // Auto-submit finding
  if (hasAutoSubmit) {
    findings.push({
      category: 'form_abuse',
      severity: 'critical',
      title: 'PDF form with auto-submit action',
      description: 'The PDF contains form fields with automatic submit actions. This can be used to exfiltrate user-entered data to an attacker-controlled server.',
      evidence: `${formFields.filter(f => f.hasSubmitAction).length} fields with submit actions`,
    });
  }

  console.log(`[JURI-X PDF] Analysis complete: JS=${hasJS}, Actions=${hasActions}, Embedded=${hasEmbeddedFiles}, Forms=${hasFormFields}, Findings=${findings.length}`);

  return {
    available: true,
    pdfPath: filePath,
    metadata,
    hasJS,
    hasActions,
    hasEmbeddedFiles,
    hasFormFields,
    hasAutoSubmit,
    streams,
    actions,
    embeddedFiles,
    formFields,
    suspiciousKeywords: keywords,
    findings,
    pdfidResult,
    errors,
  };
}
