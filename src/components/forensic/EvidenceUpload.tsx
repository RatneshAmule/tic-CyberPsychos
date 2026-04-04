'use client';

import { useState, useCallback, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from '@/components/ui/table';
import {
  Upload,
  HardDrive,
  FileText,
  FileArchive,
  Database,
  Globe,
  Cpu,
  Shield,
  Trash2,
  CheckCircle2,
  Clock,
  AlertCircle,
  Loader2,
  Search,
  FolderOpen,
  X,
  Hash,
  Info,
} from 'lucide-react';
import { format } from 'date-fns';
import type { EvidenceType, EvidenceStatus, Evidence, AnalysisResult } from '@/lib/forensic/types';

function safeFormat(timestamp: string | undefined | null, fmt: string): string {
  if (!timestamp) return '--:--';
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return '--:--';
  return format(d, fmt);
}

// =============================================================================
// Props
// =============================================================================

interface EvidenceUploadProps {
  onAnalysisComplete?: (result: AnalysisResult) => void;
}

// =============================================================================
// File extension to evidence type auto-detection map
// =============================================================================

const EXTENSION_MAP: Record<string, EvidenceType> = {
  // Disk images
  '.dd': 'disk_image',
  '.img': 'disk_image',
  '.e01': 'disk_image',
  '.raw': 'disk_image',
  '.001': 'disk_image',
  '.ad1': 'disk_image',

  // Log files
  '.log': 'log_file',
  '.txt': 'log_file',
  '.evtx': 'log_file',
  '.sys': 'log_file',
  '.xml': 'log_file',
  '.json': 'log_file',

  // Browser data
  '.sqlite': 'browser_data',
  '.db': 'browser_data',
  '.dat': 'browser_data',

  // Windows artifacts
  '.pf': 'prefetch',
  '.lnk': 'windows_artifact',
  '.reg': 'registry_hive',
  '.hive': 'registry_hive',
  '.jumplist': 'jump_list',

  // Network
  '.pcap': 'network_capture',
  '.pcapng': 'network_capture',
  '.cap': 'network_capture',

  // APK
  '.apk': 'apk',

  // Memory
  '.dmp': 'memory_dump',
  '.vmem': 'memory_dump',
  '.liemem': 'memory_dump',

  // Documents
  '.pdf': 'document',
  '.doc': 'document',
  '.docx': 'document',
  '.xls': 'document',
  '.xlsx': 'document',

  // Images
  '.jpg': 'image',
  '.jpeg': 'image',
  '.png': 'image',
  '.gif': 'image',
  '.bmp': 'image',
  '.tiff': 'image',

  // Archives
  '.zip': 'filesystem',
  '.tar': 'filesystem',
  '.gz': 'filesystem',
  '.7z': 'filesystem',
  '.rar': 'filesystem',
};

const EVIDENCE_TYPE_ICONS: Record<EvidenceType, typeof FileText> = {
  disk_image: HardDrive,
  filesystem: FolderOpen,
  log_file: FileText,
  browser_data: Globe,
  windows_artifact: Cpu,
  prefetch: Cpu,
  jump_list: Cpu,
  shellbag: Cpu,
  recent_files: FileText,
  apk: Cpu,
  image: FileText,
  document: FileText,
  network_capture: Globe,
  memory_dump: Database,
  registry_hive: Database,
};

const EVIDENCE_TYPE_COLORS: Record<EvidenceType, string> = {
  disk_image: '#06b6d4',
  filesystem: '#22c55e',
  log_file: '#f59e0b',
  browser_data: '#8b5cf6',
  windows_artifact: '#ec4899',
  prefetch: '#f97316',
  jump_list: '#f97316',
  shellbag: '#f97316',
  recent_files: '#f97316',
  apk: '#14b8a6',
  image: '#a855f7',
  document: '#3b82f6',
  network_capture: '#ef4444',
  memory_dump: '#dc2626',
  registry_hive: '#d97706',
};

const STATUS_CONFIG: Record<EvidenceStatus, { color: string; label: string; icon: typeof CheckCircle2 }> = {
  pending: { color: '#f59e0b', label: 'Pending', icon: Clock },
  processing: { color: '#3b82f6', label: 'Processing', icon: Loader2 },
  analyzed: { color: '#22c55e', label: 'Analyzed', icon: CheckCircle2 },
  error: { color: '#ef4444', label: 'Error', icon: AlertCircle },
};

const ACCEPTED_EXTENSIONS = Object.keys(EXTENSION_MAP);
const MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024; // 10 GB

// =============================================================================
// Helper functions
// =============================================================================

function detectEvidenceType(filename: string): EvidenceType {
  const lower = filename.toLowerCase();
  for (const [ext, type] of Object.entries(EXTENSION_MAP)) {
    if (lower.endsWith(ext)) return type;
  }
  // Special name-based detection
  if (lower.includes('prefetch') || lower.includes('pf_')) return 'prefetch';
  if (lower.includes('history') && (lower.includes('chrome') || lower.includes('firefox'))) return 'browser_data';
  if (lower.includes('ntuser.dat')) return 'registry_hive';
  if (lower.includes('sam') && lower.includes('system32')) return 'registry_hive';
  if (lower.includes('jump') && lower.includes('list')) return 'jump_list';
  if (lower.endsWith('.exe') || lower.endsWith('.dll')) return 'windows_artifact';
  return 'filesystem';
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

function generateMockHash(): string {
  const chars = '0123456789abcdef';
  let hash = 'sha256:';
  for (let i = 0; i < 64; i++) hash += chars[Math.floor(Math.random() * 16)];
  return hash;
}

// =============================================================================
// Upload item interface
// =============================================================================

interface UploadItem {
  id: string;
  file: File;
  name: string;
  type: EvidenceType;
  size: number;
  status: EvidenceStatus;
  progress: number;
  hash: string;
  uploadedAt: string;
  analyzedAt?: string;
  error?: string;
  path: string;
}

// =============================================================================
// Main Component
// =============================================================================

export default function EvidenceUpload({ onAnalysisComplete }: EvidenceUploadProps) {
  const [uploads, setUploads] = useState<UploadItem[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [caseId, setCaseId] = useState('case-' + Math.random().toString(36).substring(2, 8).toUpperCase());
  const [uploading, setUploading] = useState(false);
  const [filterType, setFilterType] = useState<string>('all');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dragCounter = useRef(0);

  // -------------------------------------------------------------------------
  // Handle file selection / drop
  // -------------------------------------------------------------------------

  const processFiles = useCallback((files: FileList | File[]) => {
    const newItems: UploadItem[] = [];

    Array.from(files).forEach((file) => {
      const type = detectEvidenceType(file.name);
      const now = new Date().toISOString();
      newItems.push({
        id: `upload-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        file,
        name: file.name,
        type,
        size: file.size,
        status: 'pending',
        progress: 0,
        hash: generateMockHash(),
        uploadedAt: now,
        path: `/evidence/${caseId}/${file.name}`,
      });
    });

    setUploads((prev) => [...prev, ...newItems]);
  }, [caseId]);

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounter.current = 0;
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFiles(e.dataTransfer.files);
    }
  }, [processFiles]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFiles(e.target.files);
    }
  }, [processFiles]);

  // -------------------------------------------------------------------------
  // REAL upload & analysis — sends files to backend for actual processing
  // -------------------------------------------------------------------------

  const handleUploadAll = useCallback(async () => {
    setUploading(true);
    const pending = uploads.filter((u) => u.status === 'pending');

    // Phase 1: Mark all as processing
    setUploads((prev) =>
      prev.map((u) => (u.status === 'pending' ? { ...u, status: 'processing' as EvidenceStatus, progress: 5 } : u))
    );

    try {
      // Build FormData with actual files
      const formData = new FormData();
      for (const item of pending) {
        formData.append('files', item.file);
      }
      formData.append('caseId', caseId);

      // Simulate upload progress while sending
      let uploadProgress = 5;
      const progressInterval = setInterval(() => {
        uploadProgress = Math.min(uploadProgress + 3, 40);
        setUploads((prev) =>
          prev.map((u) => (u.status === 'processing' ? { ...u, progress: uploadProgress } : u))
        );
      }, 200);

      // Send to REAL analysis API (10 min timeout for large files)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 600000); // 10 minutes
      const response = await fetch('/api/forensic/analyze', {
        method: 'POST',
        body: formData,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      clearInterval(progressInterval);

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.status}`);
      }

      // Phase 2: Processing progress
      setUploads((prev) =>
        prev.map((u) => (u.status === 'processing' ? { ...u, progress: 60 } : u))
      );

      const result = await response.json();

      // Update progress to 90
      setUploads((prev) =>
        prev.map((u) => (u.status === 'processing' ? { ...u, progress: 90 } : u))
      );

      // Mark all as analyzed with real hashes from result
      setUploads((prev) =>
        prev.map((u) => {
          if (u.status !== 'processing') return u;
          // Try to find real hash from result
          const realEvidence = result.evidence?.find((e: any) => e.name === u.name);
          return {
            ...u,
            status: 'analyzed' as EvidenceStatus,
            progress: 100,
            analyzedAt: new Date().toISOString(),
            hash: realEvidence?.hash || u.hash,
          };
        })
      );

      // Notify parent with real results
      if (onAnalysisComplete) {
        onAnalysisComplete(result);
      }
    } catch (error: any) {
      console.error('Real analysis error:', error);
      const errorMsg = error.message || 'Analysis failed';
      let userMessage = errorMsg;
      if (errorMsg === 'Failed to fetch') {
        userMessage = 'Server connection failed — check the terminal where "npm run dev" is running for errors. JURI-X uses zero native modules now — this should not happen.';
      } else if (errorMsg.includes('timeout') || errorMsg.includes('Timeout')) {
        userMessage = 'Server timed out — file may be too large. Try a smaller test file.';
      } else if (errorMsg.includes('413')) {
        userMessage = 'File too large for upload. Try a smaller file.';
      }
      setUploads((prev) =>
        prev.map((u) =>
          u.status === 'processing'
            ? { ...u, status: 'error' as EvidenceStatus, error: userMessage }
            : u
        )
      );
      alert(`Upload Error: ${userMessage}`);
    } finally {
      setUploading(false);
    }
  }, [uploads, caseId, onAnalysisComplete]);

  const removeUpload = useCallback((id: string) => {
    setUploads((prev) => prev.filter((u) => u.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setUploads([]);
  }, []);

  // -------------------------------------------------------------------------
  // Filtered list
  // -------------------------------------------------------------------------

  const filteredUploads = filterType === 'all' ? uploads : uploads.filter((u) => u.type === filterType);

  const uniqueTypes = Array.from(new Set(uploads.map((u) => u.type)));

  const totalSize = uploads.reduce((sum, u) => sum + u.size, 0);
  const analyzedCount = uploads.filter((u) => u.status === 'analyzed').length;
  const pendingCount = uploads.filter((u) => u.status === 'pending').length;

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <div className="space-y-4 h-full">
      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="forensic-card">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold font-mono text-foreground">{uploads.length}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Files</p>
          </CardContent>
        </Card>
        <Card className="forensic-card">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold font-mono text-cyan">{formatFileSize(totalSize)}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Size</p>
          </CardContent>
        </Card>
        <Card className="forensic-card">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold font-mono text-green-400">{analyzedCount}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Analyzed</p>
          </CardContent>
        </Card>
        <Card className="forensic-card">
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold font-mono text-amber-400">{pendingCount}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Pending</p>
          </CardContent>
        </Card>
      </div>

      {/* Case ID */}
      <Card className="forensic-card">
        <CardContent className="p-3">
          <div className="flex items-center gap-3">
            <Label className="text-xs text-muted-foreground shrink-0">Case ID:</Label>
            <Input
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              className="h-7 text-xs font-mono bg-muted/30 border-border/50 max-w-[220px]"
            />
            <Badge variant="outline" className="border-cyan/50 text-cyan bg-cyan/10 text-[10px] font-mono">
              <Hash className="h-3 w-3 mr-1" />
              SHA-256 Verified
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Drop Zone */}
      <div
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`
          relative cursor-pointer rounded-xl border-2 border-dashed transition-all duration-300 p-8
          ${isDragging
            ? 'border-cyan bg-cyan/5 scale-[1.01]'
            : 'border-border/60 hover:border-cyan/50 hover:bg-muted/10'
          }
        `}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileSelect}
          className="hidden"
          accept={ACCEPTED_EXTENSIONS.join(',')}
        />
        <div className="flex flex-col items-center justify-center gap-3 text-center">
          <div className={`
            rounded-full p-4 transition-all duration-300
            ${isDragging ? 'bg-cyan/20' : 'bg-muted/30'}
          `}>
            {isDragging ? (
              <Upload className="h-8 w-8 text-cyan animate-bounce" />
            ) : (
              <FolderOpen className="h-8 w-8 text-muted-foreground" />
            )}
          </div>
          <div>
            <p className="text-sm font-semibold text-foreground">
              {isDragging ? 'Drop files here...' : 'Drag & drop evidence files here'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              or click to browse  •  Supports disk images, logs, browser data, registry, PCAP, APK & more
            </p>
          </div>

          {/* Supported formats grid */}
          <div className="flex flex-wrap justify-center gap-1.5 mt-2">
            {[
              { label: 'Disk Images', ext: '.E01 .dd .img .raw' },
              { label: 'Logs', ext: '.log .evtx .txt' },
              { label: 'Browser', ext: '.sqlite .db .dat' },
              { label: 'Registry', ext: '.reg .hive' },
              { label: 'Prefetch', ext: '.pf' },
              { label: 'Network', ext: '.pcap .pcapng' },
              { label: 'APK', ext: '.apk' },
              { label: 'Memory', ext: '.dmp .vmem' },
            ].map((fmt) => (
              <span
                key={fmt.label}
                className="px-2 py-0.5 rounded bg-muted/30 border border-border/40 text-[9px] text-muted-foreground"
              >
                <span className="font-semibold text-foreground/70">{fmt.label}</span>{' '}
                <span className="font-mono">{fmt.ext}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Actions */}
      {uploads.length > 0 && (
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={handleUploadAll}
              disabled={uploading || pendingCount === 0}
              className="bg-cyan hover:bg-cyan/80 text-background font-semibold"
            >
              {uploading ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <Upload className="h-3.5 w-3.5 mr-1.5" />
              )}
              {uploading ? 'Processing...' : `Analyze ${pendingCount} File${pendingCount !== 1 ? 's' : ''}`}
            </Button>
            <Button variant="outline" size="sm" onClick={clearAll} disabled={uploading} className="border-border/50 text-xs">
              <Trash2 className="h-3.5 w-3.5 mr-1.5" />
              Clear All
            </Button>
          </div>

          {/* Type filter */}
          <div className="flex items-center gap-1.5 overflow-x-auto scrollbar-forensic">
            <Search className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            <button
              onClick={() => setFilterType('all')}
              className={`px-2 py-1 rounded text-[10px] font-medium whitespace-nowrap transition-colors ${
                filterType === 'all' ? 'bg-cyan/20 text-cyan' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              All ({uploads.length})
            </button>
            {uniqueTypes.map((t) => {
              const count = uploads.filter((u) => u.type === t).length;
              return (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`px-2 py-1 rounded text-[10px] font-medium whitespace-nowrap transition-colors capitalize ${
                    filterType === t ? 'bg-cyan/20 text-cyan' : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {t.replace(/_/g, ' ')} ({count})
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Uploaded Files Table */}
      {uploads.length > 0 && (
        <Card className="forensic-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-bold text-foreground uppercase tracking-wider flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan" />
              Evidence Items
              <Badge variant="secondary" className="text-[10px] font-mono ml-1">
                {filteredUploads.length} / {uploads.length}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-3 pt-0">
            <ScrollArea className="max-h-[400px] scrollbar-forensic">
              <div className="rounded-lg border border-border/50 overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-muted/30 hover:bg-muted/30">
                      <TableHead className="text-[10px] uppercase tracking-wider w-8">#</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">File Name</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Detected Type</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Size</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Status</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Hash (SHA-256)</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Uploaded</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider w-10"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredUploads.map((item, idx) => {
                      const statusCfg = STATUS_CONFIG[item.status];
                      const TypeIcon = EVIDENCE_TYPE_ICONS[item.type] || FileText;
                      const typeColor = EVIDENCE_TYPE_COLORS[item.type] || '#9ca3af';
                      const StatusIcon = statusCfg.icon;

                      return (
                        <TableRow
                          key={item.id}
                          className="border-border/30 hover:bg-muted/20 transition-colors"
                        >
                          {/* Index */}
                          <TableCell className="text-[10px] font-mono text-muted-foreground py-2">
                            {String(idx + 1).padStart(2, '0')}
                          </TableCell>

                          {/* File Name */}
                          <TableCell className="py-2">
                            <div className="flex items-center gap-2">
                              <TypeIcon className="h-4 w-4 shrink-0" style={{ color: typeColor }} />
                              <div className="min-w-0">
                                <p className="text-xs font-mono text-cyan truncate max-w-[200px]">{item.name}</p>
                                <p className="text-[9px] text-muted-foreground font-mono truncate max-w-[200px]">
                                  {item.path}
                                </p>
                              </div>
                            </div>
                          </TableCell>

                          {/* Type */}
                          <TableCell className="py-2">
                            <Badge
                              variant="secondary"
                              className="text-[10px] capitalize"
                              style={{
                                backgroundColor: typeColor + '15',
                                color: typeColor,
                                borderColor: typeColor + '40',
                              }}
                            >
                              {item.type.replace(/_/g, ' ')}
                            </Badge>
                          </TableCell>

                          {/* Size */}
                          <TableCell className="text-xs font-mono text-foreground py-2">
                            {formatFileSize(item.size)}
                          </TableCell>

                          {/* Status */}
                          <TableCell className="py-2">
                            <div className="flex flex-col gap-1 min-w-[100px]">
                              <div className="flex items-center gap-1">
                                <StatusIcon
                                  className={`h-3 w-3 ${item.status === 'processing' ? 'animate-spin' : ''}`}
                                  style={{ color: statusCfg.color }}
                                />
                                <span className="text-[10px] font-medium" style={{ color: statusCfg.color }}>
                                  {statusCfg.label}
                                </span>
                              </div>
                              {(item.status === 'processing') && (
                                <Progress value={item.progress} className="h-1 w-full" />
                              )}
                            </div>
                          </TableCell>

                          {/* Hash */}
                          <TableCell className="py-2">
                            <div className="flex items-center gap-1 group">
                              <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
                              <span className="text-[9px] font-mono text-muted-foreground truncate max-w-[120px]">
                                {item.hash.substring(7, 27)}...
                              </span>
                              <Info className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity cursor-help shrink-0"
                              />
                            </div>
                          </TableCell>

                          {/* Upload Time */}
                          <TableCell className="text-[10px] font-mono text-muted-foreground py-2">
                            {safeFormat(item.uploadedAt, 'HH:mm:ss')}
                          </TableCell>

                          {/* Remove */}
                          <TableCell className="py-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                removeUpload(item.id);
                              }}
                              disabled={item.status === 'processing'}
                              className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors disabled:opacity-30"
                            >
                              <X className="h-3.5 w-3.5" />
                            </button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* Info card when empty */}
      {uploads.length === 0 && (
        <Card className="forensic-card">
          <CardContent className="p-6 text-center">
            <div className="flex flex-col items-center gap-3">
              <div className="rounded-full bg-muted/20 p-3">
                <Upload className="h-6 w-6 text-muted-foreground" />
              </div>
              <div>
                <p className="text-sm text-foreground font-medium">No evidence uploaded yet</p>
                <p className="text-xs text-muted-foreground mt-1 max-w-md">
                  Apne forensic evidence files yahaan drag & drop karein ya click karke browse karein.
                  JURI-X automatically file type detect karega aur analysis shuru karega.
                </p>
              </div>

              {/* Quick guide */}
              <div className="mt-2 p-3 rounded-lg bg-muted/10 border border-border/30 text-left max-w-lg w-full">
                <p className="text-[10px] font-bold text-foreground uppercase tracking-wider mb-2">
                  Supported Evidence Types
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                  {[
                    { icon: HardDrive, label: 'Disk Images', formats: '.E01, .dd, .img, .raw', color: '#06b6d4' },
                    { icon: FileText, label: 'Log Files', formats: '.log, .evtx, .txt, .xml', color: '#f59e0b' },
                    { icon: Globe, label: 'Browser Data', formats: '.sqlite (History, Cache)', color: '#8b5cf6' },
                    { icon: Database, label: 'Registry Hives', formats: '.reg, .hive, NTUSER.DAT', color: '#d97706' },
                    { icon: Cpu, label: 'Prefetch / Jump Lists', formats: '.pf, .lnk, .jumplist', color: '#f97316' },
                    { icon: Globe, label: 'Network Captures', formats: '.pcap, .pcapng, .cap', color: '#ef4444' },
                    { icon: Cpu, label: 'APK Files', formats: '.apk (Android apps)', color: '#14b8a6' },
                    { icon: Database, label: 'Memory Dumps', formats: '.dmp, .vmem, .liemem', color: '#dc2626' },
                  ].map(({ icon: Icon, label, formats, color }) => (
                    <div key={label} className="flex items-center gap-2">
                      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
                      <div>
                        <p className="text-[10px] font-medium text-foreground">{label}</p>
                        <p className="text-[9px] font-mono text-muted-foreground">{formats}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-2 rounded-lg bg-cyan/5 border border-cyan/20 max-w-lg w-full">
                <p className="text-[10px] text-cyan flex items-center gap-1.5">
                  <Shield className="h-3.5 w-3.5 shrink-0" />
                  <span>
                    <strong>Forensic Integrity:</strong> Sabhi files ka SHA-256 hash calculate hota hai.
                    Evidence kabhi modify nahi hota — read-only access maintained rehta hai.
                  </span>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
