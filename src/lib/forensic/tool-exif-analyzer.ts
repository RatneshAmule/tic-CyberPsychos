/**
 * tool-exif-analyzer.ts — Comprehensive EXIF/Metadata Analysis
 *
 * Uses: exiftool (Perl-based, very powerful) for complete metadata extraction.
 * Extracts ALL metadata fields, GPS coordinates, camera/device identification,
 * software/tool identification, thumbnail info, and suspicious metadata detection.
 *
 * Falls back to `file` command and `identify` (ImageMagick) if exiftool is not available.
 */

import { execSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { basename } from 'path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface GPSCoordinates {
  latitude: number;
  longitude: number;
  altitude: number;
  latitudeRef: string;
  longitudeRef: string;
  decimalDegrees: string;
  dms: string;
  approximateAddress: string;
}

export interface CameraInfo {
  make: string;
  model: string;
  lens: string;
  serialNumber: string;
  focalLength: string;
  aperture: string;
  shutterSpeed: string;
  iso: string;
  flash: string;
  meteringMode: string;
  exposureMode: string;
  whiteBalance: string;
  orientation: string;
  xResolution: string;
  yResolution: string;
  bitsPerSample: string;
  colorSpace: string;
}

export interface SoftwareUsed {
  authoringSoftware: string;
  editingSoftware: string;
  exifVersion: string;
  iptcVersion: string;
  xmpToolkit: string;
  history: string[];
}

export interface ThumbnailInfo {
  hasThumbnail: boolean;
  width: number;
  height: number;
  size: string;
  format: string;
  compression: string;
}

export interface EXIFSuspiciousFinding {
  category: string;
  severity: 'benign' | 'suspicious' | 'highly_suspicious' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface EXIFAnalysisResult {
  available: boolean;
  filePath: string;
  allMetadata: Record<string, string>;
  gpsCoordinates: GPSCoordinates | null;
  cameraInfo: CameraInfo;
  softwareUsed: SoftwareUsed;
  thumbnail: ThumbnailInfo;
  suspiciousFindings: EXIFSuspiciousFinding[];
  toolUsed: string;
  metadataCount: number;
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
      console.warn(`[JURI-X EXIF] Tool not found: ${cmd.split(' ')[0]}`);
    } else {
      console.warn(`[JURI-X EXIF] ${cmd.split(' ')[0]} failed: ${msg.substring(0, 200)}`);
    }
    return null;
  }
}

// ─── exiftool Integration ───────────────────────────────────────────────────

function extractWithExifTool(filePath: string): Record<string, string> {
  const metadata: Record<string, string> = {};

  // Run exiftool with -j (JSON) for structured output
  const jsonOutput = runTool(`exiftool -j -G -a -s "${filePath}" 2>/dev/null`);
  if (jsonOutput) {
    try {
      const parsed = JSON.parse(jsonOutput);
      if (Array.isArray(parsed) && parsed.length > 0) {
        const data = parsed[0];
        for (const [key, value] of Object.entries(data)) {
          if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            metadata[key] = String(value);
          } else if (value === null || value === undefined) {
            metadata[key] = '';
          } else if (Array.isArray(value)) {
            metadata[key] = value.join(', ');
          } else if (typeof value === 'object') {
            metadata[key] = JSON.stringify(value);
          }
        }
      }
    } catch {
      // JSON parse failed, fall back to text output
    }
  }

  // Fallback: text format
  if (Object.keys(metadata).length === 0) {
    const textOutput = runTool(`exiftool -a -G -s "${filePath}" 2>/dev/null`);
    if (textOutput) {
      for (const line of textOutput.split('\n')) {
        const match = line.match(/^\[(\w+)\]\s+([\w\s()-]+?)\s*:\s*(.*)/);
        if (match) {
          metadata[`${match[1]}:${match[2].trim()}`] = match[3].trim();
        }
      }
    }
  }

  return metadata;
}

/** Extract thumbnail using exiftool. */
function extractThumbnailInfo(filePath: string): ThumbnailInfo {
  const thumb: ThumbnailInfo = {
    hasThumbnail: false,
    width: 0,
    height: 0,
    size: '',
    format: '',
    compression: '',
  };

  // Check if thumbnail exists
  const thumbCheck = runTool(`exiftool -ThumbnailImage -b "${filePath}" 2>/dev/null | wc -c`);
  if (thumbCheck && parseInt(thumbCheck, 10) > 0) {
    thumb.hasThumbnail = true;
    thumb.size = `${parseInt(thumbCheck, 10)} bytes`;
  }

  // Get thumbnail dimensions
  const thumbDim = runTool(`exiftool -ThumbnailImageWidth -ThumbnailImageHeight -ThumbnailImageLength -ThumbnailImageType "${filePath}" 2>/dev/null`);
  if (thumbDim) {
    for (const line of thumbDim.split('\n')) {
      const match = line.match(/(\w+)\s*:\s*(.+)/);
      if (match) {
        const key = match[1].trim().toLowerCase();
        const val = match[2].trim();
        if (key.includes('width')) thumb.width = parseInt(val, 10) || 0;
        if (key.includes('height') || key.includes('length')) thumb.height = parseInt(val, 10) || 0;
        if (key.includes('type')) thumb.format = val;
      }
    }
  }

  return thumb;
}

// ─── Fallback: identify (ImageMagick) ───────────────────────────────────────

function extractWithIdentify(filePath: string): Record<string, string> {
  const metadata: Record<string, string> = {};

  const output = runTool(`identify -verbose "${filePath}" 2>/dev/null`);
  if (!output) return metadata;

  for (const line of output.split('\n')) {
    const match = line.match(/^\s*([\w\s]+):\s*(.*)/);
    if (match && match[2].trim()) {
      metadata[match[1].trim()] = match[2].trim();
    }
  }

  return metadata;
}

// ─── Fallback: file command ─────────────────────────────────────────────────

function extractWithFileCommand(filePath: string): Record<string, string> {
  const metadata: Record<string, string> = {};

  const output = runTool(`file -b "${filePath}" 2>/dev/null`);
  if (output) {
    metadata['file_command'] = output;
  }

  return metadata;
}

// ─── GPS Coordinate Parsing ─────────────────────────────────────────────────

function parseGPS(metadata: Record<string, string>): GPSCoordinates | null {
  let latitude = 0;
  let longitude = 0;
  let altitude = 0;
  let latitudeRef = 'N';
  let longitudeRef = 'E';

  // exiftool uses GPSLatitude/GPSLongitude with decimal values or DMS
  const latStr = metadata['EXIF:GPSLatitude'] || metadata['GPS:GPSLatitude'] || metadata['GPSLatitude'] || '';
  const lonStr = metadata['EXIF:GPSLongitude'] || metadata['GPS:GPSLongitude'] || metadata['GPSLongitude'] || '';
  const latRef = metadata['EXIF:GPSLatitudeRef'] || metadata['GPS:GPSLatitudeRef'] || metadata['GPSLatitudeRef'] || '';
  const lonRef = metadata['EXIF:GPSLongitudeRef'] || metadata['GPS:GPSLongitudeRef'] || metadata['GPSLongitudeRef'] || '';
  const altStr = metadata['EXIF:GPSAltitude'] || metadata['GPS:GPSAltitude'] || metadata['GPSAltitude'] || '';

  if (!latStr || !lonStr) return null;

  latitudeRef = latRef || 'N';
  longitudeRef = lonRef || 'E';

  // Parse DMS format: "34 deg 12' 34.5"" or decimal
  latitude = parseGPSCoordinate(latStr);
  longitude = parseGPSCoordinate(lonStr);
  altitude = parseFloat(altStr) || 0;

  if (isNaN(latitude) || isNaN(longitude)) return null;
  if (latitude === 0 && longitude === 0) return null; // Likely null island (default)

  // Apply hemisphere references
  if (latitudeRef === 'S') latitude = -latitude;
  if (longitudeRef === 'W') longitude = -longitude;

  // Convert to DMS for display
  const latDMS = toDMS(Math.abs(latitude), latitudeRef);
  const lonDMS = toDMS(Math.abs(longitude), longitudeRef);

  return {
    latitude,
    longitude,
    altitude,
    latitudeRef,
    longitudeRef,
    decimalDegrees: `${latitude.toFixed(6)}, ${longitude.toFixed(6)}`,
    dms: `${latDMS}, ${lonDMS}`,
    approximateAddress: '',
  };
}

/** Parse a GPS coordinate from various formats. */
function parseGPSCoordinate(coordStr: string): number {
  // Try decimal format first
  const decimal = parseFloat(coordStr);
  if (!isNaN(decimal) && Math.abs(decimal) <= 90) return decimal;

  // Try DMS: "34 deg 12' 34.5""
  const dmsMatch = coordStr.match(/(\d+)\s*(?:deg|°)\s*(\d+)'?\s*(\d+(?:\.\d+)?)"/i);
  if (dmsMatch) {
    const d = parseInt(dmsMatch[1], 10);
    const m = parseInt(dmsMatch[2], 10);
    const s = parseFloat(dmsMatch[3]);
    return d + m / 60 + s / 3600;
  }

  // Try "34 12 34.5" (space-separated DMS)
  const parts = coordStr.trim().split(/\s+/).map(Number);
  if (parts.length >= 3 && parts.every(p => !isNaN(p))) {
    return parts[0] + parts[1] / 60 + parts[2] / 3600;
  }

  return NaN;
}

/** Convert decimal degrees to DMS string. */
function toDMS(decimal: number, ref: string): string {
  const d = Math.floor(decimal);
  const m = Math.floor((decimal - d) * 60);
  const s = ((decimal - d) * 60 - m) * 60;
  return `${d}°${m}'${s.toFixed(1)}"${ref}`;
}

// ─── Camera Info Extraction ─────────────────────────────────────────────────

function parseCameraInfo(metadata: Record<string, string>): CameraInfo {
  const get = (keys: string[]): string => {
    for (const k of keys) {
      if (metadata[k] && metadata[k].trim()) return metadata[k].trim();
    }
    return '';
  };

  return {
    make: get(['EXIF:Make', 'IFD0:Make', 'Make']),
    model: get(['EXIF:Model', 'IFD0:Model', 'Model']),
    lens: get(['EXIF:LensModel', 'EXIF:LensMake', 'LensModel']),
    serialNumber: get(['EXIF:BodySerialNumber', 'EXIF:SerialNumber', 'MakerNotes:SerialNumber', 'SerialNumber']),
    focalLength: get(['EXIF:FocalLength', 'FocalLength']),
    aperture: get(['EXIF:FNumber', 'Composite:Aperture', 'FNumber']),
    shutterSpeed: get(['EXIF:ExposureTime', 'Composite:ShutterSpeed', 'ExposureTime']),
    iso: get(['EXIF:ISO', 'EXIF:ISOSpeedRatings', 'Composite:ISO', 'ISO']),
    flash: get(['EXIF:Flash', 'Flash']),
    meteringMode: get(['EXIF:MeteringMode', 'MeteringMode']),
    exposureMode: get(['EXIF:ExposureMode', 'ExposureMode']),
    whiteBalance: get(['EXIF:WhiteBalance', 'WhiteBalance']),
    orientation: get(['IFD0:Orientation', 'Orientation']),
    xResolution: get(['IFD0:XResolution', 'XResolution', 'ExifTool:ExifImageWidth']),
    yResolution: get(['IFD0:YResolution', 'YResolution', 'ExifTool:ExifImageHeight']),
    bitsPerSample: get(['EXIF:BitsPerSample', 'BitsPerSample']),
    colorSpace: get(['EXIF:ColorSpace', 'ColorSpace']),
  };
}

// ─── Software Identification ────────────────────────────────────────────────

function parseSoftware(metadata: Record<string, string>): SoftwareUsed {
  const get = (keys: string[]): string => {
    for (const k of keys) {
      if (metadata[k] && metadata[k].trim()) return metadata[k].trim();
    }
    return '';
  };

  const history: string[] = [];
  for (const [key, value] of Object.entries(metadata)) {
    if (key.toLowerCase().includes('history') && value) {
      history.push(value);
    }
  }

  return {
    authoringSoftware: get(['IPTC:ApplicationRecordVersion', 'XMP:CreatorTool', 'CreatorTool', 'Producer']),
    editingSoftware: get(['IPTC:Software', 'IFD0:Software', 'XMP:Software', 'Software', 'Producer']),
    exifVersion: get(['EXIF:ExifVersion', 'ExifVersion']),
    iptcVersion: get(['IPTC:CodedCharacterSet', 'IPTC:ApplicationRecordVersion']),
    xmpToolkit: get(['XMP:XMPToolkit', 'XMPToolkit']),
    history,
  };
}

// ─── Suspicious Metadata Detection ──────────────────────────────────────────

function detectSuspiciousMetadata(
  metadata: Record<string, string>,
  gps: GPSCoordinates | null,
  camera: CameraInfo,
  software: SoftwareUsed,
): EXIFSuspiciousFinding[] {
  const findings: EXIFSuspiciousFinding[] = [];

  // 1. Mismatched dates (modified before created, or created far in the future)
  const createdDate = metadata['EXIF:DateTimeOriginal'] || metadata['IFD0:DateTime'] || metadata['DateTimeOriginal'] || '';
  const modifiedDate = metadata['EXIF:DateTimeDigitized'] || metadata['IFD0:DateTime'] || metadata['DateTime'] || '';
  const fileModifyDate = metadata['File:FileModifyDate'] || '';

  if (createdDate && modifiedDate && createdDate !== modifiedDate) {
    findings.push({
      category: 'date_mismatch',
      severity: 'suspicious',
      title: 'EXIF date mismatch',
      description: `Original date (${createdDate}) differs from digitized date (${modifiedDate}). This could indicate the image was modified after capture.`,
      evidence: `Original: ${createdDate}, Digitized: ${modifiedDate}`,
    });
  }

  // Check if date is suspiciously old or in the future
  if (createdDate) {
    const created = new Date(createdDate.replace(/(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3'));
    const now = new Date();
    if (!isNaN(created.getTime())) {
      if (created > now) {
        findings.push({
          category: 'date_anomaly',
          severity: 'highly_suspicious',
          title: 'EXIF date is in the future',
          description: `Original creation date (${createdDate}) is in the future. This is likely fabricated metadata.`,
          evidence: createdDate,
        });
      }
      if (created < new Date('1990-01-01')) {
        findings.push({
          category: 'date_anomaly',
          severity: 'suspicious',
          title: 'EXIF date is suspiciously old',
          description: `Original creation date (${createdDate}) predates common digital cameras. Metadata may be falsified.`,
          evidence: createdDate,
        });
      }
    }
  }

  // 2. GPS coordinates detected
  if (gps) {
    findings.push({
      category: 'gps_location',
      severity: 'suspicious',
      title: `GPS coordinates found: ${gps.decimalDegrees}`,
      description: `Image contains GPS metadata that reveals the location where the photo was taken: ${gps.dms}. This can be a privacy concern.`,
      evidence: `${gps.decimalDegrees} (altitude: ${gps.altitude}m)`,
    });

    // Check for known sensitive locations (generic check)
    const lat = Math.abs(gps.latitude);
    const lon = Math.abs(gps.longitude);
    // Pentagon area
    if (lat > 38.86 && lat < 38.88 && lon > 77.04 && lon < 77.06) {
      findings.push({
        category: 'sensitive_location',
        severity: 'highly_suspicious',
        title: 'GPS near sensitive government facility',
        description: 'Image was taken near the Pentagon area. This could indicate reconnaissance photography.',
        evidence: gps.decimalDegrees,
      });
    }
  }

  // 3. Editing software detected
  const editingSoftware = ['photoshop', 'gimp', 'lightroom', 'capture one', 'affinity', 'paint.net', 'pixlr', 'canva'];
  const softwareStr = `${software.editingSoftware} ${software.authoringSoftware} ${software.xmpToolkit}`.toLowerCase();

  for (const es of editingSoftware) {
    if (softwareStr.includes(es)) {
      findings.push({
        category: 'editing_software',
        severity: 'suspicious',
        title: `Image processed with: ${es.charAt(0).toUpperCase() + es.slice(1)}`,
        description: `Image metadata indicates it was processed with ${es}. The image may have been altered from its original state.`,
        evidence: software.editingSoftware || software.authoringSoftware,
      });
      break;
    }
  }

  // 4. Camera serial number present (identifies specific device)
  if (camera.serialNumber) {
    findings.push({
      category: 'device_identification',
      severity: 'benign',
      title: `Camera serial number: ${camera.serialNumber}`,
      description: `Image metadata includes camera serial number, which can identify the specific device used to take the photo.`,
      evidence: `${camera.make} ${camera.model} (S/N: ${camera.serialNumber})`,
    });
  }

  // 5. Missing expected EXIF fields (stripped metadata)
  const exifKeys = Object.keys(metadata).filter(k => k.startsWith('EXIF:'));
  if (exifKeys.length === 0 && Object.keys(metadata).length > 5) {
    findings.push({
      category: 'missing_exif',
      severity: 'suspicious',
      title: 'EXIF data stripped or missing',
      description: 'Image has metadata but no EXIF fields. This could indicate the metadata was intentionally stripped to hide the source.',
      evidence: `Total fields: ${Object.keys(metadata).length}, EXIF fields: 0`,
    });
  }

  // 6. XMP metadata with unusual entries
  const xmpKeys = Object.keys(metadata).filter(k => k.startsWith('XMP:'));
  for (const key of xmpKeys) {
    const val = metadata[key].toLowerCase();
    if (val.includes('password') || val.includes('credential') || val.includes('secret')) {
      findings.push({
        category: 'sensitive_xmp',
        severity: 'highly_suspicious',
        title: `Sensitive keyword in XMP metadata: ${key}`,
        description: `XMP metadata field ${key} contains a potentially sensitive keyword.`,
        evidence: metadata[key],
      });
    }
  }

  // 7. IPTC data with author information
  const author = metadata['IPTC:By-line'] || metadata['IPTC:Creator'] || metadata['By-line'] || metadata['Creator'];
  if (author) {
    findings.push({
      category: 'author_identification',
      severity: 'benign',
      title: `Author identified: ${author}`,
      description: `Image metadata includes author/creator information: ${author}.`,
      evidence: author,
    });
  }

  // 8. Copyright information
  const copyright = metadata['IPTC:Copyright'] || metadata['IFD0:Copyright'] || metadata['Copyright'];
  if (copyright) {
    findings.push({
      category: 'copyright',
      severity: 'benign',
      title: `Copyright notice: ${copyright}`,
      description: `Image contains copyright metadata: ${copyright}.`,
      evidence: copyright,
    });
  }

  // 9. Comment with suspicious content
  const comment = metadata['EXIF:UserComment'] || metadata['IPTC:Caption-Abstract'] || metadata['Comment'] || '';
  if (comment && (comment.includes('http') || comment.includes('password') || comment.includes('key='))) {
    findings.push({
      category: 'suspicious_comment',
      severity: 'highly_suspicious',
      title: 'Suspicious content in image comment',
      description: `Image comment/metadata contains suspicious content: ${comment.substring(0, 200)}`,
      evidence: comment.substring(0, 300),
    });
  }

  // 10. Check for very large metadata (metadata steganography indicator)
  let totalMetadataSize = 0;
  for (const value of Object.values(metadata)) {
    totalMetadataSize += value.length;
  }
  if (totalMetadataSize > 50000) {
    findings.push({
      category: 'large_metadata',
      severity: 'suspicious',
      title: `Unusually large metadata (${totalMetadataSize} characters)`,
      description: 'The image has an unusually large amount of metadata. This could indicate metadata steganography or embedded data.',
      evidence: `${totalMetadataSize} characters across ${Object.keys(metadata).length} fields`,
    });
  }

  return findings;
}

// ─── Main Analysis Function ─────────────────────────────────────────────────

export function analyzeWithExifTool(filePath: string): EXIFAnalysisResult {
  if (!existsSync(filePath)) {
    return {
      available: false,
      filePath,
      allMetadata: {},
      gpsCoordinates: null,
      cameraInfo: {
        make: '', model: '', lens: '', serialNumber: '', focalLength: '',
        aperture: '', shutterSpeed: '', iso: '', flash: '', meteringMode: '',
        exposureMode: '', whiteBalance: '', orientation: '', xResolution: '',
        yResolution: '', bitsPerSample: '', colorSpace: '',
      },
      softwareUsed: {
        authoringSoftware: '', editingSoftware: '', exifVersion: '',
        iptcVersion: '', xmpToolkit: '', history: [],
      },
      thumbnail: {
        hasThumbnail: false, width: 0, height: 0, size: '', format: '', compression: '',
      },
      suspiciousFindings: [],
      toolUsed: 'none',
      metadataCount: 0,
      errors: [`File not found: ${filePath}`],
    };
  }

  const fileStat = statSync(filePath);
  const fileName = basename(filePath);
  const errors: string[] = [];

  console.log(`[JURI-X EXIF] Analyzing ${fileName} (${fileStat.size} bytes)`);

  let metadata: Record<string, string> = {};
  let toolUsed = 'none';

  // Try exiftool first (most comprehensive)
  metadata = extractWithExifTool(filePath);
  if (Object.keys(metadata).length > 0) {
    toolUsed = 'exiftool';
    console.log(`[JURI-X EXIF] Using exiftool: ${Object.keys(metadata).length} fields`);
  }

  // Fallback: ImageMagick identify
  if (Object.keys(metadata).length === 0) {
    metadata = extractWithIdentify(filePath);
    if (Object.keys(metadata).length > 0) {
      toolUsed = 'identify';
      console.log(`[JURI-X EXIF] Using ImageMagick identify: ${Object.keys(metadata).length} fields`);
    }
  }

  // Fallback: file command
  if (Object.keys(metadata).length === 0) {
    metadata = extractWithFileCommand(filePath);
    if (Object.keys(metadata).length > 0) {
      toolUsed = 'file';
      console.log(`[JURI-X EXIF] Using file command: ${Object.keys(metadata).length} fields`);
    }
  }

  if (Object.keys(metadata).length === 0) {
    errors.push('No metadata could be extracted from the file.');
  }

  // Parse structured data
  const gpsCoordinates = parseGPS(metadata);
  const cameraInfo = parseCameraInfo(metadata);
  const softwareUsed = parseSoftware(metadata);

  // Get thumbnail info (only with exiftool)
  const thumbnail = toolUsed === 'exiftool' ? extractThumbnailInfo(filePath) : {
    hasThumbnail: false, width: 0, height: 0, size: '', format: '', compression: '',
  };

  // Detect suspicious items
  const suspiciousFindings = detectSuspiciousMetadata(metadata, gpsCoordinates, cameraInfo, softwareUsed);

  console.log(`[JURI-X EXIF] Analysis complete: ${Object.keys(metadata).length} fields, GPS: ${gpsCoordinates ? 'yes' : 'no'}, ${suspiciousFindings.length} findings`);

  return {
    available: Object.keys(metadata).length > 0,
    filePath,
    allMetadata: metadata,
    gpsCoordinates,
    cameraInfo,
    softwareUsed,
    thumbnail,
    suspiciousFindings,
    toolUsed,
    metadataCount: Object.keys(metadata).length,
    errors,
  };
}
