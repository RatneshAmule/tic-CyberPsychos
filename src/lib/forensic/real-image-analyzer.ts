import { existsSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

// ─── ZERO native module imports ───────────────────────────────────────────────
// PERMANENT FIX: Uses exiftool CLI + file/identify CLI instead of sharp/exifr.
// exiftool and ImageMagick (identify) are pre-installed on Kali Linux.

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ImageAnalysis {
  fileName: string;
  format: string;
  width: number;
  height: number;
  channels: number;
  hasAlpha: boolean;
  density: number | undefined;
  exifData: Record<string, string>;
  gpsData: { latitude: number; longitude: number } | null;
  hasGPS: boolean;
  creationDate: string | null;
  cameraMake: string | null;
  cameraModel: string | null;
  software: string | null;
  isSuspicious: boolean;
  suspiciousReasons: string[];
}

/** Safe exec — never throws */
function safeExec(cmd: string, timeout = 30000): string | null {
  try {
    return execSync(cmd, {
      encoding: 'utf-8',
      maxBuffer: 50 * 1024 * 1024,
      timeout,
    }).trim();
  } catch {
    return null;
  }
}

/** Parse exiftool JSON output */
function parseExiftoolJson(output: string): Record<string, any> | null {
  try {
    // exiftool -j returns a JSON array with one element
    const parsed = JSON.parse(output);
    if (Array.isArray(parsed) && parsed.length > 0) return parsed[0];
    if (typeof parsed === 'object') return parsed;
    return null;
  } catch {
    return null;
  }
}

// ─── Main analysis function ───────────────────────────────────────────────────

export async function analyzeImage(filePath: string): Promise<ImageAnalysis | null> {
  try {
    if (!existsSync(filePath)) return null;

    const fileName = path.basename(filePath);

    // 1. Get image dimensions using `identify` (ImageMagick) or `file` command
    let format = 'unknown';
    let width = 0;
    let height = 0;
    let channels = 3;
    let hasAlpha = false;
    let density: number | undefined = undefined;

    const identifyOutput = safeExec(`identify -verbose "${filePath}" 2>/dev/null | head -30`);
    if (identifyOutput) {
      // Parse: "JPEG 1920x1080 1920x1080+0+0 8-bit sRGB..."
      const geomMatch = identifyOutput.match(/(\d+)x(\d+)/);
      if (geomMatch) {
        width = parseInt(geomMatch[1], 10);
        height = parseInt(geomMatch[2], 10);
      }
      const fmtMatch = identifyOutput.match(/^(\w+)\s/i);
      if (fmtMatch) format = fmtMatch[1].toUpperCase();
      if (identifyOutput.includes('Alpha:')) hasAlpha = true;
      const densityMatch = identifyOutput.match(/Resolution:\s*(\d+)/i);
      if (densityMatch) density = parseInt(densityMatch[1], 10);
      if (identifyOutput.includes('Gray') || identifyOutput.includes('Grayscale')) channels = 1;
      if (identifyOutput.includes('CMYK')) channels = 4;
      if (identifyOutput.includes('Alpha') || identifyOutput.includes('RGBA')) { channels = 4; hasAlpha = true; }
    }

    // Fallback to `file` command for basic info
    if (width === 0) {
      const fileOutput = safeExec(`file "${filePath}"`);
      if (fileOutput) {
        const geomMatch = fileOutput.match(/(\d+)\s*x\s*(\d+)/);
        if (geomMatch) {
          width = parseInt(geomMatch[1], 10);
          height = parseInt(geomMatch[2], 10);
        }
        const fmtMatch = fileOutput.match(/(JPEG|PNG|GIF|BMP|WebP|TIFF|SVG)/i);
        if (fmtMatch) format = fmtMatch[1].toUpperCase();
      }
    }

    // 2. Get full EXIF data using exiftool
    let exifRecord: Record<string, any> | null = null;
    let gpsRecord: { latitude: number; longitude: number } | null = null;

    const exiftoolOutput = safeExec(`exiftool -j -G "${filePath}" 2>/dev/null`);
    if (exiftoolOutput) {
      exifRecord = parseExiftoolJson(exiftoolOutput);
    }

    // Extract GPS coordinates from exiftool output
    if (exifRecord) {
      const gpsLat = exifRecord['GPS:GPSLatitude'] || exifRecord['GPSLatitude'];
      const gpsLon = exifRecord['GPS:GPSLongitude'] || exifRecord['GPSLongitude'];
      const gpsLatRef = exifRecord['GPS:GPSLatitudeRef'] || exifRecord['GPSLatitudeRef'];
      const gpsLonRef = exifRecord['GPS:GPSLongitudeRef'] || exifRecord['GPSLongitudeRef'];

      if (gpsLat && gpsLon) {
        // exiftool may return GPS as decimal degrees directly
        const lat = typeof gpsLat === 'number' ? gpsLat : parseFloat(String(gpsLat));
        const lon = typeof gpsLon === 'number' ? gpsLon : parseFloat(String(gpsLon));
        if (!isNaN(lat) && !isNaN(lon)) {
          gpsRecord = { latitude: lat, longitude: lon };
        }
      }
    }

    // Flatten EXIF data to string key-value
    const exifData: Record<string, string> = {};
    if (exifRecord) {
      for (const [key, value] of Object.entries(exifRecord)) {
        if (value !== null && value !== undefined) {
          exifData[key] = typeof value === 'object' ? JSON.stringify(value) : String(value);
        }
      }
    }

    const creationDate =
      exifRecord?.['EXIF:DateTimeOriginal'] ||
      exifRecord?.['EXIF:DateTimeDigitized'] ||
      exifRecord?.['EXIF:DateTime'] ||
      exifRecord?.['EXIF:CreateDate'] ||
      exifRecord?.['IPTC:DateCreated'] ||
      null;
    const cameraMake = exifRecord?.['EXIF:Make'] || exifRecord?.['Make'] || null;
    const cameraModel = exifRecord?.['EXIF:Model'] || exifRecord?.['Model'] || null;
    const software = exifRecord?.['EXIF:Software'] || exifRecord?.['Software'] || null;

    // Build suspicious reasons
    const suspiciousReasons: string[] = [];
    if (gpsRecord) {
      suspiciousReasons.push(
        `GPS coordinates found: ${gpsRecord.latitude}, ${gpsRecord.longitude}`
      );
    }
    if (software && /photoshop|gimp|paint/i.test(String(software))) {
      suspiciousReasons.push(`Image edited with: ${String(software)}`);
    }
    if (!creationDate && !cameraMake && Object.keys(exifData).length === 0) {
      suspiciousReasons.push('No EXIF data — image may have been stripped');
    }
    if (hasAlpha) {
      suspiciousReasons.push(
        'RGBA image with alpha channel — potential steganography vector'
      );
    }

    return {
      fileName,
      format,
      width,
      height,
      channels,
      hasAlpha,
      density,
      exifData,
      gpsData: gpsRecord,
      hasGPS: !!gpsRecord,
      creationDate: creationDate ? String(creationDate) : null,
      cameraMake: cameraMake ? String(cameraMake) : null,
      cameraModel: cameraModel ? String(cameraModel) : null,
      software: software ? String(software) : null,
      isSuspicious: suspiciousReasons.length > 0,
      suspiciousReasons,
    };
  } catch (error) {
    console.error(`Image analysis failed for ${filePath}:`, error);
    return null;
  }
}
