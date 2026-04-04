import { createHash } from 'crypto';
import { createReadStream } from 'fs';

// Real SHA-256 hash of a file using streams (handles large files)
export async function calculateFileHash(
  filePath: string,
  algorithm: 'sha256' | 'md5' | 'sha1' = 'sha256'
): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash(algorithm);
    const stream = createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(`${algorithm}:${hash.digest('hex')}`));
    stream.on('error', reject);
  });
}

// Calculate hash synchronously for small buffers
export function calculateBufferHash(
  buffer: Buffer,
  algorithm: 'sha256' | 'md5' | 'sha1' = 'sha256'
): string {
  return `${algorithm}:${createHash(algorithm).update(buffer).digest('hex')}`;
}
