/**
 * JURI-X Database Stub
 *
 * PERMANENT FIX: No Prisma, no native modules, no database engine.
 * All data is stored in-memory / JSON files. The forensic analysis
 * results are returned directly from the worker process.
 *
 * This file exists only for backward compatibility — any code that
 * imports `db` from here will get a safe no-op object that never
 * crashes the process.
 */

// Safe no-op database stub — never crashes, never imports anything native
export const db = {
  // All methods return empty results or do nothing
  case: {
    findMany: async () => [],
    findUnique: async () => null,
    create: async (data: any) => data,
    update: async (data: any) => data,
    delete: async () => null,
  },
  evidence: {
    findMany: async () => [],
    findUnique: async () => null,
    create: async (data: any) => data,
    update: async (data: any) => data,
    delete: async () => null,
  },
  custody: {
    findMany: async () => [],
    create: async (data: any) => data,
  },
  analysisResult: {
    findMany: async () => [],
    findUnique: async () => null,
    create: async (data: any) => data,
    upsert: async (data: any) => data,
  },
  $connect: async () => {},
  $disconnect: async () => {},
  $transaction: async (fn: any) => fn(this),
};

/** Always returns null — Prisma is not used */
export function getPrismaDb(): null {
  return null;
}
