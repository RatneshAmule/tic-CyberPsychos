'use client';
import { useState, useEffect, useCallback } from 'react';

export interface CaseItem {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'closed' | 'archived';
  createdAt: string;
  updatedAt: string;
  analyst: string;
  evidenceCount: number;
}

const STORAGE_KEY = 'juri-x-cases';
const ACTIVE_CASE_KEY = 'juri-x-active-case';

function loadCases(): CaseItem[] {
  if (typeof window === 'undefined') return [];
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch { return []; }
}

function saveCases(cases: CaseItem[]) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
}

export function useMultiCase() {
  const [cases, setCases] = useState<CaseItem[]>(loadCases);
  const [activeCaseId, setActiveCaseId] = useState<string>('');

  useEffect(() => {
    saveCases(cases);
  }, [cases]);

  useEffect(() => {
    const saved = localStorage.getItem(ACTIVE_CASE_KEY);
    if (saved) {
      setActiveCaseId(saved);
    } else if (cases.length > 0) {
      setActiveCaseId(cases[0].id);
    }
  }, []);

  useEffect(() => {
    if (activeCaseId) {
      localStorage.setItem(ACTIVE_CASE_KEY, activeCaseId);
    }
  }, [activeCaseId]);

  const activeCase = cases.find(c => c.id === activeCaseId) || null;

  const createCase = useCallback((name: string, description: string = '', analyst: string = 'Anonymous') => {
    const newCase: CaseItem = {
      id: `case-${Date.now().toString(36).toUpperCase()}`,
      name,
      description,
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      analyst,
      evidenceCount: 0,
    };
    setCases(prev => [...prev, newCase]);
    setActiveCaseId(newCase.id);
    return newCase;
  }, []);

  const updateCase = useCallback((id: string, updates: Partial<CaseItem>) => {
    setCases(prev => prev.map(c => c.id === id ? { ...c, ...updates, updatedAt: new Date().toISOString() } : c));
  }, []);

  const deleteCase = useCallback((id: string) => {
    setCases(prev => prev.filter(c => c.id !== id));
    if (activeCaseId === id) {
      setActiveCaseId(cases.find(c => c.id !== id)?.id || '');
    }
  }, [activeCaseId, cases]);

  const addNote = useCallback((caseId: string, note: string) => {
    // Notes are stored in case description with a timestamp prefix
    const c = cases.find(c => c.id === caseId);
    if (c) {
      const timestampedNote = `[${new Date().toISOString()}] ${note}`;
      updateCase(caseId, { description: c.description ? `${c.description}\n${timestampedNote}` : timestampedNote });
    }
  }, [cases, updateCase]);

  return { cases, activeCase, activeCaseId, setActiveCaseId, createCase, updateCase, deleteCase, addNote };
}
