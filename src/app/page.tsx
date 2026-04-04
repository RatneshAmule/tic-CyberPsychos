'use client';

import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Shield,
  Home,
  Upload,
  Clock,
  Play,
  Network,
  AlertTriangle,
  Search,
  FileText,
  Loader2,
  CheckCircle,
  Bot,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Dashboard, { DashboardSkeleton } from '@/components/forensic/Dashboard';
import TimelineView from '@/components/forensic/TimelineView';
import RewindPlayer from '@/components/forensic/RewindPlayer';
import EntityGraph from '@/components/forensic/EntityGraph';
import SuspiciousPanel from '@/components/forensic/SuspiciousPanel';
import KeywordSearch from '@/components/forensic/KeywordSearch';
import ReportGenerator from '@/components/forensic/ReportGenerator';
import EvidenceUpload from '@/components/forensic/EvidenceUpload';
import AIInvestigator from '@/components/forensic/AIInvestigator';
import type { AnalysisResult } from '@/lib/forensic/types';

type TabId = 'dashboard' | 'evidence' | 'timeline' | 'rewind' | 'graph' | 'findings' | 'search' | 'ai' | 'reports';

interface TabConfig {
  id: TabId;
  label: string;
  icon: typeof Home;
  isSpecial?: boolean;
}

const TABS: TabConfig[] = [
  { id: 'dashboard', label: 'Dashboard', icon: Home },
  { id: 'evidence', label: 'Evidence', icon: Upload, isSpecial: true },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'rewind', label: 'Rewind Mode', icon: Play, isSpecial: true },
  { id: 'graph', label: 'Graph', icon: Network },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'search', label: 'Search', icon: Search },
  { id: 'ai', label: 'AI Investigator', icon: Bot, isSpecial: true },
  { id: 'reports', label: 'Reports', icon: FileText },
];

export default function HomePage() {
  const [activeTab, setActiveTab] = useState<TabId>('evidence');
  const [data, setData] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [analyzed, setAnalyzed] = useState(false);

  // No auto-fetch — user must upload evidence first
  // Data only comes from real file analysis via EvidenceUpload component
  const handleAnalysisComplete = useCallback((result: AnalysisResult) => {
    setData(result);
    setAnalyzed(true);
    setActiveTab('dashboard');
  }, []);

  const tabVariants = {
    enter: { opacity: 0, y: 10 },
    center: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -10 },
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Fixed Header */}
      <header className="forensic-header sticky top-0 z-50 border-b border-border/50">
        <div className="max-w-[1800px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between gap-4">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="h-8 w-8 text-cyan" />
                <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-cyan animate-pulse" />
              </div>
              <div>
                <h1 className="text-lg font-bold tracking-widest text-foreground flex items-center gap-2">
                  JURI-X
                </h1>
                <p className="text-[10px] text-muted-foreground tracking-wider uppercase">
                  Autonomous Forensic Intelligence Platform
                </p>
              </div>
            </div>

            {/* Status & Actions */}
            <div className="flex items-center gap-3">
              {loading && (
                <div className="flex items-center gap-2 text-cyan">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span className="text-xs font-mono">Analyzing...</span>
                </div>
              )}
              {analyzed && !loading && (
                <Badge
                  variant="outline"
                  className="border-emerald-500/50 text-emerald-400 bg-emerald-500/10 font-mono text-xs"
                >
                  <CheckCircle className="h-3 w-3 mr-1" />
                  Analysis Complete
                </Badge>
              )}
              <Button
                variant="default"
                size="sm"
                onClick={() => setActiveTab('evidence')}
                className="bg-cyan hover:bg-cyan/80 text-background font-semibold"
              >
                <Upload className="h-4 w-4 mr-1" />
                Upload Evidence
              </Button>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="max-w-[1800px] mx-auto px-4">
          <nav className="flex gap-1 overflow-x-auto scrollbar-forensic pb-0">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    relative flex items-center gap-2 px-3 py-2.5 text-xs font-medium whitespace-nowrap transition-all
                    rounded-t-lg
                    ${isActive
                      ? 'text-foreground bg-card border border-border border-b-transparent'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/30'
                    }
                    ${tab.isSpecial && isActive ? 'text-cyan' : ''}
                  `}
                >
                  <Icon className={`h-3.5 w-3.5 ${tab.isSpecial && isActive ? 'text-cyan' : ''}`} />
                  <span>{tab.label}</span>
                  {tab.isSpecial && (
                    <span className="hidden sm:inline text-[9px] px-1 py-0 rounded bg-cyan/10 text-cyan font-mono">
                      {tab.id === 'rewind' ? 'LIVE' : tab.id === 'ai' ? 'AI' : tab.id === 'evidence' ? 'NEW' : ''}
                    </span>
                  )}
                  {isActive && (
                    <motion.div
                      layoutId="activeTab"
                      className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan"
                      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                    />
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-[1800px] w-full mx-auto p-4 overflow-hidden">
        {activeTab === 'evidence' ? (
          <EvidenceUpload onAnalysisComplete={handleAnalysisComplete} />
        ) : loading && !data ? (
          <div className="space-y-6">
            <DashboardSkeleton />
            <div className="flex items-center justify-center py-8">
              <div className="text-center">
                <Loader2 className="h-8 w-8 text-cyan animate-spin mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">Analyzing evidence files...</p>
                <p className="text-xs text-muted-foreground font-mono mt-1">
                  Processing evidence items and reconstructing timeline
                </p>
              </div>
            </div>
          </div>
        ) : !data ? (
          <div className="flex items-center justify-center h-[70vh]">
            <div className="text-center">
              <Shield className="h-16 w-16 text-cyan/20 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-foreground mb-2">No Evidence Uploaded</h2>
              <p className="text-sm text-muted-foreground mb-4">
                Go to the <strong>Evidence</strong> tab to upload and analyze forensic files
              </p>
              <Button
                onClick={() => setActiveTab('evidence')}
                className="bg-cyan hover:bg-cyan/80 text-background"
              >
                <Upload className="h-4 w-4 mr-2" />
                Upload Evidence
              </Button>
            </div>
          </div>
        ) : (
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              variants={tabVariants}
              initial="enter"
              animate="center"
              exit="exit"
              transition={{ duration: 0.2 }}
              className="h-full"
            >
              {activeTab === 'dashboard' && <Dashboard data={data} />}
              {activeTab === 'timeline' && <TimelineView events={data.timeline} />}
              {activeTab === 'rewind' && <RewindPlayer events={data.rewindSequence} />}
              {activeTab === 'graph' && <EntityGraph graph={data.correlations} />}
              {activeTab === 'findings' && <SuspiciousPanel findings={data.suspiciousFindings} />}
              {activeTab === 'search' && <KeywordSearch results={data?.keywordResults || []} />}
              {activeTab === 'ai' && <AIInvestigator data={data} />}
              {activeTab === 'reports' && <ReportGenerator data={data} />}
            </motion.div>
          </AnimatePresence>
        )}
      </main>
    </div>
  );
}
