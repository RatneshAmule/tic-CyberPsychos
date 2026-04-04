'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { Search, X, FileText, Hash, Key } from 'lucide-react';
import type { KeywordResult } from '@/lib/forensic/types';

interface KeywordSearchProps {
  results: KeywordResult[];
}

const QUICK_KEYWORDS = ['password', 'admin', 'bitcoin', '.onion', 'confidential', 'secret', 'encrypt'];

export default function KeywordSearch({ results }: KeywordSearchProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedKeywords, setExpandedKeywords] = useState<Set<string>>(new Set());
  const [activeKeywords, setActiveKeywords] = useState<Set<string>>(new Set());

  const safeResults = useMemo(() => results || [], [results]);

  const allKeywords = useMemo(
    () => safeResults.map((r) => r.keyword),
    [safeResults]
  );

  const filteredResults = useMemo(() => {
    let filtered = safeResults;

    if (activeKeywords.size > 0) {
      filtered = filtered.filter((r) => activeKeywords.has(r.keyword));
    }

    if (searchQuery.trim()) {
      const customKeyword = searchQuery.trim().toLowerCase();
      const customResult = safeResults.find(
        (r) => r.keyword.toLowerCase() === customKeyword
      );
      if (customResult && !activeKeywords.has(customKeyword)) {
        filtered = [customResult];
      } else if (!customResult) {
        filtered = safeResults.filter((r) =>
          (r.matches || []).some(
            (m) =>
              (m.file || '').toLowerCase().includes(customKeyword) ||
              (m.context || '').toLowerCase().includes(customKeyword)
          )
        );
      }
    }

    return filtered;
  }, [safeResults, activeKeywords, searchQuery]);

  const totalFilteredMatches = useMemo(
    () => filteredResults.reduce((sum, r) => sum + (r.totalMatches || 0), 0),
    [filteredResults]
  );

  const toggleKeyword = (kw: string) => {
    setActiveKeywords((prev) => {
      const next = new Set(prev);
      if (next.has(kw)) next.delete(kw);
      else next.add(kw);
      return next;
    });
  };

  const toggleExpanded = (kw: string) => {
    setExpandedKeywords((prev) => {
      const next = new Set(prev);
      if (next.has(kw)) next.delete(kw);
      else next.add(kw);
      return next;
    });
  };

  const handleSearch = () => {
    if (searchQuery.trim()) {
      setActiveKeywords(new Set([searchQuery.trim().toLowerCase()]));
    }
  };

  return (
    <div className="space-y-4">
      {/* Search Input */}
      <Card className="forensic-card">
        <CardContent className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <Key className="h-4 w-4 text-cyan" />
            <h3 className="text-sm font-semibold text-foreground">Keyword Intelligence</h3>
            <Badge variant="secondary" className="font-mono text-xs ml-auto">
              {totalFilteredMatches} matches
            </Badge>
          </div>

          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search keywords..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                className="pl-9 bg-muted/50 border-border/50 font-mono text-sm"
              />
            </div>
            <Button
              variant="default"
              size="sm"
              onClick={handleSearch}
              className="bg-cyan hover:bg-cyan/80 text-background"
            >
              Search
            </Button>
            {searchQuery && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSearchQuery('');
                  setActiveKeywords(new Set());
                }}
              >
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>

          {/* Quick Keywords */}
          <div className="mt-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
              Quick Search
            </p>
            <div className="flex flex-wrap gap-1.5">
              {QUICK_KEYWORDS.filter((kw) => allKeywords.includes(kw)).map((kw) => {
                const result = safeResults.find((r) => r.keyword === kw);
                const isActive = activeKeywords.has(kw);
                return (
                  <Button
                    key={kw}
                    variant={isActive ? 'default' : 'secondary'}
                    size="sm"
                    className={`h-6 text-xs font-mono ${isActive ? 'bg-cyan text-background' : ''}`}
                    onClick={() => toggleKeyword(kw)}
                  >
                    <Hash className="h-3 w-3 mr-1" />
                    {kw}
                    {result && (
                      <Badge
                        variant="secondary"
                        className={`ml-1 h-4 px-1 text-[10px] ${isActive ? 'bg-background/20 text-background' : ''}`}
                      >
                        {result.totalMatches}
                      </Badge>
                    )}
                  </Button>
                );
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <ScrollArea className="h-[calc(100vh-360px)] scrollbar-forensic">
        <div className="space-y-3 pr-4">
          {filteredResults.map((result) => {
            const isExpanded = expandedKeywords.has(result.keyword);

            return (
              <Collapsible
                key={result.keyword}
                open={isExpanded}
                onOpenChange={() => toggleExpanded(result.keyword)}
              >
                <Card className="forensic-card cursor-pointer">
                  <CollapsibleTrigger className="w-full text-left">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Hash className="h-4 w-4 text-cyan" />
                          <span className="text-sm font-semibold text-foreground font-mono">
                            {result.keyword}
                          </span>
                          <Badge variant="secondary" className="font-mono text-xs">
                            {result.totalMatches} match{result.totalMatches !== 1 ? 'es' : ''}
                          </Badge>
                        </div>
                        <svg
                          className={`h-4 w-4 text-muted-foreground transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                        >
                          <path d="M6 9l6 6 6-6" />
                        </svg>
                      </div>
                    </CardContent>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <CardContent className="pt-0 pb-4 px-4">
                      <div className="space-y-2 border-t border-border/50 pt-3">
                        {result.matches.map((match, idx) => {
                          const kw = result.keyword;
                          const contextParts = match.context.split(
                            new RegExp(`(${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
                          );

                          return (
                            <div
                              key={idx}
                              className="p-2 rounded-lg bg-muted/30 border border-border/30"
                            >
                              <div className="flex items-center gap-2 mb-1">
                                <FileText className="h-3 w-3 text-muted-foreground shrink-0" />
                                <span className="text-xs font-mono text-cyan truncate flex-1">
                                  {match.file}
                                </span>
                                {match.line > 0 && (
                                  <Badge variant="secondary" className="text-[10px] font-mono shrink-0">
                                    Line {match.line}
                                  </Badge>
                                )}
                                <Badge variant="outline" className="text-[10px] shrink-0">
                                  {match.source}
                                </Badge>
                              </div>
                              <p className="text-xs text-foreground/80 font-mono leading-relaxed break-all">
                                {contextParts.map((part, i) =>
                                  i % 2 === 1 ? (
                                    <mark key={i} className="bg-cyan/20 text-cyan px-0.5 rounded">
                                      {part}
                                    </mark>
                                  ) : (
                                    <span key={i}>{part}</span>
                                  )
                                )}
                              </p>
                            </div>
                          );
                        })}
                      </div>
                    </CardContent>
                  </CollapsibleContent>
                </Card>
              </Collapsible>
            );
          })}

          {filteredResults.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No keyword matches found</p>
              <p className="text-xs mt-1">Try selecting a quick keyword or enter a custom search</p>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
