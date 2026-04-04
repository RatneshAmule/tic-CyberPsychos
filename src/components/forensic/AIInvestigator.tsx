'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Bot,
  Send,
  Loader2,
  Settings,
  Trash2,
  Sparkles,
  AlertTriangle,
  Shield,
  FileSearch,
  Globe,
  Cpu,
  X,
  Save,
  RotateCcw,
  Eye,
  EyeOff,
  ChevronDown,
  Zap,
  Copy,
  Check,
} from 'lucide-react';
import type { AnalysisResult } from '@/lib/forensic/types';

interface AISettings {
  model: string;
  apiUrl: string;
  maxTokens: number;
  temperature: number;
  topP: number;
  stream: boolean;
  maskedApiKey: string;
  isConfigured: boolean;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}

interface AIInvestigatorProps {
  data: AnalysisResult | null;
}

const QUICK_PROMPTS = [
  { label: 'Analyze Timeline', prompt: 'Analyze the forensic timeline and identify the most suspicious sequence of events. What patterns do you see?', icon: AlertTriangle },
  { label: 'Threat Assessment', prompt: 'Based on the forensic evidence, provide a comprehensive threat assessment. What is the threat level and what type of attack or insider threat does this suggest?', icon: Shield },
  { label: 'IOC Extraction', prompt: 'Extract all Indicators of Compromise (IOCs) from the available evidence — IPs, domains, file hashes, emails, and URLs. Format them in a structured list.', icon: FileSearch },
  { label: 'Kill Chain', prompt: 'Map the detected activities to the MITRE ATT&CK kill chain framework. Identify which stages of the attack lifecycle are present in the evidence.', icon: Globe },
  { label: 'Anti-Forensics', prompt: 'Analyze the evidence for signs of anti-forensics techniques — secure deletion, encryption, history cleaning, artifact manipulation. What tools and methods appear to have been used?', icon: Cpu },
];

const SUGGESTED_MODELS = [
  { value: 'moonshotai/kimi-k2.5', label: 'Kimi K2.5' },
  { value: 'nvidia/llama-3.1-nemotron-70b-instruct', label: 'Llama 3.1 70B' },
  { value: 'mistralai/mixtral-8x22b-instruct-v0.1', label: 'Mixtral 8x22B' },
  { value: 'google/gemma-2-27b-it', label: 'Gemma 2 27B' },
  { value: 'microsoft/phi-3-medium-128k-instruct', label: 'Phi-3 Medium' },
  { value: 'qwen/qwen2.5-72b-instruct', label: 'Qwen 2.5 72B' },
];

export default function AIInvestigator({ data }: AIInvestigatorProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [settings, setSettings] = useState<AISettings | null>(null);
  const [settingsForm, setSettingsForm] = useState({
    apiKey: '',
    model: 'moonshotai/kimi-k2.5',
    apiUrl: 'https://integrate.api.nvidia.com/v1/chat/completions',
    maxTokens: 16384,
    temperature: 1.0,
    topP: 1.0,
    stream: true,
  });
  const [showApiKey, setShowApiKey] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Fetch AI settings on mount
  useEffect(() => {
    fetchSettings();
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const fetchSettings = async () => {
    try {
      const res = await fetch('/api/forensic/ai-settings');
      if (res.ok) {
        const data = await res.json();
        setSettings(data);
        setSettingsForm((prev) => ({
          ...prev,
          model: data.model || prev.model,
          apiUrl: data.apiUrl || prev.apiUrl,
          maxTokens: data.maxTokens || prev.maxTokens,
          temperature: data.temperature ?? prev.temperature,
          topP: data.topP ?? prev.topP,
          stream: data.stream ?? prev.stream,
        }));
      }
    } catch (err) {
      console.error('Failed to fetch AI settings:', err);
    }
  };

  const saveSettings = async () => {
    try {
      const res = await fetch('/api/forensic/ai-settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settingsForm),
      });
      if (res.ok) {
        await fetchSettings();
        setShowSettings(false);
      }
    } catch (err) {
      console.error('Failed to save AI settings:', err);
    }
  };

  const resetSettings = async () => {
    try {
      const res = await fetch('/api/forensic/ai-settings', { method: 'DELETE' });
      if (res.ok) {
        await fetchSettings();
        setSettingsForm({
          apiKey: '',
          model: 'moonshotai/kimi-k2.5',
          apiUrl: 'https://integrate.api.nvidia.com/v1/chat/completions',
          maxTokens: 16384,
          temperature: 1.0,
          topP: 1.0,
          stream: true,
        });
      }
    } catch (err) {
      console.error('Failed to reset AI settings:', err);
    }
  };

  const buildContextMessage = useCallback(() => {
    if (!data) return '';
    const criticalFindings = data.suspiciousFindings
      .filter((f) => f.severity === 'critical' || f.severity === 'highly_suspicious')
      .map((f) => `[${f.severity.toUpperCase()}] ${f.title}: ${f.description}`)
      .join('\n');

    const timelineSummary = data.timeline.slice(0, 20)
      .map((e) => `[${e.timestamp}] ${e.action}: ${e.entity} — ${e.description}`)
      .join('\n');

    const iocs = data.geoIPResults.map((g) => `IP: ${g.ip} (${g.country}, ${g.city})`).join('\n');

    const keywords = data.keywordResults
      .map((kr) => `"${kr.keyword}": ${kr.totalMatches} matches in ${kr.matches.length} files`)
      .join('\n');

    return `CURRENT CASE CONTEXT (Case: ${data.caseInfo.name}, ID: ${data.caseInfo.id}):
${data.caseInfo.description}

EVIDENCE ITEMS (${data.evidence.length}):
${data.evidence.map((e) => `- ${e.name} (${e.type}, ${(e.size / 1024 / 1024).toFixed(1)}MB, hash: ${e.hash})`).join('\n')}

STATISTICS: ${data.stats.totalEvents} events, ${data.stats.criticalCount} critical, ${data.stats.suspiciousCount} suspicious
TIME RANGE: ${data.stats.timeRange.start} to ${data.stats.timeRange.end}

KEY SUSPICIOUS FINDINGS:
${criticalFindings || 'No critical/highly suspicious findings detected.'}

RECENT TIMELINE EVENTS (first 20 of ${data.timeline.length}):
${timelineSummary}

GEO-IP LOCATIONS:
${iocs || 'No geo-IP data.'}

KEYWORD HITS:
${keywords || 'No keyword matches.'}`;
  }, [data]);

  const sendMessage = async (messageText: string) => {
    if (!messageText.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: messageText.trim(),
      timestamp: Date.now(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    // Build messages array for API
    const contextMsg = buildContextMessage();
    const apiMessages: { role: string; content: string }[] = [];

    // Add context if available
    if (contextMsg) {
      apiMessages.push({
        role: 'user',
        content: `[FORENSIC DATA PROVIDED — analyze the following case context]\n\n${contextMsg}`,
      });
      apiMessages.push({
        role: 'assistant',
        content: 'I have received the forensic case data. I can see the case details, evidence items, timeline events, suspicious findings, and other forensic artifacts. I am ready to analyze this data. Please ask me any questions about the investigation.',
      });
    }

    // Add chat history (last 10 messages for context window)
    const history = [...messages, userMsg].slice(-10);
    for (const msg of history) {
      apiMessages.push({ role: msg.role, content: msg.content });
    }

    // Add the current message if not already in history
    if (history[history.length - 1]?.id !== userMsg.id) {
      apiMessages.push({ role: 'user', content: messageText.trim() });
    }

    try {
      abortRef.current = new AbortController();

      if (settingsForm.stream) {
        // Streaming mode
        const res = await fetch('/api/forensic/ai', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            messages: apiMessages,
            apiKey: settingsForm.apiKey || undefined,
            model: settingsForm.model,
            stream: true,
          }),
          signal: abortRef.current.signal,
        });

        if (!res.ok) {
          const errData = await res.json();
          const assistantMsg: ChatMessage = {
            id: `msg-err-${Date.now()}`,
            role: 'assistant',
            content: `Error: ${errData.error || 'Failed to get AI response. Check your API key in Settings.'}`,
            timestamp: Date.now(),
          };
          setMessages((prev) => [...prev, assistantMsg]);
          setIsLoading(false);
          return;
        }

        // Process SSE stream
        const reader = res.body?.getReader();
        const decoder = new TextDecoder();
        let fullContent = '';
        const assistantMsgId = `msg-${Date.now()}`;

        // Add empty assistant message
        setMessages((prev) => [
          ...prev,
          { id: assistantMsgId, role: 'assistant', content: '...', timestamp: Date.now() },
        ]);

        if (reader) {
          let buffer = '';
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const dataStr = line.substring(6).trim();
                if (dataStr === '[DONE]') continue;

                try {
                  const parsed = JSON.parse(dataStr);
                  const delta = parsed.choices?.[0]?.delta?.content || '';
                  if (delta) {
                    fullContent += delta;
                    setMessages((prev) =>
                      prev.map((m) =>
                        m.id === assistantMsgId ? { ...m, content: fullContent || '...' } : m
                      )
                    );
                  }
                } catch {
                  // Skip malformed JSON
                }
              }
            }
          }
        }

        // Update with final content
        setMessages((prev) =>
          prev.map((m) =>
            m.id === assistantMsgId ? { ...m, content: fullContent || 'No response received.' } : m
          )
        );
      } else {
        // Non-streaming mode
        const res = await fetch('/api/forensic/ai', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            messages: apiMessages,
            apiKey: settingsForm.apiKey || undefined,
            model: settingsForm.model,
            stream: false,
          }),
          signal: abortRef.current.signal,
        });

        const resData = await res.json();

        if (!res.ok) {
          const assistantMsg: ChatMessage = {
            id: `msg-err-${Date.now()}`,
            role: 'assistant',
            content: `Error: ${resData.error || 'Failed to get AI response.'}`,
            timestamp: Date.now(),
          };
          setMessages((prev) => [...prev, assistantMsg]);
        } else {
          const assistantMsg: ChatMessage = {
            id: `msg-${Date.now()}`,
            role: 'assistant',
            content: resData.message || 'No response received.',
            timestamp: Date.now(),
          };
          setMessages((prev) => [...prev, assistantMsg]);
        }
      }
    } catch (err: unknown) {
      const error = err as Error;
      if (error.name !== 'AbortError') {
        const assistantMsg: ChatMessage = {
          id: `msg-err-${Date.now()}`,
          role: 'assistant',
          content: `Request failed: ${error.message}`,
          timestamp: Date.now(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      }
    } finally {
      setIsLoading(false);
      abortRef.current = null;
    }
  };

  const handleStop = () => {
    abortRef.current?.abort();
    setIsLoading(false);
  };

  const handleClear = () => {
    setMessages([]);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  // Simple markdown-like rendering
  const renderContent = (content: string) => {
    const parts = content.split(/(\*\*.*?\*\*|`[^`]+`|```[\s\S]*?```|\n)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i} className="text-foreground font-semibold">{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`') && !part.startsWith('``')) {
        return (
          <code key={i} className="px-1 py-0.5 bg-muted/50 rounded text-cyan font-mono text-xs">
            {part.slice(1, -1)}
          </code>
        );
      }
      if (part.startsWith('```') && part.endsWith('```')) {
        const code = part.slice(3, -3).replace(/^\w+\n/, '');
        return (
          <pre key={i} className="my-2 p-3 bg-black/50 rounded-lg border border-border/50 overflow-x-auto">
            <code className="text-xs font-mono text-emerald-400">{code}</code>
          </pre>
        );
      }
      if (part === '\n') {
        return <br key={i} />;
      }
      // Highlight IOC patterns
      const iocParts = part.split(/((?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{32,}|https?:\/\/[^\s]+|\.onion|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi);
      return iocParts.map((sub, j) => {
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(sub)) {
          return <span key={`${i}-${j}`} className="text-red-400 font-mono">{sub}</span>;
        }
        if (/^[a-f0-9]{32,}$/.test(sub)) {
          return <span key={`${i}-${j}`} className="text-amber-400 font-mono text-[11px]">{sub}</span>;
        }
        if (/^https?:\/\//.test(sub) || /\.onion/.test(sub)) {
          return <span key={`${i}-${j}`} className="text-cyan font-mono underline">{sub}</span>;
        }
        if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(sub)) {
          return <span key={`${i}-${j}`} className="text-purple-400 font-mono">{sub}</span>;
        }
        return <span key={`${i}-${j}`}>{sub}</span>;
      });
    });
  };

  return (
    <div className="h-[calc(100vh-200px)] flex gap-3">
      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <Card className="forensic-card mb-3">
          <CardContent className="p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan/10">
                  <Bot className="h-5 w-5 text-cyan" />
                </div>
                <div>
                  <h2 className="text-sm font-bold text-foreground flex items-center gap-2">
                    AI Investigator
                    {settings?.isConfigured ? (
                      <Badge variant="outline" className="border-emerald-500/50 text-emerald-400 bg-emerald-500/10 text-[9px]">
                        CONNECTED
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="border-amber-500/50 text-amber-400 bg-amber-500/10 text-[9px]">
                        NO API KEY
                      </Badge>
                    )}
                  </h2>
                  <p className="text-[10px] text-muted-foreground font-mono">
                    {settings?.model || 'No model configured'} | {settings?.stream ? 'Streaming' : 'Standard'} mode
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleClear}
                  disabled={messages.length === 0}
                  className="h-7 text-xs text-muted-foreground"
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Clear
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowSettings(!showSettings)}
                  className="h-7 text-xs"
                >
                  <Settings className="h-3 w-3 mr-1" />
                  Settings
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Messages */}
        <Card className="forensic-card flex-1 flex flex-col overflow-hidden">
          <div ref={scrollRef} className="flex-1 overflow-y-auto scrollbar-forensic p-4 space-y-4">
            {messages.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center">
                <div className="p-4 rounded-full bg-cyan/5 mb-4">
                  <Sparkles className="h-10 w-10 text-cyan/50" />
                </div>
                <h3 className="text-lg font-bold text-foreground mb-2">JURI-X AI Investigator</h3>
                <p className="text-sm text-muted-foreground max-w-md mb-6">
                  Ask anything about your forensic case. The AI has access to your current case data, timeline, findings, and evidence details.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 w-full max-w-2xl">
                  {QUICK_PROMPTS.map((qp) => (
                    <button
                      key={qp.label}
                      onClick={() => sendMessage(qp.prompt)}
                      className="p-3 rounded-lg border border-border/50 bg-muted/20 hover:border-cyan/40 hover:bg-cyan/5 transition-all text-left group"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <qp.icon className="h-3.5 w-3.5 text-cyan/70 group-hover:text-cyan" />
                        <span className="text-xs font-semibold text-foreground">{qp.label}</span>
                      </div>
                      <p className="text-[10px] text-muted-foreground line-clamp-2">{qp.prompt}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {msg.role === 'assistant' && (
                  <div className="shrink-0 w-7 h-7 rounded-full bg-cyan/10 flex items-center justify-center mt-1">
                    <Bot className="h-4 w-4 text-cyan" />
                  </div>
                )}
                <div
                  className={`max-w-[85%] rounded-xl p-3 ${
                    msg.role === 'user'
                      ? 'bg-cyan/10 border border-cyan/30'
                      : 'bg-card border border-border/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono text-muted-foreground">
                      {msg.role === 'user' ? 'You' : 'JURI-X AI'}
                    </span>
                    <div className="flex items-center gap-1">
                      <span className="text-[9px] text-muted-foreground font-mono">
                        {new Date(msg.timestamp).toLocaleTimeString()}
                      </span>
                      {msg.role === 'assistant' && (
                        <button
                          onClick={() => copyToClipboard(msg.content, msg.id)}
                          className="p-0.5 hover:bg-muted/50 rounded"
                        >
                          {copiedId === msg.id ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3 text-muted-foreground" />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="text-sm text-foreground/90 leading-relaxed whitespace-pre-wrap">
                    {renderContent(msg.content)}
                  </div>
                </div>
                {msg.role === 'user' && (
                  <div className="shrink-0 w-7 h-7 rounded-full bg-emerald-500/10 flex items-center justify-center mt-1">
                    <Shield className="h-4 w-4 text-emerald-400" />
                  </div>
                )}
              </div>
            ))}

            {isLoading && (
              <div className="flex gap-3">
                <div className="shrink-0 w-7 h-7 rounded-full bg-cyan/10 flex items-center justify-center mt-1">
                  <Bot className="h-4 w-4 text-cyan animate-pulse" />
                </div>
                <div className="bg-card border border-border/50 rounded-xl p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Loader2 className="h-3 w-3 animate-spin text-cyan" />
                    <span>AI is analyzing...</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="p-3 border-t border-border/50">
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Input
                  ref={inputRef}
                  placeholder="Ask about your forensic case..."
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={isLoading}
                  className="pl-4 pr-4 bg-muted/30 border-border/50 font-mono text-sm h-10"
                />
              </div>
              {isLoading ? (
                <Button
                  variant="destructive"
                  size="icon"
                  onClick={handleStop}
                  className="h-10 w-10 shrink-0"
                >
                  <X className="h-4 w-4" />
                </Button>
              ) : (
                <Button
                  variant="default"
                  size="icon"
                  onClick={() => sendMessage(input)}
                  disabled={!input.trim()}
                  className="h-10 w-10 shrink-0 bg-cyan hover:bg-cyan/80 text-background"
                >
                  <Send className="h-4 w-4" />
                </Button>
              )}
            </div>
            <p className="text-[9px] text-muted-foreground mt-1.5 text-center">
              AI responses are generated using your configured NVIDIA model. Forensic data from the current case is automatically included as context.
            </p>
          </div>
        </Card>
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div className="w-[340px] shrink-0">
          <Card className="forensic-card h-full flex flex-col">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-bold text-foreground flex items-center gap-2">
                <Settings className="h-4 w-4 text-cyan" />
                AI Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 flex-1 overflow-y-auto scrollbar-forensic space-y-4">
              {/* API Key */}
              <div>
                <label className="text-xs text-muted-foreground mb-1.5 block">NVIDIA API Key</label>
                <div className="relative">
                  <Input
                    type={showApiKey ? 'text' : 'password'}
                    value={settingsForm.apiKey}
                    onChange={(e) => setSettingsForm((p) => ({ ...p, apiKey: e.target.value }))}
                    placeholder="nvapi-..."
                    className="pr-8 bg-muted/50 border-border/50 font-mono text-xs h-9"
                  />
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2"
                  >
                    {showApiKey ? (
                      <EyeOff className="h-3.5 w-3.5 text-muted-foreground" />
                    ) : (
                      <Eye className="h-3.5 w-3.5 text-muted-foreground" />
                    )}
                  </button>
                </div>
                {settings?.maskedApiKey && (
                  <p className="text-[10px] text-muted-foreground mt-1 font-mono">
                    Current: {settings.maskedApiKey}
                  </p>
                )}
                <p className="text-[9px] text-muted-foreground mt-1">
                  Get your key from build.nvidia.com
                </p>
              </div>

              {/* Model */}
              <div>
                <label className="text-xs text-muted-foreground mb-1.5 block">AI Model</label>
                <div className="relative">
                  <select
                    value={settingsForm.model}
                    onChange={(e) => setSettingsForm((p) => ({ ...p, model: e.target.value }))}
                    className="w-full h-9 px-3 bg-muted/50 border border-border/50 rounded-md text-xs font-mono text-foreground appearance-none cursor-pointer"
                  >
                    <optgroup label="NVIDIA NIM Models">
                      {SUGGESTED_MODELS.map((m) => (
                        <option key={m.value} value={m.value}>
                          {m.label} ({m.value.split('/').pop()})
                        </option>
                      ))}
                    </optgroup>
                  </select>
                  <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground pointer-events-none" />
                </div>
                <Input
                  value={settingsForm.model}
                  onChange={(e) => setSettingsForm((p) => ({ ...p, model: e.target.value }))}
                  placeholder="Or enter custom model path..."
                  className="mt-2 bg-muted/50 border-border/50 font-mono text-xs h-9"
                />
                <p className="text-[9px] text-muted-foreground mt-1">
                  Full model path e.g. moonshotai/kimi-k2.5
                </p>
              </div>

              {/* API URL */}
              <div>
                <label className="text-xs text-muted-foreground mb-1.5 block">API Endpoint</label>
                <Input
                  value={settingsForm.apiUrl}
                  onChange={(e) => setSettingsForm((p) => ({ ...p, apiUrl: e.target.value }))}
                  className="bg-muted/50 border-border/50 font-mono text-xs h-9"
                />
              </div>

              <Separator className="bg-border/50" />

              {/* Advanced Settings */}
              <div>
                <p className="text-xs font-semibold text-foreground mb-2">Advanced Parameters</p>

                <div className="space-y-3">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-[10px] text-muted-foreground">Max Tokens</label>
                      <span className="text-[10px] font-mono text-foreground">{settingsForm.maxTokens}</span>
                    </div>
                    <Input
                      type="number"
                      value={settingsForm.maxTokens}
                      onChange={(e) => setSettingsForm((p) => ({ ...p, maxTokens: parseInt(e.target.value) || 4096 }))}
                      className="bg-muted/50 border-border/50 font-mono text-xs h-8"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-[10px] text-muted-foreground">Temperature</label>
                      <span className="text-[10px] font-mono text-foreground">{settingsForm.temperature.toFixed(2)}</span>
                    </div>
                    <Input
                      type="range"
                      min={0}
                      max={2}
                      step={0.05}
                      value={settingsForm.temperature}
                      onChange={(e) => setSettingsForm((p) => ({ ...p, temperature: parseFloat(e.target.value) }))}
                      className="w-full accent-cyan"
                    />
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-[10px] text-muted-foreground">Top P</label>
                      <span className="text-[10px] font-mono text-foreground">{settingsForm.topP.toFixed(2)}</span>
                    </div>
                    <Input
                      type="range"
                      min={0}
                      max={1}
                      step={0.05}
                      value={settingsForm.topP}
                      onChange={(e) => setSettingsForm((p) => ({ ...p, topP: parseFloat(e.target.value) }))}
                      className="w-full accent-cyan"
                    />
                  </div>
                </div>
              </div>

              <Separator className="bg-border/50" />

              {/* Actions */}
              <div className="space-y-2">
                <Button
                  variant="default"
                  size="sm"
                  onClick={saveSettings}
                  className="w-full bg-cyan hover:bg-cyan/80 text-background h-9"
                >
                  <Save className="h-3.5 w-3.5 mr-1.5" />
                  Save Configuration
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={resetSettings}
                  className="w-full text-xs text-muted-foreground h-8"
                >
                  <RotateCcw className="h-3 w-3 mr-1.5" />
                  Reset to Defaults
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
