'use client';

import { useState, useMemo, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ZoomIn, ZoomOut, Maximize2, Info } from 'lucide-react';
import { motion } from 'framer-motion';
import type { CorrelationGraph, CorrelationNode, SeverityLevel } from '@/lib/forensic/types';

interface EntityGraphProps {
  graph: CorrelationGraph;
}

const SEVERITY_BORDER_COLORS: Record<string, string> = {
  critical: '#ef4444',
  highly_suspicious: '#f97316',
  suspicious: '#f59e0b',
  benign: '#22c55e',
};

const NODE_TYPE_COLORS: Record<string, string> = {
  file: '#6366f1',
  process: '#f97316',
  user: '#22c55e',
  ip: '#ef4444',
  domain: '#8b5cf6',
  url: '#06b6d4',
  hash: '#6b7280',
  registry: '#d97706',
  artifact: '#ec4899',
};

interface NodePosition {
  x: number;
  y: number;
  node: CorrelationNode;
}

function calculateLayout(nodes: CorrelationNode[]): NodePosition[] {
  const positions: NodePosition[] = [];
  const centerX = 400;
  const centerY = 300;
  const radius = 220;
  const nodeCount = nodes.length;

  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / nodeCount - Math.PI / 2;
    const jitterX = (Math.sin(i * 137.508) * 30);
    const jitterY = (Math.cos(i * 137.508 * 1.3) * 25);
    positions.push({
      x: centerX + radius * Math.cos(angle) + jitterX,
      y: centerY + radius * Math.sin(angle) + jitterY,
      node,
    });
  });

  return positions;
}

function getNodeShape(type: string): string {
  switch (type) {
    case 'file': return 'rect';
    case 'process': return 'hex';
    case 'user': return 'circle';
    case 'ip': return 'diamond';
    case 'domain': return 'rounded';
    case 'url': return 'rect';
    case 'hash': return 'oct';
    case 'registry': return 'pent';
    case 'artifact': return 'star';
    default: return 'circle';
  }
}

function renderShape(type: string, x: number, y: number, size: number, fill: string, stroke: string, strokeWidth: number) {
  const shape = getNodeShape(type);
  const half = size / 2;

  switch (shape) {
    case 'circle':
      return <circle cx={x} cy={y} r={half} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    case 'rect':
      return <rect x={x - half} y={y - half * 0.7} width={size} height={size * 0.7} rx={3} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    case 'rounded':
      return <rect x={x - half} y={y - half * 0.7} width={size} height={size * 0.7} rx={10} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    case 'diamond':
      return <polygon points={`${x},${y - half} ${x + half},${y} ${x},${y + half} ${x - half},${y}`} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    case 'hex': {
      const pts = Array.from({ length: 6 }, (_, i) => {
        const angle = (Math.PI / 3) * i - Math.PI / 6;
        return `${x + half * Math.cos(angle)},${y + half * Math.sin(angle)}`;
      }).join(' ');
      return <polygon points={pts} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    }
    case 'pent': {
      const pts = Array.from({ length: 5 }, (_, i) => {
        const angle = (2 * Math.PI * i) / 5 - Math.PI / 2;
        return `${x + half * Math.cos(angle)},${y + half * Math.sin(angle)}`;
      }).join(' ');
      return <polygon points={pts} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    }
    case 'oct': {
      const pts = Array.from({ length: 8 }, (_, i) => {
        const angle = (Math.PI / 4) * i;
        return `${x + half * Math.cos(angle)},${y + half * Math.sin(angle)}`;
      }).join(' ');
      return <polygon points={pts} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    }
    case 'star': {
      const pts: string[] = [];
      for (let i = 0; i < 10; i++) {
        const r = i % 2 === 0 ? half : half * 0.5;
        const angle = (Math.PI / 5) * i - Math.PI / 2;
        pts.push(`${x + r * Math.cos(angle)},${y + r * Math.sin(angle)}`);
      }
      return <polygon points={pts.join(' ')} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
    }
    default:
      return <circle cx={x} cy={y} r={half} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />;
  }
}

export default function EntityGraph({ graph }: EntityGraphProps) {
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const positions = useMemo(() => calculateLayout(graph.nodes), [graph.nodes]);

  const connectedNodes = useMemo(() => {
    if (!selectedNode) return new Set<string>();
    const connected = new Set<string>();
    connected.add(selectedNode);
    graph.edges.forEach((edge) => {
      if (edge.source === selectedNode) connected.add(edge.target);
      if (edge.target === selectedNode) connected.add(edge.source);
    });
    return connected;
  }, [selectedNode, graph.edges]);

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNode((prev) => (prev === nodeId ? null : nodeId));
  }, []);

  const relevantEdges = useMemo(() => {
    if (!selectedNode) return graph.edges;
    return graph.edges.filter(
      (e) => e.source === selectedNode || e.target === selectedNode
    );
  }, [selectedNode, graph.edges]);

  const positionMap = useMemo(() => {
    const map = new Map<string, NodePosition>();
    positions.forEach((p) => map.set(p.node.id, p));
    return map;
  }, [positions]);

  const selectedNodeData = useMemo(
    () => graph.nodes.find((n) => n.id === selectedNode),
    [graph.nodes, selectedNode]
  );

  const edgeCount = useMemo(
    () => (selectedNode ? relevantEdges.length : graph.edges.length),
    [selectedNode, relevantEdges, graph.edges]
  );

  return (
    <div className="space-y-4">
      {/* Controls */}
      <Card className="forensic-card">
        <CardContent className="p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h3 className="text-sm font-semibold text-foreground">Entity Correlation Graph</h3>
              <Badge variant="secondary" className="font-mono text-xs">
                {graph.nodes.length} nodes
              </Badge>
              <Badge variant="secondary" className="font-mono text-xs">
                {edgeCount} edges
              </Badge>
            </div>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => setZoom((z) => Math.min(z + 0.2, 2))}
              >
                <ZoomIn className="h-3.5 w-3.5" />
              </Button>
              <span className="text-xs font-mono text-muted-foreground w-12 text-center">
                {(zoom * 100).toFixed(0)}%
              </span>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => setZoom((z) => Math.max(z - 0.2, 0.5))}
              >
                <ZoomOut className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => {
                  setZoom(1);
                  setSelectedNode(null);
                }}
              >
                <Maximize2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>

          {/* Legend */}
          <div className="flex flex-wrap gap-3 mt-2">
            {Object.entries(NODE_TYPE_COLORS).map(([type, color]) => (
              <div key={type} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
                <span className="capitalize">{type}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Graph */}
      <div className="flex gap-4">
        <Card className="forensic-card flex-1 overflow-hidden">
          <CardContent className="p-0">
            <div className="overflow-auto scrollbar-forensic" style={{ maxHeight: 'calc(100vh - 380px)' }}>
              <svg
                width={800 * zoom}
                height={600 * zoom}
                viewBox="0 0 800 600"
                className="select-none"
              >
                <defs>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                    <feMerge>
                      <feMergeNode in="coloredBlur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                  <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" fill="#334155" />
                  </marker>
                </defs>

                {/* Edges */}
                {relevantEdges.map((edge, idx) => {
                  const source = positionMap.get(edge.source);
                  const target = positionMap.get(edge.target);
                  if (!source || !target) return null;

                  const isSelected = selectedNode !== null;
                  const opacity = isSelected ? 0.9 : 0.3;
                  const weight = Math.max(1, edge.weight * 3);

                  return (
                    <g key={`edge-${idx}`}>
                      <line
                        x1={source.x}
                        y1={source.y}
                        x2={target.x}
                        y2={target.y}
                        stroke={isSelected ? '#06b6d4' : '#334155'}
                        strokeWidth={weight}
                        strokeOpacity={opacity}
                        markerEnd="url(#arrowhead)"
                      />
                      {/* Edge label */}
                      <text
                        x={(source.x + target.x) / 2}
                        y={(source.y + target.y) / 2 - 6}
                        fill={isSelected ? '#06b6d4' : '#475569'}
                        fontSize="9"
                        textAnchor="middle"
                        fontFamily="monospace"
                        opacity={opacity}
                      >
                        {edge.relation}
                      </text>
                    </g>
                  );
                })}

                {/* Nodes */}
                {positions.map(({ x, y, node }) => {
                  const isHovered = hoveredNode === node.id;
                  const isSelected = selectedNode === node.id;
                  const isConnected = connectedNodes.has(node.id);
                  const isDimmed = selectedNode && !isConnected;
                  const size = isSelected ? 44 : isHovered ? 40 : 36;
                  const color = NODE_TYPE_COLORS[node.type] || '#64748b';
                  const severityBorder = node.severity ? SEVERITY_BORDER_COLORS[node.severity] : null;
                  const stroke = severityBorder || color;
                  const strokeWidth = isSelected ? 3 : isHovered ? 2.5 : 1.5;

                  return (
                    <g
                      key={node.id}
                      style={{
                        cursor: 'pointer',
                        opacity: isDimmed ? 0.2 : 1,
                        transition: 'opacity 0.2s',
                      }}
                      onClick={() => handleNodeClick(node.id)}
                      onMouseEnter={() => setHoveredNode(node.id)}
                      onMouseLeave={() => setHoveredNode(null)}
                    >
                      {/* Glow for selected */}
                      {isSelected && (
                        <motion.g
                          initial={{ opacity: 0 }}
                          animate={{ opacity: [0.3, 0.6, 0.3] }}
                          transition={{ duration: 2, repeat: Infinity }}
                        >
                          {renderShape(node.type, x, y, size + 12, 'none', '#06b6d4', 1)}
                        </motion.g>
                      )}

                      {renderShape(node.type, x, y, size, `${color}30`, stroke, strokeWidth)}

                      {/* Label */}
                      <text
                        x={x}
                        y={y + size / 2 + 14}
                        fill={isDimmed ? '#334155' : '#94a3b8'}
                        fontSize="10"
                        textAnchor="middle"
                        fontFamily="monospace"
                        fontWeight={isSelected ? 'bold' : 'normal'}
                      >
                        {node.label.length > 22 ? node.label.slice(0, 20) + '...' : node.label}
                      </text>

                      {/* Severity indicator */}
                      {node.severity && node.severity !== 'benign' && (
                        <circle
                          cx={x + size / 2 - 2}
                          cy={y - size / 2 + 2}
                          r="4"
                          fill={SEVERITY_BORDER_COLORS[node.severity]}
                        />
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>
          </CardContent>
        </Card>

        {/* Node Details */}
        {selectedNodeData && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="w-full lg:w-[300px] shrink-0"
          >
            <Card className="forensic-card forensic-glow sticky top-4">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <div
                    className="w-3 h-3 rounded-sm"
                    style={{ backgroundColor: NODE_TYPE_COLORS[selectedNodeData.type] }}
                  />
                  <h3 className="text-sm font-semibold text-foreground capitalize">{selectedNodeData.type}</h3>
                  {selectedNodeData.severity && (
                    <Badge
                      variant="outline"
                      className="text-[10px] ml-auto"
                      style={{
                        borderColor: SEVERITY_BORDER_COLORS[selectedNodeData.severity],
                        color: SEVERITY_BORDER_COLORS[selectedNodeData.severity],
                      }}
                    >
                      {selectedNodeData.severity.replace(/_/g, ' ')}
                    </Badge>
                  )}
                </div>

                <p className="text-sm font-mono text-cyan mb-3 break-all">{selectedNodeData.label}</p>

                <div className="space-y-1.5">
                  {Object.entries(selectedNodeData.properties).map(([key, value]) => (
                    <div key={key} className="flex justify-between text-xs">
                      <span className="text-muted-foreground capitalize">{key}:</span>
                      <span className="text-foreground font-mono text-right max-w-[180px] truncate">
                        {String(value)}
                      </span>
                    </div>
                  ))}
                </div>

                {/* Connections */}
                <div className="mt-3 pt-3 border-t border-border/50">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
                    Connections
                  </p>
                  {graph.edges
                    .filter((e) => e.source === selectedNode || e.target === selectedNode)
                    .map((edge, idx) => {
                      const otherId = edge.source === selectedNode ? edge.target : edge.source;
                      const otherNode = graph.nodes.find((n) => n.id === otherId);
                      return (
                        <div key={idx} className="flex items-center gap-2 text-xs mb-1">
                          <div
                            className="w-2 h-2 rounded-full shrink-0"
                            style={{ backgroundColor: otherNode ? NODE_TYPE_COLORS[otherNode.type] : '#64748b' }}
                          />
                          <span className="text-foreground truncate flex-1">
                            {otherNode?.label || otherId}
                          </span>
                          <span className="text-muted-foreground text-[10px] font-mono shrink-0">
                            {edge.relation}
                          </span>
                        </div>
                      );
                    })}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </div>
    </div>
  );
}
