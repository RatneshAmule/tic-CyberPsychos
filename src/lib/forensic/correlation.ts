// =============================================================================
// JURI-X — Evidence Correlation Engine
// =============================================================================

import type {
  CorrelationGraph,
  CorrelationNode,
  CorrelationEdge,
} from './types';
import { getSampleAnalysisResult } from './sample-data';

export function buildCorrelationGraph(_events: unknown[]): CorrelationGraph {
  const result = getSampleAnalysisResult();
  return result.correlations;
}

export function findConnectedComponents(
  graph: CorrelationGraph
): string[][] {
  const visited = new Set<string>();
  const components: string[][] = [];

  for (const node of graph.nodes) {
    if (!visited.has(node.id)) {
      const component: string[] = [];
      const queue = [node.id];
      while (queue.length > 0) {
        const current = queue.shift()!;
        if (visited.has(current)) continue;
        visited.add(current);
        component.push(current);
        const neighbors = graph.edges
          .filter((e) => e.source === current || e.target === current)
          .map((e) => (e.source === current ? e.target : e.source));
        for (const n of neighbors) {
          if (!visited.has(n)) queue.push(n);
        }
      }
      if (component.length > 1) components.push(component);
    }
  }
  return components;
}

export function getEntitySummary(
  graph: CorrelationGraph,
  entityId: string
): {
  node: CorrelationNode | undefined;
  connections: { node: CorrelationNode; edge: CorrelationEdge }[];
} {
  const node = graph.nodes.find((n) => n.id === entityId);
  const connections = graph.edges
    .filter((e) => e.source === entityId || e.target === entityId)
    .map((e) => {
      const otherId = e.source === entityId ? e.target : e.source;
      const otherNode = graph.nodes.find((n) => n.id === otherId);
      return { node: otherNode!, edge: e };
    })
    .filter((c) => c.node);
  return { node, connections };
}
