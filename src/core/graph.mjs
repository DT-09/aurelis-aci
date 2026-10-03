export function buildGraph(records=[]) {
  const nodes = new Map(); const edges=[];
  for (const r of records) {
    if (!nodes.has(r.fromId)) nodes.set(r.fromId,{id:r.fromId,label:r.fromLabel,type:r.fromType});
    if (!nodes.has(r.toId)) nodes.set(r.toId,{id:r.toId,label:r.toLabel,type:r.toType});
    edges.push({from:r.fromId,to:r.toId,relationship:r.relationship});
  }
  return { nodes:[...nodes.values()], edges };
}

export function blastRadius(graph, rootId) {
  const seen=new Set([rootId]); const queue=[rootId];
  while(queue.length){ const id=queue.shift(); for(const e of graph.edges){ if(e.from===id&&!seen.has(e.to)){seen.add(e.to);queue.push(e.to);} if(e.to===id&&!seen.has(e.from)){seen.add(e.from);queue.push(e.from);} } }
  return [...seen];
}
