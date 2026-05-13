"use client";

import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import ReactFlow, {
  Background,
  Controls,
  Panel,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  MarkerType,
  EdgeProps,
  getBezierPath,
  Connection,
  Edge,
  Position,
  NodeProps,
  Handle
} from "reactflow";
import "reactflow/dist/style.css";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ShieldAlert, 
  Zap, 
  Target, 
  Share2, 
  Maximize2, 
  Settings2, 
  Brain,
  Search,
  Activity,
  Cpu,
  Database,
  Lock,
  RefreshCw,
  Play,
  Filter
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// --- Types ---

type RiskLevel = "low" | "medium" | "high" | "critical";
type NodeType = "asset" | "service" | "vulnerability" | "exploit" | "impact";

interface NodeData {
  label: string;
  type: NodeType;
  risk: RiskLevel;
  status?: "idle" | "scanning" | "compromised";
  description?: string;
}

interface CustomEdgeData {
  type?: "recon" | "vulnerability" | "exploit" | "exfiltration";
  active?: boolean;
}

// --- Custom Components ---

const RiskGlow = ({ level, active }: { level: RiskLevel; active?: boolean }) => {
  const colors = {
    low: "bg-blue-500/20 shadow-[0_0_15px_rgba(59,130,246,0.5)]",
    medium: "bg-yellow-500/20 shadow-[0_0_15px_rgba(234,179,8,0.5)]",
    high: "bg-orange-500/20 shadow-[0_0_15px_rgba(249,115,22,0.5)]",
    critical: "bg-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.6)] animate-pulse",
  };

  if (!active && level !== "critical") return null;

  return (
    <div className={cn(
      "absolute inset-[-4px] rounded-xl z-[-1] transition-all duration-500",
      colors[level]
    )} />
  );
};

const ImpactParticles = ({ active }: { active: boolean }) => {
  if (!active) return null;
  return (
    <div className="absolute inset-0 pointer-events-none">
      {[...Array(6)].map((_, i) => (
        <motion.div
          key={i}
          initial={{ scale: 0.5, opacity: 0, x: 0, y: 0 }}
          animate={{ 
            opacity: [0, 1, 0],
            x: [0, (i % 2 === 0 ? 40 : -40) * Math.random()],
            y: [0, -60 * Math.random()],
            scale: [0.5, 1, 0.5]
          }}
          transition={{ 
            duration: 2, 
            repeat: Infinity, 
            delay: i * 0.3,
            ease: "easeOut" 
          }}
          className="absolute top-1/2 left-1/2 w-1.5 h-1.5 bg-red-400 rounded-sm shadow-[0_0_8px_#f87171]"
        />
      ))}
    </div>
  );
};

const CustomNode = ({ data }: NodeProps<NodeData>) => {
  const isCritical = data.risk === "critical";
  const isCompromised = data.status === "compromised";

  const getIcon = () => {
    switch (data.type) {
      case "asset": return <Search className="w-4 h-4" />;
      case "service": return <Cpu className="w-4 h-4" />;
      case "vulnerability": return <ShieldAlert className="w-4 h-4" />;
      case "exploit": return <Target className="w-4 h-4" />;
      case "impact": return <Zap className="w-4 h-4" />;
    }
  };

  const getBorderColor = () => {
    if (isCompromised) return "border-red-500 animate-pulse";
    switch (data.risk) {
      case "critical": return "border-red-500/50";
      case "high": return "border-orange-500/50";
      case "medium": return "border-yellow-500/50";
      case "low": return "border-blue-500/50";
    }
  };

  return (
    <div className={cn(
      "relative group px-4 py-3 rounded-xl border bg-black/80 backdrop-blur-md transition-all duration-300 min-w-[170px]",
      getBorderColor(),
      isCompromised ? "shadow-[0_0_30px_rgba(239,68,68,0.4)] scale-105" : "hover:border-primary/50"
    )}>
      <Handle type="target" position={Position.Left} className="w-2 h-2 !bg-primary border-none" />
      
      <RiskGlow level={data.risk} active={isCompromised} />
      
      {data.type === "impact" && <ImpactParticles active={isCompromised} />}

      <div className="flex items-center gap-3">
        <div className={cn(
          "p-2.5 rounded-lg bg-white/5 border border-white/10 group-hover:bg-primary/10 group-hover:border-primary/20 transition-all duration-500",
          isCompromised && "text-red-500 border-red-500/50 bg-red-500/10 shadow-[0_0_15px_rgba(239,68,68,0.3)]"
        )}>
          {getIcon()}
        </div>
        <div>
          <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground mb-1 opacity-70">
            {data.type}
          </p>
          <p className="text-xs font-bold text-white tracking-tight leading-tight">{data.label}</p>
        </div>
      </div>

      {data.status === "scanning" && (
        <div className="absolute -top-1.5 -right-1.5">
          <span className="flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-primary"></span>
          </span>
        </div>
      )}

      <Handle type="source" position={Position.Right} className="w-2 h-2 !bg-primary border-none" />
    </div>
  );
};

const CustomEdge = ({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
}: EdgeProps<CustomEdgeData>) => {
  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const getPulseColor = () => {
    switch (data?.type) {
      case "recon": return "#3b82f6"; // blue
      case "vulnerability": return "#eab308"; // yellow
      case "exploit": return "#ef4444"; // red
      case "exfiltration": return "#f43f5e"; // bright red
      default: return "#00FF88";
    }
  };

  return (
    <>
      <path
        id={id}
        style={{
          ...style,
          strokeWidth: 2,
          stroke: data?.active ? getPulseColor() : "rgba(255,255,255,0.1)",
          transition: "stroke 0.5s ease",
        }}
        className="react-flow__edge-path"
        d={edgePath}
        markerEnd={markerEnd}
      />
      {data?.active && (
        <circle r="3" fill={getPulseColor()}>
          <animateMotion dur="2s" repeatCount="indefinite" path={edgePath} />
        </circle>
      )}
      {/* Additional particle layer for swarm agents */}
      <circle r="1.5" fill="#fff" opacity="0.6 shadow-[0_0_5px_#fff]">
        <animateMotion dur="4s" repeatCount="indefinite" path={edgePath} />
      </circle>
    </>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

const edgeTypes = {
  custom: CustomEdge,
};

// --- Initial Data ---

const initialNodes: any[] = [
  {
    id: "node-1",
    type: "custom",
    data: { label: "Public Gateway", type: "asset", risk: "low", status: "idle" },
    position: { x: 0, y: 150 },
  },
  {
    id: "node-2",
    type: "custom",
    data: { label: "Auth API v1", type: "service", risk: "medium", status: "idle" },
    position: { x: 250, y: 50 },
  },
  {
    id: "node-3",
    type: "custom",
    data: { label: "User Data Service", type: "service", risk: "medium", status: "idle" },
    position: { x: 250, y: 250 },
  },
  {
    id: "node-4",
    type: "custom",
    data: { label: "JWT NONE Algorithm", type: "vulnerability", risk: "critical", status: "idle" },
    position: { x: 500, y: 50 },
  },
  {
    id: "node-5",
    type: "custom",
    data: { label: "IDOR on /data", type: "vulnerability", risk: "high", status: "idle" },
    position: { x: 500, y: 250 },
  },
  {
    id: "node-6",
    type: "custom",
    data: { label: "Admin JWT Token", type: "exploit", risk: "critical", status: "idle" },
    position: { x: 750, y: 50 },
  },
  {
    id: "node-7",
    type: "custom",
    data: { label: "Database Exfiltration", type: "impact", risk: "critical", status: "idle" },
    position: { x: 1000, y: 150 },
  },
];

const initialEdges: Edge[] = [
  { id: "e1-2", source: "node-1", target: "node-2", type: "custom", data: { type: "recon", active: true } },
  { id: "e1-3", source: "node-1", target: "node-3", type: "custom", data: { type: "recon", active: true } },
  { id: "e2-4", source: "node-2", target: "node-4", type: "custom", data: { type: "vulnerability", active: false } },
  { id: "e3-5", source: "node-3", target: "node-5", type: "custom", data: { type: "vulnerability", active: false } },
  { id: "e4-6", source: "node-4", target: "node-6", type: "custom", data: { type: "exploit", active: false } },
  { id: "e6-7", source: "node-6", target: "node-7", type: "custom", data: { type: "exfiltration", active: false } },
  { id: "e5-7", source: "node-5", target: "node-7", type: "custom", data: { type: "exfiltration", active: false } },
];

// --- Auto-layout utility ---
function autoLayout(rawNodes: any[]): Record<string, { x: number; y: number }> {
  // Hierarchical layout: asset→service→vulnerability→exploit→impact
  const typeOrder: Record<string, number> = {
    asset: 0, service: 1, vulnerability: 2, exploit: 3, impact: 4,
  };
  const columns: Record<number, any[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };
  for (const n of rawNodes) {
    const col = typeOrder[n.type] ?? 2;
    columns[col].push(n);
  }

  // Find the tallest column to determine spacing
  const maxColSize = Math.max(...Object.values(columns).map(c => c.length), 1);

  const positions: Record<string, { x: number; y: number }> = {};
  const COL_W = 280;
  // Compress row spacing when many nodes exist — minimum 80px, max 120px
  const ROW_H = Math.max(80, Math.min(120, 600 / maxColSize));

  for (const [col, nodes] of Object.entries(columns)) {
    const colNum = Number(col);
    const totalH = nodes.length * ROW_H;
    // Center each column relative to tallest column height
    const maxH = maxColSize * ROW_H;
    const offsetY = (maxH - totalH) / 2;
    nodes.forEach((n, i) => {
      positions[n.id] = {
        x: colNum * COL_W + 20,
        y: i * ROW_H + offsetY,
      };
    });
  }
  return positions;
}

// Inner component that has access to useReactFlow
function AttackChainGraphInner({ nodes: externalNodes, edges: externalEdges }: { nodes: any[], edges: any[] }) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isLiveData, setIsLiveData] = useState(false);
  const reactFlowInstance = useReactFlow();
  const fitViewTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Simulation Logic (only shown when no live data)
  const runSimulation = useCallback(async () => {
    if (isLiveData) return;
    setIsSimulating(true);
    setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, status: "idle" } })));
    setEdges(eds => eds.map(e => ({ ...e, data: { ...e.data, active: false } })));

    const steps = [
      { nodeId: "node-1", edgeId: null },
      { nodeId: "node-2", edgeId: "e1-2" },
      { nodeId: "node-4", edgeId: "e2-4" },
      { nodeId: "node-6", edgeId: "e4-6" },
      { nodeId: "node-7", edgeId: "e6-7" },
    ];

    for (const step of steps) {
      await new Promise(resolve => setTimeout(resolve, 1500));
      setNodes(nds => nds.map(n => n.id === step.nodeId ? { ...n, data: { ...n.data, status: "compromised" } } : n));
      if (step.edgeId) {
        setEdges(eds => eds.map(e => e.id === step.edgeId ? { ...e, data: { ...e.data, active: true } } : e));
      }
    }
    setIsSimulating(false);
  }, [setNodes, setEdges, isLiveData]);

  // Handle live scan data from backend
  useEffect(() => {
    if (!externalNodes || externalNodes.length === 0) return;

    setIsLiveData(true);
    const positions = autoLayout(externalNodes);

    const mappedNodes = externalNodes.map((n: any) => ({
      id: n.id,
      type: "custom",
      position: positions[n.id] || { x: 200, y: 200 },
      data: {
        label: n.label,
        type: (n.type || "vulnerability") as NodeType,
        risk: ((n.risk || n.severity || "medium") as string).toLowerCase() as RiskLevel,
        status: (n.status === "compromised" ? "compromised" : n.status === "scanning" ? "scanning" : "idle") as any,
      },
    }));

    const mappedEdges = externalEdges.map((e: any) => ({
      id: `e-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      type: "custom",
      data: { type: e.type || "exploit", active: e.active !== false },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#00FF88" },
    }));

    setNodes(mappedNodes);
    setEdges(mappedEdges);

    // Debounced fitView — wait for ReactFlow to process the new nodes
    if (fitViewTimerRef.current) clearTimeout(fitViewTimerRef.current);
    fitViewTimerRef.current = setTimeout(() => {
      reactFlowInstance.fitView({ padding: 0.15, duration: 400 });
    }, 150);
  }, [externalNodes, externalEdges, setNodes, setEdges, reactFlowInstance]);

  // Derived metrics
  const criticalCount = nodes.filter(n => n.data.risk === "critical").length;
  const compromisedCount = nodes.filter(n => n.data.status === "compromised").length;

  return (
    <Card className="bg-[#0B0F0C]/80 backdrop-blur-xl border-primary/20 shadow-[0_0_50px_rgba(0,255,136,0.05)] h-full overflow-hidden flex flex-col min-h-[600px] w-full">
      <CardHeader className="flex flex-row items-center justify-between pb-4 border-b border-white/5 space-y-0">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 bg-primary/20 blur-md animate-pulse" />
            <div className="p-1.5 rounded-lg bg-primary/10 border border-primary/20 relative">
              <Share2 className="w-4 h-4 text-primary" />
            </div>
          </div>
          <div>
            <CardTitle className="text-sm font-bold uppercase tracking-widest text-foreground">Quantara AI Swarm Attack Graph</CardTitle>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-black opacity-50">Multi-Step Attack Correlation Engine</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
            {!isLiveData && (
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-2 bg-primary/5 border-primary/20 hover:bg-primary/10 text-primary text-[10px] font-black uppercase tracking-widest"
                onClick={runSimulation}
                disabled={isSimulating}
              >
                <Play className={cn("w-3 h-3", isSimulating && "animate-spin")} />
                {isSimulating ? "Simulating..." : "Replay Demo"}
              </Button>
            )}
            {isLiveData && (
              <Badge variant="outline" className="h-8 px-4 gap-2 bg-primary/5 border-primary/30 text-primary text-[10px] font-black uppercase tracking-widest">
                <Activity className="w-3 h-3 animate-pulse" />
                Live Scan Graph
              </Badge>
            )}
            <Button variant="ghost" size="icon" className="h-8 w-8 rounded-lg border border-white/5 bg-black/40 hover:bg-primary/10 text-muted-foreground hover:text-primary">
                <Maximize2 className="w-4 h-4" />
            </Button>
            <Button variant="ghost" size="icon" className="h-8 w-8 rounded-lg border border-white/5 bg-black/40 hover:bg-primary/10 text-muted-foreground hover:text-primary">
                <Settings2 className="w-4 h-4" />
            </Button>
        </div>
      </CardHeader>
      
      <CardContent className="flex-1 p-0 relative overflow-hidden bg-black/20">
        {/* Particle Layer Background */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden h-full w-full">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(0,255,136,0.05)_0%,transparent_70%)]" />
          <div className="mesh-gradient absolute inset-0 opacity-10" />
        </div>

        {/* Legend Panel */}
        <div className="absolute top-4 left-4 z-20 space-y-3">
            <div className="flex flex-wrap items-center gap-4 p-3 rounded-xl bg-black/60 border border-white/5 backdrop-blur-md">
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]" />
                    <span className="text-[9px] uppercase tracking-wider text-muted-foreground font-black">Asset</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]" />
                    <span className="text-[9px] uppercase tracking-wider text-muted-foreground font-black">Vulnerability</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                    <span className="text-[9px] uppercase tracking-wider text-muted-foreground font-black">Exploit/Impact</span>
                </div>
                <div className="h-4 w-px bg-white/10 mx-1" />
                <div className="flex items-center gap-2">
                    <div className="w-3 h-[1px] bg-blue-400" />
                    <span className="text-[9px] uppercase tracking-wider text-muted-foreground font-black italic">Recon</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-3 h-[1px] bg-red-500" />
                    <span className="text-[9px] uppercase tracking-wider text-muted-foreground font-black italic">Attack Flow</span>
                </div>
            </div>
            
            <Badge variant="outline" className="bg-primary/10 border-primary/20 text-primary py-1.5 px-4 flex items-center gap-2 backdrop-blur-md rounded-lg">
                <Brain className="w-3.5 h-3.5 animate-pulse" />
                <span className="text-[10px] font-black uppercase tracking-widest">Neural Mapping Active</span>
            </Badge>
        </div>

        {/* Metrics Overlay */}
        <div className="absolute bottom-4 right-4 z-20 flex gap-3">
             <div className="px-5 py-3 rounded-2xl bg-black/60 border border-white/5 backdrop-blur-xl flex items-center gap-6">
                 <div className="flex flex-col">
                     <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-black mb-1 opacity-50">Graph Nodes</span>
                     <div className="flex items-end gap-1">
                        <span className="text-xl font-black text-primary leading-none">{nodes.length}</span>
                        <span className="text-[10px] font-bold text-primary/70 pb-0.5">nodes</span>
                     </div>
                 </div>
                 <div className="h-8 w-px bg-white/10" />
                 <div className="flex flex-col">
                     <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-black mb-1 opacity-50">Attack Paths</span>
                     <div className="flex items-end gap-1">
                        <span className="text-xl font-black text-orange-400 leading-none">{edges.length}</span>
                        <span className="text-[10px] font-bold text-orange-400/70 pb-0.5">edges</span>
                     </div>
                 </div>
                 <div className="h-8 w-px bg-white/10" />
                 <div className="flex flex-col">
                     <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-black mb-1 opacity-50">Critical Nodes</span>
                     <div className="flex items-end gap-1">
                        <span className={cn("text-xl font-black leading-none", criticalCount > 0 ? "text-red-400" : "text-muted-foreground")}>{criticalCount}</span>
                        <span className={cn("text-[10px] font-bold pb-0.5", criticalCount > 0 ? "text-red-400/70" : "text-muted-foreground/50")}>critical</span>
                     </div>
                 </div>
                 <div className="h-8 w-px bg-white/10" />
                 <div className="flex flex-col">
                     <span className="text-[9px] text-muted-foreground uppercase tracking-widest font-black mb-1 opacity-50">Source</span>
                     <div className="flex items-center gap-2">
                        <span className={cn("h-1.5 w-1.5 rounded-full animate-pulse", isLiveData ? "bg-primary" : "bg-blue-400")} />
                        <span className="text-sm font-bold text-white tracking-tight italic">
                          {isLiveData ? "LIVE" : "DEMO"}
                        </span>
                     </div>
                 </div>
             </div>
        </div>

        <div className="w-full h-full min-h-[500px]">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            className="bg-transparent"
          >
            <Background color="#111" gap={20} />
            <Controls className="bg-black/60 border-white/5 fill-white" />
          </ReactFlow>
        </div>
      </CardContent>

      <style jsx global>{`
        .react-flow__handle {
          width: 8px !important;
          height: 8px !important;
          background: #00FF88 !important;
          border: 2px solid #0B0F0C !important;
        }
        .react-flow__node {
          cursor: pointer;
        }
        .react-flow__controls button {
          background: rgba(0,0,0,0.4);
          border-bottom: 1px solid rgba(255,255,255,0.1);
          color: white;
          width: 30px;
          height: 30px;
        }
        .react-flow__controls button:hover {
          background: rgba(0,255,136,0.1);
        }
        .react-flow__attribution {
          display: none;
        }
        @keyframes mesh-pulse {
          0% { opacity: 0.1; }
          50% { opacity: 0.2; }
          100% { opacity: 0.1; }
        }
        .mesh-gradient {
          background-image: 
            radial-gradient(at 0% 0%, rgba(0, 255, 136, 0.1) 0%, transparent 50%),
            radial-gradient(at 100% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
            radial-gradient(at 100% 100%, rgba(239, 68, 68, 0.1) 0%, transparent 50%),
            radial-gradient(at 0% 100%, rgba(234, 179, 8, 0.1) 0%, transparent 50%);
          animation: mesh-pulse 10s infinite ease-in-out;
        }
      `}</style>
    </Card>
  );
}

// Exported wrapper that provides ReactFlowProvider context
export function AttackChainGraph({ nodes, edges }: { nodes: any[], edges: any[] }) {
  return (
    <ReactFlowProvider>
      <AttackChainGraphInner nodes={nodes} edges={edges} />
    </ReactFlowProvider>
  );
}
