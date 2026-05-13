"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { AlertTriangle, CheckCircle, RefreshCw, Server, WifiOff } from "lucide-react";
import { toast } from "sonner";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ConnectionStatusProps {
  onStatusChange?: (isConnected: boolean) => void;
}

export function ConnectionStatus({ onStatusChange }: ConnectionStatusProps) {
  const [status, setStatus] = useState<"checking" | "connected" | "error">("checking");
  const [error, setError] = useState<string | null>(null);
  const [apiUrl, setApiUrl] = useState(API_BASE_URL);

  const checkConnection = async () => {
    setStatus("checking");
    setError(null);

    const signal = AbortSignal.timeout(10000); // 10s for health check

    try {
      const response = await fetch(`${apiUrl}/api/v1/health`, {
        signal,
        headers: { Accept: "application/json" },
        mode: 'cors'
      });

      if (response.ok) {
        const data = await response.json();
        setStatus("connected");
        setError(null);
        onStatusChange?.(true);
        toast.success(`Connected to backend v${data.version}`);
      } else {
        setStatus("error");
        setError(`Backend returned status ${response.status}`);
        onStatusChange?.(false);
      }
    } catch (err: any) {
      // Handle the case where the user navigated away or the component unmounted
      if (err.name === 'TimeoutError' || (err.name === 'AbortError' && signal.aborted)) {
        setStatus("error");
        setError("Connection timed out (10s). Is the backend running?");
        console.warn("Backend connection timed out");
        onStatusChange?.(false);
        return;
      }

      setStatus("error");
      const errorMessage = err instanceof Error ? err.message : "Unknown error";
      setError(`Cannot connect to ${apiUrl}. Is the backend running?`);
      onStatusChange?.(false);
      console.error("Backend connection failed:", errorMessage);
    }
  };

  useEffect(() => {
    checkConnection();
    // Auto-check every 30 seconds
    const interval = setInterval(checkConnection, 30000);
    return () => clearInterval(interval);
  }, [apiUrl]);

  if (status === "connected") {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center gap-2 text-neon-green text-sm"
      >
        <CheckCircle className="h-4 w-4" />
        <span>Backend Connected</span>
        <Button
          variant="ghost"
          size="sm"
          onClick={checkConnection}
          className="h-6 w-6 p-0 text-text-muted hover:text-neon-green"
        >
          <RefreshCw className="h-3 w-3" />
        </Button>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 space-y-3"
    >
      <div className="flex items-center gap-3">
        {status === "checking" ? (
          <RefreshCw className="h-5 w-5 text-yellow-500 animate-spin" />
        ) : (
          <WifiOff className="h-5 w-5 text-red-500" />
        )}
        <div className="flex-1">
          <p className="text-red-500 font-medium">
            {status === "checking" ? "Checking backend connection..." : "Backend Connection Failed"}
          </p>
          {error && (
            <p className="text-red-500/70 text-sm mt-1">{error}</p>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs text-text-muted">
        <Server className="h-3 w-3" />
        <span>API URL: {apiUrl}</span>
      </div>

      <div className="flex gap-2">
        <Button
          size="sm"
          onClick={checkConnection}
          disabled={status === "checking"}
          className="bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30"
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${status === "checking" ? "animate-spin" : ""}`} />
          {status === "checking" ? "Checking..." : "Retry Connection"}
        </Button>
      </div>

      <div className="text-xs text-text-secondary space-y-1">
        <p>Troubleshooting:</p>
        <ul className="list-disc list-inside space-y-0.5">
          <li>Ensure backend is running: <code className="bg-bg-deep px-1 rounded border border-border-green">python -m backend.main</code></li>
          <li>Or run with Docker: <code className="bg-bg-deep px-1 rounded border border-border-green">docker-compose up backend</code></li>
          <li>Check CORS settings in backend</li>
          <li>Verify the API URL in environment variables</li>
        </ul>
      </div>
    </motion.div>
  );
}
