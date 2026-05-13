"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import {
  Activity,
  Download,
  Settings,
  Copy,
  CheckCircle,
  AlertCircle,
  RefreshCw,
  Shield,
  Terminal,
} from "lucide-react";
import { useLabTools } from "@/hooks/use-lab-tools";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

interface AdvancedProxyLabProps {
  tool: "hetty" | "mitmweb";
  isActive: boolean;
}

export function AdvancedProxyLab({ tool, isActive }: AdvancedProxyLabProps) {
  const { tools, refreshStatus, downloadCA } = useLabTools(isActive);
  const [iframeKey, setIframeKey] = useState(0);
  const [showSetup, setShowSetup] = useState(true);
  const [copied, setCopied] = useState(false);

  const toolStatus = tools[tool];
  const isRunning = toolStatus.running;
  const isLoading = toolStatus.loading;

  // Auto-refresh iframe when tool becomes running
  useEffect(() => {
    if (isRunning && !isLoading) {
      setIframeKey((prev) => prev + 1);
    }
  }, [isRunning, isLoading]);

  // Keyboard shortcut: Ctrl+Shift+H switches to Hetty
  useEffect(() => {
    if (tool !== "hetty") return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key === "H") {
        e.preventDefault();
        // This will be handled by parent component via callback or context
        // For now, we just show a toast
        toast.info("Press Ctrl+Shift+H in the Scanner page to switch to Hetty");
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [tool]);

  const handleDownloadCA = useCallback(async () => {
    try {
      await downloadCA(tool === "hetty" ? "hetty" : "mitmproxy");
      toast.success(`${tool === "hetty" ? "Hetty" : "mitmproxy"} CA certificate downloaded`);
    } catch (error) {
      toast.error("Failed to download CA certificate");
    }
  }, [downloadCA, tool]);

  const handleCopyProxy = useCallback(() => {
    const proxyAddress =
      tool === "hetty" ? "127.0.0.1:8082" : "127.0.0.1:8084";
    navigator.clipboard.writeText(proxyAddress);
    setCopied(true);
    toast.success(`Proxy address copied: ${proxyAddress}`);
    setTimeout(() => setCopied(false), 2000);
  }, [tool]);

  const toolName = tool === "hetty" ? "Hetty" : "mitmweb";
  const toolDescription =
    tool === "hetty"
      ? "Modern HTTP toolkit for security research"
      : "Classic interactive HTTPS proxy";
  const proxyPort = tool === "hetty" ? "8082" : "8084";

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-280px)] bg-background/40 rounded-lg border border-primary/20">
        <div className="flex flex-col items-center gap-4">
          <RefreshCw className="w-8 h-8 text-primary animate-spin" />
          <p className="text-muted-foreground">Checking {toolName} status...</p>
        </div>
      </div>
    );
  }

  if (!isRunning) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-280px)] bg-background/40 rounded-lg border border-destructive/30">
        <div className="flex flex-col items-center gap-4 max-w-md text-center p-8">
          <AlertCircle className="w-12 h-12 text-destructive" />
          <h3 className="text-xl font-semibold text-foreground">{toolName} Not Running</h3>
          <p className="text-muted-foreground">
            The {toolName} proxy service is not available. Make sure the Docker containers
            are running with <code className="bg-secondary px-2 py-1 rounded">docker-compose up -d</code>
          </p>
          <Button
            onClick={refreshStatus}
            variant="outline"
            className="border-primary/30 text-primary hover:bg-primary/10"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Retry Connection
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full gap-4">
      {/* Status Bar */}
      <Card className="bg-background/40 border-primary/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="w-3 h-3 rounded-full bg-primary animate-pulse" />
                <div className="absolute inset-0 w-3 h-3 rounded-full bg-primary animate-ping opacity-30" />
              </div>
              <div>
                <CardTitle className="text-lg text-foreground flex items-center gap-2">
                  {toolName}
                  <Badge
                    variant="outline"
                    className="border-primary/50 text-primary bg-primary/10"
                  >
                    Running
                  </Badge>
                </CardTitle>
                <CardDescription className="text-muted-foreground">
                  {toolDescription}
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={handleDownloadCA}
                variant="outline"
                size="sm"
                className="border-primary/30 text-primary hover:bg-primary/10"
              >
                <Download className="w-4 h-4 mr-2" />
                Download CA
              </Button>
              <Button
                onClick={() => setShowSetup(!showSetup)}
                variant="outline"
                size="sm"
                className="border-border text-muted-foreground hover:text-foreground hover:bg-secondary"
              >
                <Settings className="w-4 h-4 mr-2" />
                {showSetup ? "Hide Setup" : "Setup"}
              </Button>
            </div>
          </div>
        </CardHeader>

        {/* Setup Instructions (Collapsible) */}
        {showSetup && (
          <CardContent className="pt-0">
            <div className="rounded-lg bg-background/40 border border-border p-4 space-y-4">
              <div className="flex items-start gap-3">
                <Terminal className="w-5 h-5 text-primary mt-0.5" />
                <div className="space-y-2 flex-1">
                  <p className="text-sm text-muted-foreground">
                    <strong className="text-foreground">Proxy Configuration:</strong> Set your
                    browser or system proxy to:
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 bg-secondary px-3 py-2 rounded text-primary font-mono text-sm">
                      127.0.0.1:{proxyPort}
                    </code>
                    <Button
                      onClick={handleCopyProxy}
                      size="sm"
                      variant="ghost"
                      className="text-muted-foreground hover:text-foreground hover:bg-muted/50"
                    >
                      {copied ? (
                        <CheckCircle className="w-4 h-4 text-primary" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <Shield className="w-5 h-5 text-primary mt-0.5" />
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    <strong className="text-foreground">SSL/TLS Interception:</strong> To inspect
                    HTTPS traffic, install the CA certificate:
                  </p>
                  <ol className="text-sm text-muted-foreground list-decimal list-inside space-y-1 pl-2">
                    <li>Click "Download CA" above</li>
                    <li>Install the certificate in your browser or system trust store</li>
                    <li>
                      {tool === "hetty"
                        ? "Hetty CA is auto-generated on first run"
                        : "mitmproxy CA is in ~/.mitmproxy/"}
                    </li>
                  </ol>
                </div>
              </div>

              <details className="text-sm">
                <summary className="cursor-pointer text-primary hover:text-primary/80 font-medium">
                  CA Installation Guide by Platform
                </summary>
                <div className="mt-3 space-y-3 text-muted-foreground pl-2">
                  <div>
                    <strong className="text-foreground">macOS:</strong>
                    <code className="block bg-secondary px-2 py-1 rounded mt-1 font-mono text-xs">
                      sudo security add-trusted-cert -d -r trustRoot -k
                      /Library/Keychains/System.keychain ~/Downloads/hetty-ca.crt
                    </code>
                  </div>
                  <div>
                    <strong className="text-foreground">Windows (PowerShell Admin):</strong>
                    <code className="block bg-secondary px-2 py-1 rounded mt-1 font-mono text-xs">
                      certutil -addstore -f &quot;ROOT&quot; %USERPROFILE%\Downloads\hetty-ca.crt
                    </code>
                  </div>
                  <div>
                    <strong className="text-foreground">Linux (Firefox):</strong>
                    <p className="mt-1">
                      Go to Settings → Privacy & Security → Certificates → View
                      Certificates → Authorities → Import
                    </p>
                  </div>
                </div>
              </details>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Iframe Container */}
      <motion.div
        key={iframeKey}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex-1 min-h-0 rounded-lg border border-primary/20 overflow-hidden bg-background"
      >
        <iframe
          src={`/poc/${tool}/`}
          className="w-full h-[calc(100vh-280px)] border-0"
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-downloads"
          allow="clipboard-write"
          title={`${toolName} Proxy Interface`}
        />
      </motion.div>
    </div>
  );
}

export default AdvancedProxyLab;
