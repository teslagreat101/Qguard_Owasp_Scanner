"use client";

import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import {
  CheckCircle,
  XCircle,
  AlertCircle,
  Info,
  Terminal,
  Pause,
  RotateCcw,
} from "lucide-react";

interface ScanConsoleProps {
  logs: Array<{
    time: string;
    level: "info" | "success" | "warn" | "error" | "debug";
    message: string;
    module?: string;
  }>;
  isScanning: boolean;
  progress: number;
  onCancel?: () => void;
  onClear?: () => void;
}

function getLogIcon(level: string) {
  switch (level) {
    case "success":
      return <CheckCircle className="h-3 w-3 text-primary" />;
    case "error":
      return <XCircle className="h-3 w-3 text-red-400" />;
    case "warn":
      return <AlertCircle className="h-3 w-3 text-yellow-400" />;
    case "debug":
      return <Terminal className="h-3 w-3 text-blue-400" />;
    default:
      return <Info className="h-3 w-3 text-muted-foreground" />;
  }
}

function getLogColor(level: string): string {
  switch (level) {
    case "success":
      return "text-primary";
    case "error":
      return "text-red-400";
    case "warn":
      return "text-yellow-400";
    case "debug":
      return "text-blue-400";
    default:
      return "text-muted-foreground";
  }
}

export function ScanConsole({
  logs,
  isScanning,
  progress,
  onCancel,
  onClear,
}: ScanConsoleProps) {
  return (
    <Card className="bg-card border-primary/10">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="h-5 w-5 text-primary" />
            <CardTitle className="text-white text-base">Scan Console</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            {isScanning && (
              <Button
                variant="ghost"
                size="sm"
                onClick={onCancel}
                className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
              >
                <Pause className="h-4 w-4 mr-1" />
                Cancel
              </Button>
            )}
            {!isScanning && logs.length > 0 && onClear && (
              <Button
                variant="ghost"
                size="sm"
                onClick={onClear}
                className="text-muted-foreground hover:text-muted-foreground"
              >
                <RotateCcw className="h-4 w-4 mr-1" />
                Clear
              </Button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        {isScanning && (
          <div className="mt-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-muted-foreground">Scan Progress</span>
              <span className="text-xs font-mono text-primary">{progress}%</span>
            </div>
            <div className="h-1.5 bg-[rgba(0,255,136,0.08)] rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-[#00FF88] to-[#00C853]"
                initial={{ width: 0 }}
                animate={{ width: `${progress}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>
          </div>
        )}
      </CardHeader>

      <CardContent className="p-0">
        <ScrollArea className="h-[250px] bg-[rgba(0,0,0,0.3)] rounded-lg mx-4 mb-4">
          <div className="p-3 font-mono text-xs space-y-1">
            {logs.length === 0 ? (
              <div className="text-muted-foreground italic">
                Waiting for scan output...
              </div>
            ) : (
              logs.map((log, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-start gap-2"
                >
                  <span className="text-[#3D4F48] shrink-0">[{log.time}]</span>
                  <span className="shrink-0">{getLogIcon(log.level)}</span>
                  <span className={`${getLogColor(log.level)} break-all`}>
                    {log.message}
                  </span>
                  {log.module && (
                    <Badge
                      variant="outline"
                      className="text-[10px] border-[rgba(0,255,136,0.15)] text-muted-foreground shrink-0 ml-auto"
                    >
                      {log.module}
                    </Badge>
                  )}
                </motion.div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
