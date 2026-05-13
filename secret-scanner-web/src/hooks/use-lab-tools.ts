"use client";

import { useState, useEffect, useCallback, useRef } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const LAB_UNAVAILABLE: LabToolsState = {
  hetty: { running: false, url: "", loading: false },
  mitmweb: { running: false, url: "", loading: false },
};

export interface LabToolStatus {
  running: boolean;
  url: string;
  loading: boolean;
}

export interface LabToolsState {
  hetty: LabToolStatus;
  mitmweb: LabToolStatus;
}

async function fetchLabStatus(): Promise<{ data: LabToolsState; unavailable?: boolean }> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/api/lab/status`, {
      headers: { Accept: "application/json" },
    });
  } catch {
    // Network error — backend not reachable
    return { data: LAB_UNAVAILABLE, unavailable: true };
  }

  // 404 means the lab feature isn't deployed on this backend instance.
  // 401/403 means user isn't authenticated yet or endpoint requires auth.
  // Treat silently as "lab unavailable" rather than throwing.
  if (response.status === 404 || response.status === 401 || response.status === 403) {
    return { data: LAB_UNAVAILABLE, unavailable: true };
  }

  if (!response.ok) {
    throw new Error(`Failed to fetch lab status: ${response.status}`);
  }

  const data = await response.json();
  return {
    data: {
      hetty: {
        running: data.hetty?.running ?? false,
        url: data.hetty?.url ?? "http://hetty:8080",
        loading: false,
      },
      mitmweb: {
        running: data.mitmweb?.running ?? false,
        url: data.mitmweb?.url ?? "http://mitmweb:8081",
        loading: false,
      },
    },
  };
}

export function useLabTools(isActive: boolean = true) {
  const [tools, setTools] = useState<LabToolsState>({
    hetty: { running: false, url: "", loading: true },
    mitmweb: { running: false, url: "", loading: true },
  });
  // Stop polling once we know the lab endpoint is not deployed
  const labUnavailableRef = useRef(false);

  const refreshStatus = useCallback(async () => {
    if (labUnavailableRef.current) return;
    try {
      const { data, unavailable } = await fetchLabStatus();
      if (unavailable) {
        labUnavailableRef.current = true;
      }
      setTools(data);
    } catch (error) {
      console.error("Failed to refresh lab tools status:", error);
      setTools(LAB_UNAVAILABLE);
    }
  }, []);

  const downloadCA = useCallback(
    async (tool: "hetty" | "mitmproxy") => {
      const endpoint =
        tool === "hetty"
          ? `${API_BASE}/api/lab/ca/hetty`
          : `${API_BASE}/api/lab/ca/mitmproxy`;
      const filename =
        tool === "hetty" ? "hetty-ca.crt" : "mitmproxy-ca-cert.pem";

      try {
        const response = await fetch(endpoint);

        if (!response.ok) {
          throw new Error(`Failed to download CA: ${response.status}`);
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        URL.revokeObjectURL(url);
      } catch (error) {
        console.error("Failed to download CA certificate:", error);
        throw error;
      }
    },
    []
  );

  useEffect(() => {
    if (!isActive) return;

    // Initial fetch
    refreshStatus();

    // Poll every 5 seconds
    const interval = setInterval(refreshStatus, 5000);

    return () => clearInterval(interval);
  }, [isActive, refreshStatus]);

  return {
    tools,
    refreshStatus,
    downloadCA,
  };
}

export default useLabTools;
