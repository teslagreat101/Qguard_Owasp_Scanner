"use client";

import { AuthGuard } from "@/components/auth/AuthGuard";
import { AcceptanceGuard } from "@/components/legal/AcceptanceGuard";
import { ScannerProvider } from "@/contexts/scanner-context";

export default function DashboardLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <AuthGuard>
            <AcceptanceGuard>
                <ScannerProvider>
                    {children}
                </ScannerProvider>
            </AcceptanceGuard>
        </AuthGuard>
    );
}
