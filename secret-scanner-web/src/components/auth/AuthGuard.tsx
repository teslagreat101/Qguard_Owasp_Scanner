"use client";

import { useAuth } from "@/contexts/auth-context";
import { useRouter, usePathname } from "next/navigation";
import { useEffect } from "react";
import { Loader2 } from "lucide-react";

export function AuthGuard({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, loading } = useAuth();
    const router = useRouter();
    const pathname = usePathname();

    useEffect(() => {
        if (!loading && !isAuthenticated && pathname !== "/login") {
            router.push("/login");
        }
    }, [loading, isAuthenticated, router, pathname]);

    if (loading) {
        return (
            <div className="flex h-screen w-screen items-center justify-center bg-background">
                <div className="flex flex-col items-center gap-4">
                    <Loader2 className="h-10 w-10 animate-spin text-primary" />
                    <p className="text-muted-foreground font-medium animate-pulse">Authenticating Secure Session...</p>                </div>
            </div>
        );
    }

    if (!isAuthenticated && pathname !== "/login") {
        return null;
    }

    return <>{children}</>;
}
