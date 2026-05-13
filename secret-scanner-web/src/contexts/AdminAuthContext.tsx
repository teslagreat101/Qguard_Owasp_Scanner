"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useRouter } from "next/navigation";

interface AdminUser {
  id: string;
  email: string;
  username: string;
  full_name: string;
  is_super_admin: boolean;
}

interface AdminAuthContextType {
  user: AdminUser | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  logout: () => void;
  token: string | null;
}

const AdminAuthContext = createContext<AdminAuthContextType | undefined>(undefined);

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

import { auth, signInWithGoogle } from "@/lib/firebase";
import { onAuthStateChanged } from "firebase/auth";

export function AdminAuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AdminUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  const handleAdminSession = async (adminToken: string, adminUser: AdminUser) => {
    setToken(adminToken);
    setUser(adminUser);
    localStorage.setItem("admin_token", adminToken);
    localStorage.setItem("admin_user", JSON.stringify(adminUser));
  };

  useEffect(() => {
    const initAuth = async () => {
      // 1. Check for stored token
      const storedToken = localStorage.getItem("admin_token");
      const storedUser = localStorage.getItem("admin_user");

      if (storedToken && storedUser) {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
        setIsLoading(false);
        return;
      }

      // 2. Check for Firebase user (Google Login)
      const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
        if (firebaseUser?.email === "threathunter369@gmail.com") {
          try {
            // Get Firebase ID token to verify on backend
            const idToken = await firebaseUser.getIdToken();
            const response = await fetch(`${API_BASE_URL}/api/v1/auth/google-login`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ id_token: idToken }),
            });

            if (response.ok) {
              const data = await response.json();
              if (data.user.is_super_admin) {
                await handleAdminSession(data.access_token, data.user);
              }
            }
          } catch (error) {
            console.error("Firebase admin auto-login failed:", error);
          }
        }
        setIsLoading(false);
      });

      return () => unsubscribe();
    };

    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || "Login failed");
      }

      const data = await response.json();

      if (!data.user.is_super_admin) {
        throw new Error("Access denied: Admin privileges required");
      }

      await handleAdminSession(data.access_token, data.user);
      router.push("/admin/dashboard");
    } finally {
      setIsLoading(false);
    }
  };

  const loginWithGoogle = async () => {
    setIsLoading(true);
    try {
      const user = await signInWithGoogle();
      if (user.email !== "threathunter369@gmail.com") {
        throw new Error("Access denied: User is not an authorized administrator.");
      }

      // Upgrade to admin session via backend
      const idToken = await user.getIdToken();
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/google-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_token: idToken }),
      });

      if (!response.ok) {
        throw new Error("Failed to verify admin privileges");
      }

      const data = await response.json();
      await handleAdminSession(data.access_token, data.user);
      router.push("/admin/dashboard");
    } catch (error) {
      console.error("Google Admin Login Error:", error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("admin_token");
    localStorage.removeItem("admin_user");
    router.push("/admin/login");
  };

  const value: AdminAuthContextType = {
    user,
    isLoading,
    isAuthenticated: !!user && !!token,
    login,
    loginWithGoogle,
    logout,
    token,
  };

  return (
    <AdminAuthContext.Provider value={value}>
      {children}
    </AdminAuthContext.Provider>
  );
}

export function useAdminAuth() {
  const context = useContext(AdminAuthContext);
  if (context === undefined) {
    throw new Error("useAdminAuth must be used within an AdminAuthProvider");
  }
  return context;
}
