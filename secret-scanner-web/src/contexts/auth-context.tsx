"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  ReactNode,
} from "react";
import { User } from "firebase/auth";
import {
  auth,
  registerWithEmail,
  loginWithEmail,
  signInWithGoogle,
  logoutUser,
  sendVerificationEmail,
  onIdTokenChange,
  check2FAStatus,
} from "@/lib/firebase";
import { toast } from "sonner";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  isEmailVerified: boolean;
  has2FA: boolean;
  register: (email: string, password: string) => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  resendVerificationEmail: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [has2FA, setHas2FA] = useState(false);

  useEffect(() => {
    // onIdTokenChange fires on sign-in, sign-out, and token refresh (every hour)
    const unsubscribe = onIdTokenChange(async (user) => {
      setUser(user);
      if (user) {
        setHas2FA(check2FAStatus(user));
        // Get fresh token and inject into API singleton
        try {
          // Force refresh if needed
          const token = await user.getIdToken();
          const { default: api } = await import('@/lib/api');
          api.setAuthToken(token);
          console.log("🔒 API Auth Token Synchronized");
        } catch (e) {
          console.error("Error setting/refreshing auth token:", e);
        }
      } else {
        const { default: api } = await import('@/lib/api');
        api.setAuthToken(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const register = async (email: string, password: string) => {
    await registerWithEmail(email, password);
  };

  const login = async (email: string, password: string) => {
    await loginWithEmail(email, password);
  };

  const loginWithGoogle = async () => {
    await signInWithGoogle();
  };

  const logout = async () => {
    await logoutUser();
  };

  const resendVerificationEmail = async () => {
    if (user && !user.emailVerified) {
      await sendVerificationEmail(user);
    }
  };

  const value: AuthContextType = {
    user,
    loading,
    isAuthenticated: !!user,
    isEmailVerified: user?.emailVerified ?? false,
    has2FA,
    register,
    login,
    loginWithGoogle,
    logout,
    resendVerificationEmail,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
