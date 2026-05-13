import { initializeApp, getApps, getApp } from "firebase/app";
import {

  getAuth,
  GoogleAuthProvider,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  signOut,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateEmail,
  updatePassword,
  updateProfile,
  reauthenticateWithCredential,
  EmailAuthProvider,
  multiFactor,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator,
  RecaptchaVerifier,
  MultiFactorResolver,
  onAuthStateChanged,
  onIdTokenChanged,
  User,
  Unsubscribe,
  type ApplicationVerifier,
} from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage";
import { toast } from "sonner";

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
  measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID
};

// Initialize Firebase
const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();

// Initialize services
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
export const googleProvider = new GoogleAuthProvider();

// Enable email verification link in same device
auth.useDeviceLanguage();

// ───────────────────────────────────────────────────────────────────────────
// Auth Helper Functions
// ───────────────────────────────────────────────────────────────────────────

// Register with email/password
export const registerWithEmail = async (email: string, password: string) => {
  try {
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    const { initializeUser } = await import("./db-service");
    await initializeUser(userCredential.user.uid, email);
    await sendEmailVerification(userCredential.user);
    toast.success("Account created! Please check your email to verify your account.");
    return userCredential.user;
  } catch (error: any) {
    toast.error(error.message || "Registration failed");
    throw error;
  }
};

// Login with email/password
export const loginWithEmail = async (email: string, password: string) => {
  try {
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const { initializeUser } = await import("./db-service");
    await initializeUser(userCredential.user.uid, userCredential.user.email!);

    if (!userCredential.user.emailVerified) {
      toast.warning("Please verify your email before accessing the dashboard.");
    } else {
      toast.success("Welcome back!");
    }
    return userCredential.user;
  } catch (error: any) {
    toast.error(error.message || "Login failed");
    throw error;
  }
};

// Google Sign-In
export const signInWithGoogle = async () => {
  try {
    const result = await signInWithPopup(auth, googleProvider);
    const { initializeUser } = await import("./db-service");
    await initializeUser(result.user.uid, result.user.email!);
    toast.success("Signed in with Google!");
    return result.user;
  } catch (error: any) {
    toast.error(error.message || "Google sign-in failed");
    throw error;
  }
};

// Logout
export const logoutUser = async () => {
  try {
    await signOut(auth);
    toast.success("Logged out successfully");
  } catch (error: any) {
    toast.error(error.message || "Logout failed");
    throw error;
  }
};

// Send verification email
export const sendVerificationEmail = async (user: User) => {
  try {
    await sendEmailVerification(user);
    toast.success("Verification email sent!");
  } catch (error: any) {
    toast.error(error.message || "Failed to send verification email");
    throw error;
  }
};

// Reset password
export const resetPassword = async (email: string) => {
  try {
    await sendPasswordResetEmail(auth, email);
    toast.success("Password reset email sent!");
  } catch (error: any) {
    toast.error(error.message || "Failed to send reset email");
    throw error;
  }
};

// Update user email
export const updateUserEmail = async (user: User, newEmail: string, password: string) => {
  try {
    // Re-authenticate
    const credential = EmailAuthProvider.credential(user.email!, password);
    await reauthenticateWithCredential(user, credential);

    // Update email
    await updateEmail(user, newEmail);
    await sendEmailVerification(user);
    toast.success("Email updated! Please verify your new email.");
  } catch (error: any) {
    toast.error(error.message || "Failed to update email");
    throw error;
  }
};

// Update user password
export const updateUserPassword = async (user: User, currentPassword: string, newPassword: string) => {
  try {
    // Re-authenticate
    const credential = EmailAuthProvider.credential(user.email!, currentPassword);
    await reauthenticateWithCredential(user, credential);

    // Update password
    await updatePassword(user, newPassword);
    toast.success("Password updated successfully!");
  } catch (error: any) {
    toast.error(error.message || "Failed to update password");
    throw error;
  }
};

// Update display name
export const updateUserProfile = async (
  user: User,
  displayName: string
): Promise<void> => {
  try {
    await updateProfile(user, { displayName });
    toast.success("Profile updated successfully!");
  } catch (error: any) {
    toast.error(error.message || "Failed to update profile");
    throw error;
  }
};

// Check if user has 2FA enabled
export const check2FAStatus = (user: User): boolean => {
  return multiFactor(user).enrolledFactors.length > 0;
};

// Create an invisible RecaptchaVerifier bound to a DOM container id
export const createRecaptchaVerifier = (containerId: string): RecaptchaVerifier => {
  return new RecaptchaVerifier(auth, containerId, { size: "invisible" });
};

// Send phone MFA verification code — returns verificationId
export const sendPhone2FACode = async (
  user: User,
  phoneNumber: string,
  appVerifier: ApplicationVerifier
): Promise<string> => {
  try {
    const session = await multiFactor(user).getSession();
    const phoneInfoOptions = { phoneNumber, session };
    const provider = new PhoneAuthProvider(auth);
    const verificationId = await provider.verifyPhoneNumber(
      phoneInfoOptions,
      appVerifier
    );
    toast.success("Verification code sent to " + phoneNumber);
    return verificationId;
  } catch (error: any) {
    toast.error(error.message || "Failed to send verification code");
    throw error;
  }
};

// Complete phone MFA enrollment with the received code
export const completePhone2FAEnrollment = async (
  user: User,
  verificationId: string,
  verificationCode: string
): Promise<void> => {
  try {
    const credential = PhoneAuthProvider.credential(
      verificationId,
      verificationCode
    );
    const assertion = PhoneMultiFactorGenerator.assertion(credential);
    await multiFactor(user).enroll(assertion, "Phone");
    toast.success("Two-factor authentication enabled!");
  } catch (error: any) {
    toast.error(error.message || "Failed to enable 2FA. Check your code and try again.");
    throw error;
  }
};

// Unenroll the first phone MFA factor
export const unenrollPhone2FA = async (user: User): Promise<void> => {
  try {
    const factors = multiFactor(user).enrolledFactors;
    if (factors.length === 0) return;
    await multiFactor(user).unenroll(factors[0]);
    toast.success("Two-factor authentication disabled");
  } catch (error: any) {
    toast.error(error.message || "Failed to disable 2FA");
    throw error;
  }
};

// Get ID token change listener (fires on refresh)
export const onIdTokenChange = (callback: (user: User | null) => void): Unsubscribe => {
  return onIdTokenChanged(auth, callback);
};

export default app;
