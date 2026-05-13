/**
 * Security Protocol v5.0 — Database Service
 * Subscription-based Firestore implementation
 */

import { db } from "./firebase";
import {
    doc,
    setDoc,
    getDoc,
    updateDoc,
    collection,
    addDoc,
    query,
    where,
    orderBy,
    getDocs,
    limit,
    Timestamp,
    serverTimestamp,
    deleteDoc,
    onSnapshot
} from "firebase/firestore";

// ───────────────────────────────────────────────────────────────────────────
// User & Subscription Management
// ───────────────────────────────────────────────────────────────────────────

const SUPER_ADMIN_EMAIL = "threathunter369@gmail.com";

export const initializeUser = async (uid: string, email: string) => {
    const userRef = doc(db, "users", uid);
    const snap = await getDoc(userRef);
    const isSuperAdmin = email === SUPER_ADMIN_EMAIL;

    if (!snap.exists()) {
        await setDoc(userRef, {
            uid,
            email,
            plan: isSuperAdmin ? "elite" : "free",
            scanLimit: isSuperAdmin ? 999999 : 10,
            scansUsedThisMonth: 0,
            subscriptionStatus: "active",
            billingCycleStart: serverTimestamp(),
            billingCycleEnd: Timestamp.fromMillis(Date.now() + (isSuperAdmin ? 365 : 30) * 24 * 60 * 60 * 1000),
            created_at: serverTimestamp(),
            last_active_at: serverTimestamp(),
        });
    } else {
        // Always keep the super admin at elite tier in case the document already existed
        const updates: any = { last_active_at: serverTimestamp() };
        if (isSuperAdmin) {
            updates.plan = "elite";
            updates.scanLimit = 999999;
        }
        await updateDoc(userRef, updates);
    }
};

export const getUserProfile = async (uid: string) => {
    const userRef = doc(db, "users", uid);
    const snap = await getDoc(userRef);
    if (!snap.exists()) return null;
    const data = snap.data();
    // Always return elite for the super admin regardless of what's stored
    if (data.email === SUPER_ADMIN_EMAIL) {
        return { ...data, plan: "elite", scanLimit: 999999 };
    }
    return data;
};

export const subscribeToUserProfile = (uid: string, callback: (data: any) => void) => {
    const userRef = doc(db, "users", uid);
    return onSnapshot(
        userRef,
        (snap) => {
            if (snap.exists()) {
                callback(snap.data());
            }
        },
        (error) => {
            // Silently ignore permission-denied — this fires normally during/after signout
            // when Firebase auth state clears before the listener is detached.
            if (error.code !== "permission-denied") {
                console.error("[Firestore] subscribeToUserProfile error:", error);
            }
        }
    );
};

// ───────────────────────────────────────────────────────────────────────────
// Scan Management
// ───────────────────────────────────────────────────────────────────────────

export interface SaveScanOptions {
    uid: string;
    target: string;
    scan_type: string;
    status: string;
    results: {
        findings: any[];
        logs: any[];
        stats: any;
        duration: number;
        risk_score: number;
    };
}

export const saveScanResult = async (options: SaveScanOptions) => {
    const { uid, target, scan_type, status, results } = options;

    // 1. Create top-level scan document
    const scanData = {
        customer_id: uid,
        target_path: target,
        scan_type: scan_type,
        status: status,
        risk_score: results.risk_score || 100,
        findings_count: results.findings.length,
        duration_ms: results.duration,
        created_at: serverTimestamp(),
    };

    const scanRef = await addDoc(collection(db, "scans"), scanData);

    // 2. Add findings as sub-collection
    const findingsPromises = results.findings.map((f) => {
        return addDoc(collection(db, "scans", scanRef.id, "findings"), {
            ...f,
            scan_id: scanRef.id,
            customer_id: uid,
            created_at: serverTimestamp(),
        });
    });

    // 3. Add logs as sub-collection
    const logPromises = results.logs.map((l) => {
        return addDoc(collection(db, "scans", scanRef.id, "logs"), {
            ...l,
            scan_id: scanRef.id,
            created_at: serverTimestamp(),
        });
    });

    await Promise.all([...findingsPromises, ...logPromises]);

    // 4. Increment scan count for user
    const userRef = doc(db, "users", uid);
    const profile = await getUserProfile(uid);
    if (profile) {
        await updateDoc(userRef, {
            scansUsedThisMonth: (profile.scansUsedThisMonth || 0) + 1,
        });
    }

    return scanRef.id;
};

export const getScanHistory = async (uid: string, limitCount: number = 20) => {
    const q = query(
        collection(db, "scans"),
        where("customer_id", "==", uid),
        orderBy("created_at", "desc"),
        limit(limitCount)
    );

    const snap = await getDocs(q);
    return snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
};

// ───────────────────────────────────────────────────────────────────────────
// Tasks & Workflow
// ───────────────────────────────────────────────────────────────────────────

export const createTask = async (uid: string, task: any) => {
    return await addDoc(collection(db, "users", uid, "tasks"), {
        ...task,
        uid: uid,
        is_completed: false,
        created_at: serverTimestamp(),
    });
};

export const getTasks = async (uid: string) => {
    const snap = await getDocs(collection(db, "users", uid, "tasks"));
    return snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
};

export const updateTaskStatus = async (uid: string, taskId: string, completed: boolean) => {
    const taskRef = doc(db, "users", uid, "tasks", taskId);
    await updateDoc(taskRef, {
        is_completed: completed,
        updated_at: serverTimestamp(),
    });
};

// ───────────────────────────────────────────────────────────────────────────
// Scheduling
// ───────────────────────────────────────────────────────────────────────────

export const createSchedule = async (uid: string, schedule: any) => {
    return await addDoc(collection(db, "users", uid, "schedules"), {
        ...schedule,
        uid: uid,
        is_active: true,
        created_at: serverTimestamp(),
    });
};

export const getSchedules = async (uid: string) => {
    const snap = await getDocs(collection(db, "users", uid, "schedules"));
    return snap.docs.map(doc => ({ id: doc.id, ...doc.data() }));
};

export const deleteSchedule = async (uid: string, scheduleId: string) => {
    await deleteDoc(doc(db, "users", uid, "schedules", scheduleId));
};
