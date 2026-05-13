"use client";

import { motion } from "framer-motion";

function FloatingPaths({ position }: { position: number }) {
    const paths = Array.from({ length: 36 }, (_, i) => ({
        id: i,
        d: `M-${380 - i * 5 * position} -${189 + i * 6}C-${
            380 - i * 5 * position
        } -${189 + i * 6} -${312 - i * 5 * position} ${216 - i * 6} ${
            152 - i * 5 * position
        } ${343 - i * 6}C${616 - i * 5 * position} ${470 - i * 6} ${
            684 - i * 5 * position
        } ${875 - i * 6} ${684 - i * 5 * position} ${875 - i * 6}`,
        color: `rgba(0,255,136,${0.1 + i * 0.03})`,
        width: 0.5 + i * 0.03,
    }));

    return (
        <div className="absolute inset-0 pointer-events-none overflow-visible">
            <svg
                className="w-full h-full"
                viewBox="0 0 696 316"
                fill="none"
                preserveAspectRatio="xMidYMid slice"
            >
                <title>Background Paths</title>
                {paths.map((path) => (
                    <motion.path
                        key={path.id}
                        d={path.d}
                        stroke="url(#neon-gradient)"
                        strokeWidth={path.width}
                        strokeOpacity={0.1 + path.id * 0.03}
                        initial={{ pathLength: 0.3, opacity: 0.6 }}
                        animate={{
                            pathLength: 1,
                            opacity: [0.3, 0.6, 0.3],
                            pathOffset: [0, 1, 0],
                        }}
                        transition={{
                            duration: 20 + Math.random() * 10,
                            repeat: Number.POSITIVE_INFINITY,
                            ease: "linear",
                        }}
                    />
                ))}
                <defs>
                    <linearGradient id="neon-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#00FF88" stopOpacity="0.8" />
                        <stop offset="50%" stopColor="#00C853" stopOpacity="0.5" />
                        <stop offset="100%" stopColor="#00FF88" stopOpacity="0.2" />
                    </linearGradient>
                </defs>
            </svg>
        </div>
    );
}

export function BackgroundPaths() {
    return (
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute inset-0 scale-150">
                <FloatingPaths position={1} />
                <FloatingPaths position={-1} />
            </div>
            {/* Glow overlay for extra neon effect */}
            <div 
                className="absolute inset-0"
                style={{
                    background: "radial-gradient(ellipse at 50% 50%, rgba(0,255,136,0.03) 0%, transparent 70%)"
                }}
            />
        </div>
    );
}
