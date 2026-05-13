"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import { useTheme } from "next-themes";
import { motion, useMotionValue, useSpring, useTransform, AnimatePresence } from "framer-motion";

interface GlowCardProps {
    children: React.ReactNode;
    className?: string;
    glowColor?: string;
    borderColor?: string;
    hoverGlow?: boolean;
    initial?: any;
    whileInView?: any;
    transition?: any;
    viewport?: any;
}

export function GlowCard({
    children,
    className,
    glowColor,
    borderColor,
    hoverGlow = true,
    initial,
    whileInView,
    transition = { duration: 0.5 },
    viewport = { once: true },
}: GlowCardProps) {
    const [isHovered, setIsHovered] = useState(false);
    const mouseX = useMotionValue(0);
    const mouseY = useMotionValue(0);
    const { resolvedTheme } = useTheme();
    const isLight = resolvedTheme === "light";

    const resolvedGlowColor = glowColor ?? (isLight ? "rgba(108, 99, 255, 0.1)" : "rgba(0, 255, 136, 0.15)");

    // Smooth mouse tracking
    const springConfig = { damping: 25, stiffness: 350 };
    const smoothX = useSpring(mouseX, springConfig);
    const smoothY = useSpring(mouseY, springConfig);

    function handleMouseMove({ currentTarget, clientX, clientY }: React.MouseEvent) {
        const { left, top } = currentTarget.getBoundingClientRect();
        mouseX.set(clientX - left);
        mouseY.set(clientY - top);
    }

    const backgroundGlow = useTransform(
        [smoothX, smoothY],
        ([x, y]) => `radial-gradient(circle 350px at ${x}px ${y}px, ${resolvedGlowColor}, transparent 80%)`
    );

    return (
        <motion.div
            onMouseMove={handleMouseMove}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            initial={initial}
            whileInView={whileInView}
            transition={transition}
            viewport={viewport}
            whileHover={{
                y: -8,
                transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] }
            }}
            className={cn(
                "group relative rounded-2xl border transition-all duration-700 overflow-hidden",
                isLight
                    ? cn(
                        "bg-white",
                        isHovered
                            ? "border-[#c7cce0] shadow-[0_20px_50px_rgba(0,0,0,0.08)]"
                            : "border-[#e6e9f2] shadow-[0_10px_30px_rgba(0,0,0,0.05)]"
                    )
                    : cn(
                        "bg-[rgba(10,15,12,0.45)] backdrop-blur-3xl",
                        isHovered
                            ? "border-[rgba(0,255,136,0.6)] shadow-lg shadow-[0_30px_60px_rgba(0,0,0,0.8),0_0_25px_rgba(0,255,136,0.15)] bg-[rgba(15,22,18,0.55)]"
                            : "border-[rgba(255,255,255,0.1)] shadow-sm shadow-[0_8px_32px_rgba(0,0,0,0.4)]"
                    ),
                className
            )}
        >
            {/* Atmospheric Background Pulses — dark only */}
            {!isLight && (
                <AnimatePresence>
                    {isHovered && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 0.15 }}
                            exit={{ opacity: 0 }}
                            className="absolute inset-0 z-0 pointer-events-none overflow-hidden"
                        >
                            <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-primary rounded-full blur-[100px] animate-pulse" />
                            <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-[#00A3FF] rounded-full blur-[80px] opacity-40 animate-pulse [animation-delay:1s]" />
                        </motion.div>
                    )}
                </AnimatePresence>
            )}

            {/* Dynamic Mouse Glow Tracking Layer */}
            {hoverGlow && (
                <motion.div
                    className="absolute inset-0 z-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-700"
                    style={{ background: backgroundGlow }}
                />
            )}

            {/* Top highlight line */}
            <div className={cn(
                "absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-1000",
                isLight ? "via-[#6c63ff]/30" : "via-neon-green/50"
            )} />

            {/* Subtle Inner Glow */}
            {!isLight && (
                <div className="absolute inset-0 z-0 bg-gradient-to-tr from-neon-green/[0.03] via-transparent to-[rgba(0,163,255,0.02)] pointer-events-none" />
            )}

            {/* Content Container */}
            <div className="relative z-10 h-full p-6">
                {children}
            </div>

            {/* Tech Mesh Overlay — dark only */}
            {!isLight && (
                <div className="absolute inset-0 z-0 opacity-[0.05] pointer-events-none bg-[url('https://grainy-gradients.vercel.app/noise.svg')] bg-repeat mix-blend-overlay" />
            )}
        </motion.div>
    );
}
