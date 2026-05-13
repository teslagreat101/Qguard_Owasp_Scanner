"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import { motion, useMotionValue, useSpring, useTransform, AnimatePresence } from "framer-motion";

interface GlowCardProps {
    children: React.ReactNode;
    className?: string;
    glowColor?: string;
    borderColor?: string;
    hoverGlow?: boolean;
    initial?: any;
    animate?: any;
    whileInView?: any;
    transition?: any;
    viewport?: any;
}

export function GlowCard({
    children,
    className,
    glowColor = "rgba(0, 255, 136, 0.15)",
    borderColor = "rgba(0, 255, 136, 0.2)",
    hoverGlow = true,
    initial = { opacity: 0, y: 20 },
    animate = { opacity: 1, y: 0 },
    whileInView,
    transition = { duration: 0.5 },
    viewport = { once: true },
}: GlowCardProps) {
    const [isHovered, setIsHovered] = useState(false);
    const mouseX = useMotionValue(0);
    const mouseY = useMotionValue(0);

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
        ([x, y]) => `radial-gradient(circle 350px at ${x}px ${y}px, ${glowColor}, transparent 80%)`
    );

    return (
        <motion.div
            onMouseMove={handleMouseMove}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            initial={initial}
            animate={animate}
            whileInView={whileInView}
            transition={transition}
            viewport={viewport}
            whileHover={{
                y: -8,
                transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] }
            }}
            className={cn(
                "group relative rounded-2xl border transition-all duration-700 overflow-hidden h-full",
                "bg-card/90 backdrop-blur-3xl",
                isHovered
                    ? "border-primary/30 shadow-lg shadow-primary/10 bg-card"
                    : "border-border shadow-sm",
                className
            )}
        >
            {/* 🌌 Atmospheric Background Pulses (Dark Mode Only) */}
            <AnimatePresence>
                {isHovered && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 0.15 }}
                        exit={{ opacity: 0 }}
                        className="absolute inset-0 z-0 pointer-events-none overflow-hidden"
                    >
                        <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-primary rounded-full blur-[100px] animate-pulse" />
                        <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-blue-500 rounded-full blur-[80px] opacity-40 animate-pulse [animation-delay:1s]" />
                    </motion.div>
                )}
            </AnimatePresence>

            {/* 💡 Dynamic Mouse Glow Tracking Layer */}
            {hoverGlow && (
                <motion.div
                    className="absolute inset-0 z-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-700"
                    style={{ background: backgroundGlow }}
                />
            )}

            {/* 💎 Glassmorphism Textures & Overlays */}
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-1000" />
            <div className="absolute inset-y-0 right-0 w-px bg-gradient-to-b from-transparent via-border to-transparent" />

            {/* Subtle Inner Glow */}
            <div className="absolute inset-0 z-0 bg-gradient-to-tr from-primary/[0.03] via-transparent to-blue-500/[0.02] pointer-events-none" />

            {/* 📦 Content Container */}
            <div className="relative z-10 h-full p-6">
                {children}
            </div>

            {/* 🧬 Tech Mesh Overlay */}
            <div className="absolute inset-0 z-0 opacity-[0.05] pointer-events-none bg-[url('https://grainy-gradients.vercel.app/noise.svg')] bg-repeat mix-blend-overlay dark:mix-blend-overlay" />
        </motion.div>
    );
}
