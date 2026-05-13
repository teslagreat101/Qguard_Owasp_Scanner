"use client";
import { useRef, useEffect } from "react";

export default function PlexusBackground() {
    const canvasRef = useRef<HTMLCanvasElement>(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;

        let animationFrameId: number;
        let particles: Particle[] = [];
        const particleCount = 50;
        const connectionDistance = 140;

        class Particle {
            x: number; y: number; vx: number; vy: number; radius: number;
            constructor(w: number, h: number) {
                this.x = Math.random() * w; this.y = Math.random() * h;
                this.vx = (Math.random() - 0.5) * 0.4; this.vy = (Math.random() - 0.5) * 0.4;
                this.radius = Math.random() * 1.5 + 0.5;
            }
            update(w: number, h: number) {
                this.x += this.vx; this.y += this.vy;
                if (this.x < 0 || this.x > w) this.vx *= -1;
                if (this.y < 0 || this.y > h) this.vy *= -1;
            }
            draw(ctx: CanvasRenderingContext2D) {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                ctx.fillStyle = "rgba(0, 255, 136, 0.25)";
                ctx.fill();
            }
        }

        const init = () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            particles = [];
            for (let i = 0; i < particleCount; i++) {
                particles.push(new Particle(canvas.width, canvas.height));
            }
        };

        const animate = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            for (let i = 0; i < particles.length; i++) {
                const p1 = particles[i];
                p1.update(canvas.width, canvas.height);
                p1.draw(ctx);
                for (let j = i + 1; j < particles.length; j++) {
                    const p2 = particles[j];
                    const dx = p1.x - p2.x, dy = p1.y - p2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < connectionDistance) {
                        ctx.beginPath();
                        ctx.moveTo(p1.x, p1.y);
                        ctx.lineTo(p2.x, p2.y);
                        ctx.strokeStyle = `rgba(0, 255, 136, ${(1 - dist / connectionDistance) * 0.15})`;
                        ctx.lineWidth = 0.5;
                        ctx.stroke();
                    }
                }
            }
            animationFrameId = requestAnimationFrame(animate);
        };

        init();
        animate();
        const handleResize = () => init();
        window.addEventListener("resize", handleResize);
        return () => { cancelAnimationFrame(animationFrameId); window.removeEventListener("resize", handleResize); };
    }, []);

    return <canvas ref={canvasRef} className="fixed inset-0 z-0 pointer-events-none opacity-30" />;
}
