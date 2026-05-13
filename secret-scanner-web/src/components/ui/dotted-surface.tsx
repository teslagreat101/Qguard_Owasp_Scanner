'use client';
import { cn } from '@/lib/utils';
import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

type DottedSurfaceProps = Omit<React.ComponentProps<'div'>, 'ref'>;

/**
 * DottedSurface — neon-green Three.js wave particles.
 * Positions absolutely inside parent (use `relative overflow-hidden` on parent).
 */
export function DottedSurface({ className, ...props }: DottedSurfaceProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // ── Grid config ──────────────────────────────────────────────
    const SEPARATION = 130;
    const AMOUNTX   = 44;
    const AMOUNTY   = 56;

    // ── Neon-green palette (normalized 0-1) ──────────────────────
    // Base:  #00FF88  →  r=0   g=1.0  b=0.533
    // Teal:  #00E5CC  →  r=0   g=0.9  b=0.8
    const R_BASE = 0;
    const G_BASE = 1.0;
    const B_BASE = 0.533;

    // ── Scene ────────────────────────────────────────────────────
    const scene  = new THREE.Scene();
    const W      = container.clientWidth  || window.innerWidth;
    const H      = container.clientHeight || window.innerHeight;

    const camera = new THREE.PerspectiveCamera(55, W / H, 1, 12000);
    camera.position.set(0, 380, 1300);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(W, H);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    // ── Geometry ─────────────────────────────────────────────────
    const geometry  = new THREE.BufferGeometry();
    const positions = new Float32Array(AMOUNTX * AMOUNTY * 3);
    const colors    = new Float32Array(AMOUNTX * AMOUNTY * 3);

    let i = 0;
    for (let ix = 0; ix < AMOUNTX; ix++) {
      for (let iy = 0; iy < AMOUNTY; iy++) {
        positions[i * 3]     = ix * SEPARATION - (AMOUNTX * SEPARATION) / 2;
        positions[i * 3 + 1] = 0;
        positions[i * 3 + 2] = iy * SEPARATION - (AMOUNTY * SEPARATION) / 2;
        colors[i * 3]     = R_BASE;
        colors[i * 3 + 1] = G_BASE;
        colors[i * 3 + 2] = B_BASE;
        i++;
      }
    }

    geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geometry.setAttribute('color',    new THREE.Float32BufferAttribute(colors, 3));

    // ── Material ─────────────────────────────────────────────────
    const material = new THREE.PointsMaterial({
      size:         6,
      vertexColors: true,
      transparent:  true,
      opacity:      0.55,
      sizeAttenuation: true,
    });

    const points = new THREE.Points(geometry, material);
    scene.add(points);

    // ── Animation ────────────────────────────────────────────────
    let count = 0;
    let animationId: number;
    const posAttr = geometry.attributes.position as THREE.BufferAttribute;
    const colAttr = geometry.attributes.color    as THREE.BufferAttribute;
    const posArr  = posAttr.array as Float32Array;
    const colArr  = colAttr.array as Float32Array;

    const animate = () => {
      animationId = requestAnimationFrame(animate);

      let idx = 0;
      for (let ix = 0; ix < AMOUNTX; ix++) {
        for (let iy = 0; iy < AMOUNTY; iy++) {
          const wave =
            Math.sin((ix + count) * 0.28) * 55 +
            Math.sin((iy + count) * 0.45) * 45;

          // Y position driven by wave
          posArr[idx * 3 + 1] = wave;

          // Brightness driven by wave height (peak → brighter green)
          const t = (wave + 100) / 200; // 0→1
          colArr[idx * 3]     = R_BASE + t * 0.05;
          colArr[idx * 3 + 1] = G_BASE * (0.6 + 0.4 * t);
          colArr[idx * 3 + 2] = B_BASE * (0.5 + 0.5 * t);

          idx++;
        }
      }

      posAttr.needsUpdate = true;
      colAttr.needsUpdate = true;
      renderer.render(scene, camera);
      count += 0.07;
    };

    animate();

    // ── Resize ───────────────────────────────────────────────────
    const handleResize = () => {
      const w = container.clientWidth  || window.innerWidth;
      const h = container.clientHeight || window.innerHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    // ── Cleanup ──────────────────────────────────────────────────
    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationId);
      geometry.dispose();
      material.dispose();
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={cn('pointer-events-none absolute inset-0', className)}
      {...props}
    />
  );
}
