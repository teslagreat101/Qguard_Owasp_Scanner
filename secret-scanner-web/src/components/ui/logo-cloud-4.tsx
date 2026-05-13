'use client';
import { cn } from '@/lib/utils';
import { InfiniteSlider } from '@/components/ui/infinite-slider';
import { ProgressiveBlur } from '@/components/ui/progressive-blur';

type Logo = {
  src: string;
  alt: string;
  width?: number;
  height?: number;
};

type LogoCloudProps = React.ComponentProps<'div'> & {
  logos: Logo[];
};

export function LogoCloud({ logos, className, ...props }: LogoCloudProps) {
  return (
    <div
      className={cn(
        'relative w-full overflow-hidden',
        'border-y border-[rgba(0,255,136,0.08)]',
        'bg-[rgba(11,15,12,0.6)] backdrop-blur-sm',
        'py-8',
        className,
      )}
      {...props}
    >
      {/* Top scan-line accent */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px"
        style={{
          background:
            'linear-gradient(90deg, transparent 0%, rgba(0,255,136,0.3) 50%, transparent 100%)',
        }}
      />

      {/* Header label */}
      <div className="mb-6 text-center">
        <p className="text-[10px] font-bold uppercase tracking-[0.25em] text-muted-foreground">
          Positioned to become the Future Trusted security platform of
        </p>
        <p className="mt-1 font-outfit text-sm font-extrabold tracking-tight text-primary">
          Industry Leaders
        </p>
      </div>

      {/* Slider */}
      <div className="relative">
        <InfiniteSlider gap={56} reverse speed={55} speedOnHover={18}>
          {logos.map((logo) => (
            <div
              key={`logo-${logo.alt}`}
              className="flex items-center justify-center opacity-40 transition-opacity duration-300 hover:opacity-80"
            >
              <img
                alt={logo.alt}
                className="pointer-events-none h-5 select-none brightness-0 invert md:h-6"
                height="auto"
                loading="lazy"
                src={logo.src}
                width="auto"
              />
            </div>
          ))}
        </InfiniteSlider>

        {/* Left fade */}
        <ProgressiveBlur
          blurIntensity={0.8}
          className="pointer-events-none absolute top-0 left-0 h-full w-[140px]"
          direction="left"
        />
        {/* Right fade */}
        <ProgressiveBlur
          blurIntensity={0.8}
          className="pointer-events-none absolute top-0 right-0 h-full w-[140px]"
          direction="right"
        />
      </div>

      {/* Bottom scan-line accent */}
      <div
        className="pointer-events-none absolute inset-x-0 bottom-0 h-px"
        style={{
          background:
            'linear-gradient(90deg, transparent 0%, rgba(0,255,136,0.3) 50%, transparent 100%)',
        }}
      />
    </div>
  );
}

/* ── Default logo set ── */
export const defaultLogos: Logo[] = [
  { src: 'https://svgl.app/library/nvidia-wordmark-light.svg',         alt: 'Nvidia' },
  { src: 'https://svgl.app/library/supabase_wordmark_light.svg',       alt: 'Supabase' },
  { src: 'https://svgl.app/library/openai_wordmark_light.svg',         alt: 'OpenAI' },
  { src: 'https://svgl.app/library/turso-wordmark-light.svg',          alt: 'Turso' },
  { src: 'https://svgl.app/library/vercel_wordmark.svg',               alt: 'Vercel' },
  { src: 'https://svgl.app/library/github_wordmark_light.svg',         alt: 'GitHub' },
  { src: 'https://svgl.app/library/claude-ai-wordmark-icon_light.svg', alt: 'Claude AI' },
  { src: 'https://svgl.app/library/clerk-wordmark-light.svg',          alt: 'Clerk' },
];
