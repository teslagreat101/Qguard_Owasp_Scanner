"use client";
import { TypewriterEffectSmooth } from "@/components/ui/typewriter-effect";
import Link from "next/link";

export default function TypewriterEffectSmoothDemo() {
    const words = [
        {
            text: "Build",
        },
        {
            text: "awesome",
        },
        {
            text: "apps",
        },
        {
            text: "with",
        },
        {
            text: "Aceternity.",
            className: "text-primary dark:text-primary",
        },
    ];
    return (
        <div className="flex flex-col items-center justify-center h-screen bg-background ">
            <p className="text-neutral-600 dark:text-neutral-200 text-xs sm:text-base  ">
                The road to freedom starts from here
            </p>
            <TypewriterEffectSmooth words={words} />
            <div className="flex flex-col md:flex-row space-y-4 md:space-y-0 space-x-0 md:space-x-4">
                <button className="w-40 h-10 rounded-xl bg-background border dark:border-white border-transparent text-foreground text-sm">
                    Join now
                </button>
                <Link href="/">
                    <button className="w-40 h-10 rounded-xl bg-white text-black border border-black  text-sm">
                        Back Home
                    </button>
                </Link>
            </div>
        </div>
    );
}
