import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-geist-sans)", "ui-sans-serif", "system-ui"],
        mono: ["var(--font-geist-mono)", "ui-monospace"],
      },
      colors: {
        zen: {
          bg: "#070a10",
          panel: "rgba(15, 20, 32, 0.55)",
          border: "rgba(148, 163, 184, 0.12)",
          accent: "#7dd3fc",
          accent2: "#a78bfa",
          muted: "#94a3b8",
        },
      },
      backgroundImage: {
        "zen-gradient":
          "radial-gradient(1200px 600px at 10% -10%, rgba(125, 211, 252, 0.12), transparent 55%), radial-gradient(900px 500px at 90% 0%, rgba(167, 139, 250, 0.12), transparent 50%), linear-gradient(180deg, #070a10 0%, #05060a 100%)",
      },
      boxShadow: {
        glass: "0 8px 32px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255,255,255,0.04)",
      },
    },
  },
  plugins: [],
};

export default config;
