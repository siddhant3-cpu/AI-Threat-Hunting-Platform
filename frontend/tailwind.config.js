/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0b0f19",
          card: "rgba(15, 23, 42, 0.6)",
          border: "rgba(255, 255, 255, 0.06)",
          accent: "#3b82f6",
          glow: "#2563eb",
          text: "#f8fafc",
          muted: "#94a3b8",
          success: "#10b981",
          warning: "#f59e0b",
          danger: "#ef4444",
          critical: "#dc2626"
        }
      },
      backdropBlur: {
        xs: "2px",
        md: "12px",
      }
    },
  },
  plugins: [],
}
