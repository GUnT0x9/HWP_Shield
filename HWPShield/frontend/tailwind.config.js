/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        risk: {
          clean: '#22c55e',
          suspicious: '#eab308',
          high: '#f97316',
          malicious: '#dc2626',
        }
      }
    },
  },
  plugins: [],
}
