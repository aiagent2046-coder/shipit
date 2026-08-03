/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    // Tailwind 4 moved the PostCSS plugin into its own package; the bare
    // `tailwindcss` entry that worked in v3 now throws at build time.
    "@tailwindcss/postcss": {},
    // autoprefixer is gone on purpose: v4 handles vendor prefixes itself via
    // Lightning CSS, and running both means two passes over the same rules.
  },
};

export default config;
