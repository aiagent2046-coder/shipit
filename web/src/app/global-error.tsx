"use client";

// The boundary for the ROOT LAYOUT itself. `error.tsx` beside it catches render
// errors in the routes, but not one thrown by the layout -- and that one still
// blanks the whole site. This file is what catches it.
//
// WHY THE STYLES ARE INLINE HERE AND TAILWIND NEXT DOOR. When this component
// activates it REPLACES the root layout, so it must render its own <html> and
// <body>, and it runs without anything the layout provided: `globals.css` is
// imported by the layout, the font variables are set by the layout, Providers
// are mounted by the layout. Reaching for a Tailwind class or a design-system
// component here would make the fallback depend on the very thing that may have
// just failed. Inline styles and plain elements are the only things guaranteed
// to render.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          padding: 24,
          fontFamily: "system-ui, sans-serif",
          background: "#0b0b0c",
          color: "#e7e7e9",
        }}
      >
        <div style={{ maxWidth: 560, margin: "96px auto" }}>
          <h2 style={{ fontSize: 24, margin: "0 0 12px" }}>
            Something went wrong
          </h2>
          <p style={{ margin: "0 0 20px", lineHeight: 1.5, opacity: 0.8 }}>
            Drydock failed to load. Trying again often works; if it does not,
            the reference below identifies this exact failure in our logs.
          </p>
          <button
            onClick={() => reset()}
            style={{
              font: "inherit",
              padding: "8px 16px",
              borderRadius: 6,
              border: "1px solid #3a3a3f",
              background: "#e7e7e9",
              color: "#0b0b0c",
              cursor: "pointer",
            }}
          >
            Try again
          </button>
          {error.digest ? (
            <p
              style={{
                marginTop: 20,
                fontFamily: "ui-monospace, monospace",
                fontSize: 12,
                opacity: 0.6,
              }}
            >
              Reference: {error.digest}
            </p>
          ) : null}
        </div>
      </body>
    </html>
  );
}
