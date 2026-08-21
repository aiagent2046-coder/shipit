import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/providers";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";

const inter = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Drydock — Your AI Production Engineer",
  description:
    "Drydock is the AI production engineer for AI-generated repos. Paste a GitHub URL or upload a zip: it audits your app, scores production-readiness out of 10, and ships the fixes as a pull request.",
  // Proof to enot.io that whoever controls this domain also controls the
  // merchant account being opened against it. Their checker fetches the home
  // page and looks for `<meta name="enot" content="...">`; Next renders this
  // into the server HTML, so it is there before any JavaScript runs.
  //
  // NOT A SECRET. It is the first segment of the onboarding connection id,
  // readable by anyone who views source -- which is the point, since the
  // checker reads it unauthenticated. It proves control of the domain and
  // grants nothing.
  //
  // WHY HERE AND NOT A FILE IN public/. enot.io also accepts an
  // `enot_<token>.html` at the site root. A bare token file has nowhere to
  // carry this explanation, so in six months it reads as debris and gets
  // tidied away -- silently un-verifying the merchant account. In the layout
  // it is a line of reviewed code with a reason attached.
  //
  // SAFE TO DELETE once enot.io is confirmed to be the payment provider and
  // the account is live -- verification is checked at onboarding, not
  // continuously. Delete it also if enot.io is NOT chosen: an unused claim
  // pointing at a provider we never signed with is worse than nothing.
  other: { enot: "5b5e6a26" },
};

// Set the theme class before hydration so there's no flash of the wrong
// theme. Dark is the default identity; a stored choice or system light
// preference overrides it.
const themeScript = `(function(){try{var t=localStorage.getItem('shipit-theme');if(!t){t=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';}document.documentElement.classList.toggle('dark',t!=='light');document.documentElement.style.colorScheme=t;}catch(e){document.documentElement.classList.add('dark');}})();`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${inter.variable} ${mono.variable}`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className="flex min-h-screen flex-col bg-bg font-sans text-text antialiased">
        <Providers>
          <Header />
          <main className="flex-1">{children}</main>
          <Footer />
        </Providers>
      </body>
    </html>
  );
}
