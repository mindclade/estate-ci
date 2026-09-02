import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Estate CI | Mindclade",
  description: "Mindclade repository qualification and governed operations",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
