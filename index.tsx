import { createFileRoute } from "@tanstack/react-router";
import { lazy, Suspense, useEffect, useState } from "react";

const DeepShieldApp = lazy(() => import("../deepshield/DeepShieldApp"));

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Cyber Citadel — Zero-Trust Security Operations Console" },
      {
        name: "description",
        content:
          "Real-time SOC console for threat detection, incident response, quantum health and AI gateway defense.",
      },
      { property: "og:title", content: "Cyber Citadel — Security Operations Console" },
      {
        property: "og:description",
        content:
          "Real-time SOC console for threat detection, incident response, quantum health and AI gateway defense.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    document.documentElement.classList.add("dark");
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="font-mono text-sm text-muted-foreground">
          Initializing security kernel…
        </p>
      </div>
    );
  }

  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-background">
          <p className="font-mono text-sm text-muted-foreground">
            Loading operations console…
          </p>
        </div>
      }
    >
      <DeepShieldApp />
    </Suspense>
  );
}
