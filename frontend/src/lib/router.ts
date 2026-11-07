import { useEffect, useState } from "react";

/** Hash routing ("#/incidents/abc"): no server rewrite rules needed, works from any host. */
function currentPath(): string {
  const raw = window.location.hash.replace(/^#/, "");
  return raw === "" ? "/" : raw.split("?")[0];
}

export function useRoute(): { path: string; segments: string[] } {
  const [path, setPath] = useState(currentPath);
  useEffect(() => {
    const onChange = () => setPath(currentPath());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return { path, segments: path.split("/").filter(Boolean) };
}

export const href = (path: string): string => `#${path}`;
