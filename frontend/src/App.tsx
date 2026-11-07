import { useEffect } from "react";
import { StatusBand } from "./components/StatusBand";
import { StatusProvider } from "./hooks/status";
import { href, useRoute } from "./lib/router";
import { About } from "./pages/About";
import { Events } from "./pages/Events";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Incidents } from "./pages/Incidents";
import { Kiosk } from "./pages/Kiosk";
import { Network } from "./pages/Network";
import { Overview } from "./pages/Overview";
import { Processes } from "./pages/Processes";
import { System } from "./pages/System";
import styles from "./App.module.css";

const NAV = [
  { path: "/", label: "Overview" },
  { path: "/incidents", label: "Incidents" },
  { path: "/events", label: "Events" },
  { path: "/system", label: "System" },
  { path: "/processes", label: "Processes" },
  { path: "/network", label: "Network" },
  { path: "/about", label: "About" },
];

function Page({ segments }: { segments: string[] }) {
  const [first, second] = segments;
  switch (first) {
    case undefined:
      return <Overview />;
    case "incidents":
      return second ? <IncidentDetail id={second} key={second} /> : <Incidents />;
    case "events":
      return <Events />;
    case "system":
      return <System />;
    case "processes":
      return <Processes />;
    case "network":
      return <Network />;
    case "about":
      return <About />;
    default:
      return (
        <p>
          That page does not exist. <a href={href("/")}>Go to the overview</a>.
        </p>
      );
  }
}

export default function App() {
  const { segments } = useRoute();
  const kiosk = segments[0] === "kiosk";

  // A wall display is always dark, whatever the browser's colour-scheme preference says.
  useEffect(() => {
    if (kiosk) document.documentElement.dataset.theme = "dark";
    else delete document.documentElement.dataset.theme;
  }, [kiosk]);

  // The HDMI screen: no navigation, polls even when the tab is not "visible", and the
  // full-screen alert takes over the whole display.
  if (kiosk) {
    return (
      <StatusProvider intervalMs={5000} pauseWhenHidden={false}>
        <Kiosk />
      </StatusProvider>
    );
  }

  const current = "/" + (segments[0] ?? "");
  return (
    <StatusProvider>
      <a className={styles.skip} href="#main">
        Skip to content
      </a>
      <header className={styles.header}>
        <a className={styles.brand} href={href("/")}>
          SentinelPi
        </a>
        <nav aria-label="Main">
          <ul className={styles.nav}>
            {NAV.map((n) => (
              <li key={n.path}>
                <a href={href(n.path)} aria-current={current === n.path ? "page" : undefined}>
                  {n.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      </header>
      <div className={styles.shell}>
        <StatusBand />
        <main id="main" className={styles.main} tabIndex={-1}>
          <Page segments={segments} />
        </main>
      </div>
    </StatusProvider>
  );
}
