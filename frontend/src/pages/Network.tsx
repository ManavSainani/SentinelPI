import { useState } from "react";
import { api } from "../api/client";
import type { Listener } from "../api/types";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { usePolling } from "../hooks/usePolling";
import ui from "../ui.module.css";

function Baseline({ l }: { l: Listener }) {
  if (l.in_baseline === null) return <span className={ui.muted}>Not compared</span>;
  return l.in_baseline ? (
    <span>Expected</span>
  ) : (
    <span className={ui.chip} style={{ borderColor: "var(--sev-medium)" }}>
      <svg width="12" height="12" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 21 12 12 21 3 12Z" fill="var(--sev-medium)" /></svg>
      New since baseline
    </span>
  );
}

export function Network() {
  const [protocol, setProtocol] = useState("");
  const [exposed, setExposed] = useState(false);
  const n = usePolling(
    `net:${protocol}:${exposed}`,
    (s) => api.listeners({ protocol: protocol || undefined, exposed_only: exposed || undefined }, s),
    15_000,
  );
  return (
    <div>
      <div className={ui.pageHead}>
        <div>
          <h1>Network</h1>
          <p>
            Ports this host is listening on{n.data?.observed_at ? <> at the last check (<Time iso={n.data.observed_at} />)</> : ""}.
            “Reachable from the network” means the port is not limited to this machine.
          </p>
        </div>
      </div>
      <div className={ui.toolbar}>
        <label className={ui.field}>
          Protocol
          <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            <option value="">TCP and UDP</option>
            <option value="tcp">TCP only</option>
            <option value="udp">UDP only</option>
          </select>
        </label>
        <label className={ui.field} style={{ gridAutoFlow: "column", alignItems: "center", gap: 8 }}>
          <input type="checkbox" checked={exposed} onChange={(e) => setExposed(e.target.checked)} />
          Only ports reachable from the network
        </label>
      </div>
      <StaleNotice error={n.data ? n.error : null} updatedAt={n.updatedAt} />
      {n.loading && <Loading what="listening ports" />}
      {n.data === null && n.error && <ErrorBox what="listening ports" error={n.error} onRetry={n.refresh} />}
      {n.data && n.data.baseline_captured_at === null && (
        <p className={ui.muted}>
          No port baseline is approved yet, so new ports cannot be flagged. Approve one on the Pi with{" "}
          <span className={ui.mono}>python -m sentinelpi.detection baseline capture</span>.
        </p>
      )}
      {n.data && n.data.items.length === 0 && <Empty>No listening ports match. Clear a filter, or start the monitor if nothing has been collected.</Empty>}
      {n.data && n.data.items.length > 0 && (
        <div className={`${ui.card} ${ui.tableWrap}`}>
          <table className={ui.table}>
            <caption className="sr-only">Listening ports</caption>
            <thead>
              <tr>
                <th scope="col">Protocol</th>
                <th scope="col" className={ui.right}>Port</th>
                <th scope="col">Address</th>
                <th scope="col">Process</th>
                <th scope="col">Reach</th>
                <th scope="col">Baseline</th>
              </tr>
            </thead>
            <tbody>
              {n.data.items.map((l) => (
                <tr key={`${l.protocol}-${l.port}-${l.local_address}-${l.pid ?? ""}`}>
                  <td>{l.protocol.toUpperCase()}</td>
                  <td className={ui.right}>{l.port}</td>
                  <td className={ui.mono}>{l.local_address}</td>
                  <td>{l.process_name ?? <span className={ui.muted}>unknown</span>}</td>
                  <td>{l.reachable_beyond_loopback ? "Reachable from the network" : "This machine only"}</td>
                  <td><Baseline l={l} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
