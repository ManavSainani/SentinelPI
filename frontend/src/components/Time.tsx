import { formatDateTime } from "../lib/format";

/** Local time for reading; the exact UTC instant is in the tooltip and the datetime attribute. */
export function Time({ iso }: { iso: string }) {
  return (
    <time dateTime={iso} title={`${iso} (UTC)`} style={{ whiteSpace: "nowrap" }}>
      {formatDateTime(iso)}
    </time>
  );
}
