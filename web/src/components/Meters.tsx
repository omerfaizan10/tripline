// Meter list: one ratio per named row, bars aligned on one baseline.
// Fill is the "resolved" green; the track is a lighter step of the same hue.

export type MeterRow = {
  name: string;
  note?: string;
  value: number;
  total: number;
};

export function Meters({ rows, label }: { rows: MeterRow[]; label: string }) {
  return (
    <table className="meters" aria-label={label}>
      <tbody>
        {rows.map((r) => {
          const pct = r.total ? (r.value / r.total) * 100 : 0;
          return (
            <tr key={r.name}>
              <th scope="row">
                {r.name}
                {r.note ? <span className="dim"> {r.note}</span> : null}
              </th>
              <td className="bar">
                <span className="track" aria-hidden="true">
                  <span className="fill" style={{ width: `${pct}%` }} />
                </span>
              </td>
              <td className="fig num">
                {r.value} of {r.total}{" "}
                <span className="dim">({pct.toFixed(0)}%)</span>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
