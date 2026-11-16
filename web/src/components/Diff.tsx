export function Diff({ text }: { text: string }) {
  const lines = text.replace(/\n$/, "").split("\n");
  return (
    <pre className="diff" aria-label="Changes the agent made">
      {lines.map((l, i) => {
        let cls = "";
        if (
          l.startsWith("+++") ||
          l.startsWith("---") ||
          l.startsWith("diff ") ||
          l.startsWith("index ") ||
          l.startsWith("#")
        )
          cls = "meta";
        else if (l.startsWith("@@")) cls = "hunk";
        else if (l.startsWith("+")) cls = "add";
        else if (l.startsWith("-")) cls = "del";
        return (
          <span key={i} className={cls}>
            {l || " "}
          </span>
        );
      })}
    </pre>
  );
}
