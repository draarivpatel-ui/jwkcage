/* Bounded fail-closed severity-aware finding truncation. */
const RANK = Object.freeze({ critical: 4, high: 3, medium: 2, low: 1, info: 0 });

function rank(hit) {
  return RANK[hit.severity] === undefined ? 0 : RANK[hit.severity];
}

export function pushCappedFinding(findings, hit, cap) {
  if (findings.length < cap) {
    findings.push(hit);
    return false;
  }
  const hitRank = rank(hit);
  for (let index = findings.length - 1; index >= 0; index -= 1) {
    if (rank(findings[index]) < hitRank) {
      findings[index] = hit;
      return true;
    }
  }
  return true;
}

export function capFindings(allFindings, cap) {
  const limited = [];
  let truncated = false;
  for (const hit of allFindings) {
    if (pushCappedFinding(limited, hit, cap)) truncated = true;
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const hit of limited) {
    if (counts[hit.severity] !== undefined) counts[hit.severity] += 1;
  }
  return { limited, counts, truncated };
}
