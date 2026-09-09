# Model observation acceptance

An audit can finish while most model candidates fail admission. The report now
shows accepted and received observation counts near its coverage summary when
any candidates were excluded. Free baseline and current paid review have their
own counts. The same notice can be derived from historical `model_findings`
records; missing or inconsistent accounting remains unknown.

These are processing facts. Accepted source citations do not establish that the
model's conclusions are correct. Rejection does not establish that a proposed
problem is false. Withdrawing a candidate is distinct from failing a source
citation or response-format check. No score penalty, automatic rescan, or extra
model call is introduced. Numeric legacy API scores remain unchanged.

## API records

New scan manifests include `model_acceptance`, version 1, with `received`,
`accepted`, `rejected`, `source_rejected`, `withdrawn`, `other_rejected`, and
`state`. States describe counts only: `no_candidates`, `none_accepted`,
`partially_accepted`, or `all_accepted`. They do not grade evidence quality.
The canonical `model_findings` counters and original aggregate reasons remain
unchanged. HTML and web notices derive from those counters rather than trusting
a second, possibly inconsistent copy of the summary.

`rejection_diagnostics`, version 1, contains up to 200 `items` per scan and an
`omitted` count. The cap applies across responses and rubrics. Aggregate rejection
counts remain complete after the item cap is reached. Each item retains only:

- Response number, candidate number within that response, and scanner rubric.
- The existing aggregate rejection reason and a bounded diagnostic detail.
- Positive, bounded claimed line coordinates when representable.
- `file_ref`: `sha256:` followed by SHA-256 of the UTF-8 archive path, only when
  that exact path exists in the candidate-source map; otherwise null.

For `source_quote_or_location_mismatch`, detail distinguishes `unknown_file`,
`invalid_line_range`, `quote_missing_or_short`, and `quote_mismatch`. This only
explains an already rejected candidate. It does not relax the existing exact
quote match, adjust coordinates, repair model output, or accept a rejected item.

Rejected titles, explanations, quotations, unknown paths, quote hashes, and
arbitrary model metadata are never persisted through this diagnostic channel.
For a known file, an operator with the original archive can correlate its exact
archive path by calculating the path's SHA-256. No source file is hashed into
`file_ref`. Old reports without item diagnostics cannot retrospectively recover
their rejected candidates.

The diagnostic projection uses fixed field and code allowlists in both report
renderers. Unknown fields are dropped; malformed entries count as omitted.
