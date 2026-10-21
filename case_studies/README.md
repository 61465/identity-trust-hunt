# Case studies

Each file in this directory is a *public* report on applying
`identity-trust-hunt` to a specific target. The format is uniform so
readers can compare one target to another at a glance:

- **Target** — the repository and the commit scanned.
- **Scanner version** — the exact `identity-trust-hunt` version.
- **Headline** — one line.
- **Provider × claim rows evaluated** — which contracts fired.
- **Confirmed findings** — hits a human reviewer validated as real.
- **False positives surfaced** — hits a human reviewer dismissed, with
  the dismissal reason, so the detector dictionary can tighten over
  time.
- **Vendor channel** — HackerOne, GHSA, email, or "no disclosure
  needed".

Case studies that touch *unfixed* findings live under
`case_studies/_drafts/` and are `.gitignore`d until the vendor's
coordinated-disclosure window closes.
