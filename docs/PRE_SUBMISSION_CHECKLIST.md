# Pre-submission checklist for GHSA reports

Fill out and attach to every GHSA submission for identity-vertical
findings. Any `NO` means file as a regular issue or hardening PR,
not as a GHSA.

**Target vendor**:
**Finding title**:
**Severity you plan to claim** (CVSS vector):
**identity-trust-hunt scanner version used**:

---

## 1. Provider file read end-to-end

- [ ] I read the ENTIRE provider file, not just the matched line.
- [ ] I noted whether the provider itself returns a trust bit
      (`verified`, `email_verified`, `_trusted`) alongside the
      claim.
- [ ] If a trust bit is present, I checked how downstream consumes
      it.

**Trust bit present?** YES / NO
**If yes, downstream reads it?** YES / NO

---

## 2. Every caller of the provider's output read

- [ ] I grepped for every call site that imports / invokes this
      provider.
- [ ] For each call site, I read the enclosing function.
- [ ] I identified where the provider output ultimately flows to
      an authentication / linking sink.

**Call sites found**: (list)
**Sink identified at**: (file:line)

---

## 3. Sink's enclosing function read to exit

- [ ] I read the enclosing function of the sink end-to-end.
- [ ] I followed every `return`, every early exit, every error
      path.
- [ ] I identified every gate / check between the sink and the
      identity decision.

**Gates found between source and sink**: (list)
**Attack path survives all gates?** YES / NO

---

## 4. Local reproduction

- [ ] I cloned the target repo.
- [ ] I wrote a minimal test case or script that exercises the
      attack path.
- [ ] The test reaches the identity-takeover / data-leak state.
- [ ] I captured output or logs showing the exploit succeeded.

**PoC file / command**:
**Observed result**:

---

## 5. Independent review

- [ ] I asked at least one second reader (human or LLM) to read
      the report against the code.
- [ ] Their one-sentence job was to find a reason this is NOT a
      vulnerability.
- [ ] They either confirmed the finding or raised a specific
      concern.

**Reviewer**:
**Reviewer verdict**:

---

## Severity sanity check

- [ ] CVSS vector reflects the actual attack conditions, not the
      worst-case theoretical.
- [ ] AC (Attack Complexity) is `H` if the attack needs a race,
      specific config, or operator opt-in.
- [ ] PR (Privileges Required) is `L` if the attacker needs an
      account on the vulnerable service; `N` only if truly
      unauthenticated.
- [ ] S (Scope) is `C` only if the attack crosses a trust
      boundary into other components.
- [ ] CVSS justification is written in the report body with
      one line per metric.

---

## Final gate

If any of 1-5 is `NO`, STOP. File as issue or hardening PR, not
GHSA. If severity sanity-check fails, lower the claim before
submitting.

If all 5 are `YES`, submit the GHSA.
