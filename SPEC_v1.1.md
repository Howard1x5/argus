# PROJECT SPEC: ARGUS — Automated Response & Guided Unified Security

**Created:** February 27, 2026
**Updated:** March 1, 2026
**Status:** In Progress
**Version:** 1.1
**Author:** Clint Howard
**Interview System:** Level 3 Spec System (Phase 2 Output)

---

## 1. CONTEXT

### What This Is

ARGUS is a CLI-based automated Incident Response analysis pipeline. An analyst feeds it an evidence directory containing any mix of supported forensic artifacts — EVTX files, Excel-exported event logs, IIS/Apache/Nginx web logs, PCAPs, memory dumps, registry hives, prefetch files, CSV exports, Zeek logs, and cloud logs (AWS CloudTrail, Azure AD, GCP audit). ARGUS runs the full IR workflow — triage, deep multi-domain analysis via LLM-powered agents, cross-system correlation, forensic validation, IOC extraction/enrichment, MITRE ATT&CK mapping, Sigma rule generation, evidence figure generation with captions, and professional PDF report output — producing a complete, defensible deliverable package.

ARGUS is named after Argus Panoptes, the all-seeing giant of Greek mythology with 100 eyes. After Argus was slain, Hera placed his eyes on the peacock's tail. The tool's identity includes an ASCII peacock or stylized eye motif in its banner.

### Who This Is For

- **Primary user:** Clint Howard (the developer), for use on IR challenges and real engagements
- **Secondary users:** Other IR/DFIR analysts who download the open-source tool
- **Audience for output:** IR leads, CISOs, technical reviewers who will scrutinize findings under interview-level questioning
- **Distribution:** Open-source on GitHub, shared with prospective employers as a portfolio piece

### What Success Looks Like

You run `argus analyze ./case-001` and within 30-60 minutes you have a `output/` directory containing: a 25-40 page professional PDF report with evidence figures and analyst note placeholders, validated IOC lists, MITRE ATT&CK mapping, Sigma detection rules, a detection strategy brief, a validation appendix with claim traceability, and a validation failures log. The report quality matches or exceeds the Trigonous IR Report produced manually during the Daylight Security engagement. Every claim in the report is traceable to raw evidence. No hallucinations survive to the final output.

### What Failure Looks Like

1. **Shallow analysis** — ARGUS finds the obvious indicators but misses encoded PowerShell commands, behavioral timing patterns, cross-system correlation, and absence-based findings.
2. **Manual handback** — ARGUS tells the analyst to "manually review the IIS logs" instead of analyzing them itself.
3. **Phantom findings** — A claim appears in the report but the evidence doesn't exist. Worst failure mode.
4. **Hallucination passing validation** — The entity exists but the interpretation is wrong (e.g., whoami classified as privesc instead of recon).
5. **Report bloat** — Output too dense to be usable.
6. **Agent blindness** — Agents receive tiny samples and miss critical findings. This was the v1.0 failure. Fixed in v1.1 via ForensicExtractor.

### Platform & Environment

- **Primary target:** REMnux (Linux-based forensic distribution)
- **Secondary target:** Ubuntu/Debian with clean install instructions
- **Language:** Python 3.8+
- **LLM dependency:** Anthropic Claude API (user provides their own API key)
- **Package manager:** pip

### Architecture Lesson from v1.0 Build (CRITICAL)

The initial build revealed a fundamental problem: LLM agents receiving small event samples (~0.3% of data) could not replicate manual analysis quality. Manual analysis worked because the analyst queried 100% of data iteratively: query → observe → dig deeper → query again.

**The v1.1 pivot: "Programmatic Investigator + LLM Interpreter"**
- Python code does exhaustive, targeted extraction from the FULL dataset (all 28,958+ events)
- All decoding (base64, URL encoding), correlation, and process tree building happens programmatically
- LLM agents receive COMPLETE extraction results for their domain — not samples
- Agents focus on INTERPRETATION (reasoning about behavior, timing, intent) — not DISCOVERY (finding needles in haystacks)

This eliminates sampling, duplicated detection logic, and agent blindness.

---

## 2. BEHAVIOR

### Pipeline Architecture

```
Phase 0:   INIT
Phase 1:   INGEST
Phase 2:   TRIAGE (2-pass: programmatic + 5 LLM triage agents)
Phase 2.5: HYPOTHESIS GENERATION
Phase 3a:  FORENSIC EXTRACTION (programmatic — queries full dataset, decodes, correlates)
Phase 3b:  DEEP ANALYSIS (9 LLM agents interpret extractions + 1 synthesizer)
Phase 4:   VALIDATION (Forensic Validation Engine — pure programmatic)
Phase 5:   IOC EXTRACTION & ENRICHMENT
Phase 6:   DETECTION ENGINEERING
Phase 7:   REPORT GENERATION (pause for analyst notes)
Phase 8:   OUTPUT PACKAGING
```

### CLI Interface

ASCII art banner (Argus Panoptes / peacock motif) prints on every command invocation.

```bash
argus init ./case-001              # Create case directory with config template
argus analyze ./case-001           # Run full pipeline
argus triage ./case-001            # Run only Phase 0-2.5
argus report ./case-001            # Regenerate report from existing analysis
argus finalize ./case-001          # Convert reviewed draft to PDF + package
argus status ./case-001            # Show pipeline progress
argus run-phase 3 ./case-001       # Re-run a single phase
argus run-phase 3 ./case-001 --guidance notes.md  # Re-run with guidance
argus resume ./case-001            # Resume from last completed phase
argus enrich ./case-001            # Run/re-run IOC enrichment
argus debrief ./case-001           # Post-case lessons learned (LLM-guided)
argus list                         # List all tracked cases
argus add-pattern "name" --regex "pattern"
argus add-false-positive "description"
```

Default: progress bar. `--verbose` for streaming. Full log always at `./case-001/logs/argus.log`.
Resume: completion markers per phase. Incomplete phases restart from scratch.

### Phase 0: INIT

Create case directory, copy evidence, SHA-256 hash all files, set evidence read-only, generate argus.yaml. No manual systems input — auto-detected in Phase 1.

### Phase 1: INGEST

Verify evidence integrity (re-hash). Auto-detect file types. Parse through modular parsers. Normalize to unified event schema (timestamp_utc, source_system, event_type, event_id, severity, source_ip, dest_ip, username, process_name, process_id, parent_process_name, parent_process_id, command_line, parent_command_line, raw_payload, source_file, source_line). Store as Parquet. Auto-detect systems. Flag unparseable files with reasons.

Supported formats: .xlsx (with multi-format Payload handling), .evtx, .log (IIS/Apache/Nginx), .csv, .pcap/.pcapng, .dmp/.raw/.vmem, registry hives, .pf, .json (CloudTrail/Azure/GCP), Zeek logs.

### Phase 2: TRIAGE

**2a: Programmatic Scan** — Event ID distribution, timeline/histogram, unique entities, web stats, regex pattern scan (PowerShell, LOLBins, lateral movement, credential tools, web attacks, base64, custom patterns from ~/.argus/pattern_library/).

**2b: 5 LLM Triage Agents** (receive triage summary, not raw events):
- T1: Pattern Gap Hunter (what regex missed)
- T2: Behavioral Anomaly (timing, volume, statistical outliers)
- T3: Cross-Source Correlation (connections between evidence sources)
- T4: Absence & Evasion (what's missing that should be there)
- T5: Identity & Privilege Context (role-based analysis)

**2c: Merge** — Deduplicate programmatic + agent findings.

**2d: Hypothesis Generation** — Rule-based + one LLM call. Ranked hypotheses guide Phase 3.

### Phase 3a: FORENSIC EXTRACTION (Programmatic Investigator) — CRITICAL

**100% PROGRAMMATIC. NO LLM. QUERIES FULL DATASET.**

This is the architectural fix for v1.0 agent blindness. The ForensicExtractor runs exhaustive, targeted queries against ALL Parquet data. All decoding happens here. All process tree building happens here. All cross-source correlation happens here.

**11 Extraction Categories:**

1. **Process Trees** — Build COMPLETE trees from Sysmon EID 1 + Windows EID 4688. Full chains: grandparent → parent → child → grandchild. Pre-flag suspicious parent-child (w3wp→cmd, services.exe spawns).

2. **Web Attacks** — ALL web server worker child processes. ALL requests to suspicious URIs. ALL command-like query params. ALL POST to upload endpoints. Cross-reference: web request timestamp → process creation timestamp (link request to execution).

3. **Encoded Content Decoding** — FIND and DECODE all base64 (handle UTF-16LE, UTF-8, nested). DECODE all URL-encoded content from web logs. DECODE all PowerShell -EncodedCommand. Note certutil -decode operations.

4. **Credential Access** — ALL procdump/mimikatz/lsass/SAM/NTDS references. ALL EID 4648/4769/4771/4776. ALL LSASS access (Sysmon 10). Cross-reference: credential tool → subsequent logon.

5. **Lateral Movement** — ALL EID 4624 Type 3 from internal IPs. ALL Type 10 (RDP). ALL EID 4648. ALL Sysmon 3 to 445/135/139/5985/3389. ALL WMI/WinRM spawns. Cross-system: outbound on A → logon on B (±5 sec).

6. **Persistence** — ALL EID 7045 services. ALL Sysmon 13 on Run/Services/COM keys. ALL EID 4698 scheduled tasks. ALL Sysmon 11 in startup/system32/Tasks. Flag random names, cmd in ImagePath.

7. **Network & C2** — ALL Sysmon 3 with process names. ALL Sysmon 22 DNS. ALL external connections with process context. PCAP analysis if available (top talkers, beaconing, TLS SNI).

8. **Authentication Timeline** — ALL auth events across all systems. Per-user timeline. Brute force patterns. First-time logons from new sources.

9. **File Operations** — ALL Sysmon 11/23/15. Flag Temp/Public/inetpub files. Cross-reference: file creation → subsequent execution.

10. **Absence & Gaps** — Event cadence analysis. Gap detection. Log boundary context. Missing Event ID types. EID 1102/104 (log cleared).

11. **Unified Timeline** — Merge ALL events chronologically. Second-by-second for attack window. Tag each event with source.

Output: `extractions/` directory with one JSON per category + `extraction_summary.json`.

### Phase 3b: DEEP ANALYSIS (LLM Interpreter)

9 agents + 1 synthesizer. Each receives COMPLETE extraction results for their domain (from Phase 3a). NOT sampled events.

Agent job is INTERPRETATION: reasoning about behavior, timing, intent, attack narrative. NOT discovery.

**Agents:**
1. Process Tree Analyst → receives `process_trees.json`
2. File Operations Analyst → receives `file_operations.json`
3. Registry & Persistence Analyst → receives `persistence.json`
4. Network & C2 Analyst → receives `network.json`
5. Service Analysis Specialist → receives `persistence.json` (service subset)
6. Auth & Lateral Movement Analyst → receives `credential_access.json` + `lateral_movement.json` + `auth_timeline.json`
7. Cross-System Correlation Analyst → receives `unified_timeline.json` + `lateral_movement.json`
8. PowerShell & Encoded Content Analyst → receives `decoded_content.json` + process context
9. Anomaly & Absence Analyst → receives `absence_analysis.json` + `extraction_summary.json`
10. Master Synthesizer → reads ALL agent outputs, creates unified reconstruction

All agents output structured claims per FVE spec (claim_id, summary, affected_entities, timestamp_range, log_sources, event_ids, detection_method, query_used, confidence, mitre_technique, raw_evidence_refs, assumptions, inferred_vs_direct).

### Phase 4: VALIDATION (FVE)

100% PROGRAMMATIC. Validates every claim against raw Parquet:
- Entity existence check
- Timestamp consistency (±2 sec configurable)
- Event ID correctness
- Quote/string verification
- Cross-reference integrity
- Contradiction detection
- Duplicate detection

Outcomes: VERIFIED, PARTIALLY_VERIFIED, UNVERIFIED, CONTRADICTED, FAILED.

Outputs: validated_claims.json, validation_failures.md (with manual review instructions), claim_traceability.json/.md, hallucination_log.json.

Feedback loop: if claims reference entities not in triage, warn about triage gaps.

### Phase 5: IOC EXTRACTION & ENRICHMENT

Extract IOCs (IPs, domains, URLs, hashes, emails) excluding RFC 1918/internal. Enrich via VT/AbuseIPDB/URLhaus/OTX if keys configured. Cache results. Risk score. Graceful degradation without keys.

### Phase 6: DETECTION ENGINEERING

MITRE ATT&CK mapping from validated claims. Sigma rules for confirmed TTPs. Detection strategy brief (LLM): risk-ranked TTPs, detection layers, coverage gaps, false positive guidance.

### Phase 7: REPORT GENERATION

Generate evidence figures (YAML config + HTML + screenshot). Build report markdown (Executive Summary, Scope, Timeline, Attack Chain, IOCs, MITRE, Affected Systems, Root Cause, Recommendations, Appendices). Insert [ANALYST NOTE] placeholders with context-specific prompts and verification references. Generate validation appendix. PAUSE for analyst review.

### Phase 7.5-7.6: ANALYST REVIEW + FINALIZE

Analyst fills in notes via dictation. `argus finalize` checks for unfilled placeholders, converts to PDF via WeasyPrint.

### Phase 8: OUTPUT PACKAGING

Copy deliverables to output/. Generate README. Display summary with timing/cost.

### Post-Pipeline: DEBRIEF

`argus debrief` — LLM-guided post-case interview. Suggests pattern library additions. Analyst approves.

---

## 3. CONSTRAINTS

### Must NOT Do

1. Never modify original evidence files (SHA-256 verified, read-only)
2. Never silently drop findings or errors
3. Never make analytical decisions without analyst knowledge
4. Never store API keys in plaintext
5. Never send raw evidence to LLM without size/content controls
6. Never generate final report with unvalidated claims
7. Never assume the attack narrative
8. Never log case data outside case directory
9. Never transmit evidence to any endpoint other than configured LLM API
10. Never execute remediation actions
11. Never interact with live systems
12. Never present LLM analysis as validated fact without FVE approval
13. Never include case data from one case in another's output
14. Never make unbounded API calls (configurable ceiling, default ~$10-15)
15. **Never sample events when full extraction is possible.** ForensicExtractor must query 100% of dataset. If token limits require reduction for agents, summarize extraction results — never sample raw events.

### Hard Requirements

All evidence formats listed in Phase 1. Timestamps normalized to UTC. Excel export limitations auto-detected and warned. Sysmon absence warned. OS-version-aware Event ID mapping. Internal IP filtering for IOC extraction.

### Directory Structure

```
~/.argus/
├── config.yaml, cases.log
├── lessons_learned/
└── pattern_library/ (custom_regex.yaml, false_positives.yaml)

case-001/
├── argus.yaml
├── evidence/ (read-only, hashed)
├── parsed/ (Parquet)
├── triage/ (Phase 2)
├── extractions/ (Phase 3a — NEW in v1.1)
│   ├── process_trees.json, web_attacks.json, decoded_content.json
│   ├── credential_access.json, lateral_movement.json, persistence.json
│   ├── network.json, auth_timeline.json, file_operations.json
│   ├── absence_analysis.json, unified_timeline.json
│   └── extraction_summary.json
├── analysis/ (Phase 3b agents + synthesis)
├── validation/ (Phase 4)
├── iocs/ (Phase 5)
├── detection/ (Phase 6: mitre, sigma_rules/, strategy)
├── report/ (Phase 7: figures/, draft, final, PDF)
├── logs/ (argus.log, token_usage.json, phase_completions/)
└── output/ (Phase 8: final deliverables)
```

### Public vs Non-Public Repository Content

**Public (included in open-source repository):**
- `src/argus/` — All production code (parsers, phases, agents, extraction, validation)
- `tests/` — Unit and integration tests
- `README.md`, `CONTRIBUTING.md`, `LICENSE`
- `pyproject.toml`, `requirements.txt`
- `SPEC_v1.1.md` — This specification document

**Non-Public (excluded via .gitignore, kept locally):**
- `~/.argus/` — User configuration, API keys, lessons learned
- `case-*/` — All case directories with evidence and analysis
- Legacy specification documents and development notes
- Personal notes and preparation documents
- Internal architecture analysis documents
- Any files containing case data, client information, or sensitive findings

**Rationale:** The tool itself is open-source and shareable. Case data, personal notes, and development artifacts that may contain sensitive information are never committed.

### Error Handling

- Unparseable files: parse everything first, then flag with reasons
- Missing API keys: skip enrichment, continue, can add later
- Failed validation: flag with review instructions, never silently drop
- API failures: exponential backoff, save progress, notify user
- Contradictions: present both, never pick one
- Extraction too large for LLM context: summarize by severity, note full data available

### Development & Contribution Guidelines

**Repository Structure:**

This project uses a two-folder development model:
- **Local development folder** — Working copies, private notes, case data, test evidence. No git remote configured.
- **Public repository folder** — Production code only. Connected to GitHub.

**Workflow:**
1. All development happens in the local development folder
2. When ready to publish, copy public files to the public repository folder
3. Commit and push from the public repository only
4. The local folder intentionally has no remote to prevent accidental pushes

**Pre-commit Hook:**
A pre-commit hook (`.githooks/pre-commit`) scans for accidental inclusion of:
- Personal paths, home directories
- API keys, tokens, credentials
- Private IP addresses
- Connection strings

To enable: `git config core.hooksPath .githooks`

**Commit Messages:**
- Use conventional commit format: `type(scope): description`
- Types: feat, fix, refactor, docs, test, chore
- Keep messages concise and descriptive of the actual change
- Do NOT include references to AI assistants, LLM tools, or code generation tools in commit messages
- Commit messages should read as if written by the developer, describing what changed and why

### Domain Rules

1. Timestamps normalized to UTC. Mixed timezone flagged.
2. Excel exports lose fidelity. Auto-detect, warn, adjust confidence.
3. Payload column has multiple JSON formats. Handle all three.
4. Process trees require Sysmon. Warn if absent.
5. Cross-source clock skew. Use tolerance windows.
6. Internal IPs filtered from IOCs.
7. Event IDs are OS-version dependent.
8. Base64 decoding handles UTF-16LE, UTF-8, nested/double encoding.
9. Detection logic lives in ONE place. ForensicExtractor + shared pattern library. No duplication.

---

## 4. EXAMPLES

### Good Output

ForensicExtractor finds ALL 30 w3wp.exe children, decodes ALL 11 base64 commands, identifies ProcDump LSASS dump, file rename to cool_pic.png, 5 failed WMI attempts, successful Invoke-SMBExec, all 6 services, Pastebin download, log termination at 09:09:42, 70-minute gap. Agents interpret the complete extractions. Report: 25-40 pages, 29 figures, 6 Sigma rules, 15 MITRE techniques.

### Bad Output (Avoid)

1. Agent blindness from sampling (v1.0 failure — fixed by ForensicExtractor)
2. Manual handback (unacceptable)
3. Phantom findings (FVE + analyst review catches)
4. Report bloat (25-40 pages max for this scope)
5. Duplicated detection logic (single source of truth in ForensicExtractor)

---

## 5. TASK DECOMPOSITION

### Task 1: Project Scaffolding
CLI, ASCII banner, directory structure, argus init. **Checkpoint: Yes**

### Task 2: User Profile & Setup
argus setup, API key storage, pattern library scaffolding. **Checkpoint: No**

### Task 3: Evidence Parser Framework
Modular parsers for all formats. Unified schema. Parquet output. Auto-detection. **Checkpoint: Yes**

### Task 4: Phase 0-1 (INIT + INGEST)
Case setup, evidence copy/hash, parsing, normalization, system detection. **Checkpoint: Yes**

### Task 5: Phase 2a (Programmatic Triage)
Event distribution, timeline, entities, patterns. **Checkpoint: No**

### Task 6: Phase 2b (LLM Triage Agents)
5 agents (T1-T5). Agent framework with prompt templates, JSON output, error handling. **Checkpoint: Yes**

### Task 7: Phase 2c-2d (Merge + Hypotheses)
Finding merger, hypothesis generator. **Checkpoint: No**

### Task 8: Phase 3a (ForensicExtractor) — MOST CRITICAL TASK
All 11 extraction categories against 100% of data. All decoding. All tree building. All correlation.
**VALIDATION:** Must find against Trigonous data: all 30 w3wp children, all 11 decoded base64 commands, ProcDump LSASS (pd.exe -accepteula -ma 588), file move (dumpfile.dmp→cool_pic.png), 5 failed WMI attempts, successful Invoke-SMBExec, all 6 random services with decoded ImagePaths, Pastebin download (e.ps1), log termination at 09:09:42, 70-minute recon gap. If ANY missing, ForensicExtractor is incomplete.
**Checkpoint: Yes — review extraction completeness thoroughly**

### Task 9: Phase 3b (Deep Analysis Agents)
9 agents + synthesizer receiving COMPLETE extractions. Structured claims per FVE spec. **Checkpoint: Yes**

### Task 10: Phase 4 (FVE Validation)
Programmatic validation engine. All 7 check types. Generate all outputs. **Checkpoint: Yes**

### Task 11: Phase 5 (IOC)
Extraction, enrichment, caching, graceful degradation. **Checkpoint: No**

### Task 12: Phase 6 (Detection Engineering)
MITRE mapping, Sigma rules, detection strategy brief. **Checkpoint: No**

### Task 13: Phase 7 (Report Generation)
Figure generator, report builder, analyst placeholders, validation appendix, PAUSE. **Checkpoint: Yes**

### Task 14: Phase 7.5-7.6 (Finalize)
argus finalize, PDF conversion. **Checkpoint: No**

### Task 15: Phase 8 (Output Packaging)
Copy deliverables, README, summary. **Checkpoint: No**

### Task 16: Resume, Run-Phase, Status
--resume, run-phase N --guidance, status. **Checkpoint: No**

### Task 17: Debrief & Pattern Library
argus debrief, pattern management, lessons learned. **Checkpoint: No**

### Task 18: Integration Testing Against Trigonous
Full pipeline against Trigonous evidence. Compare to manual findings. ALL Task 8 items in final report. **Checkpoint: Yes**

### Task 19: Documentation & Polish
README, CONTRIBUTING, inline docs. **Checkpoint: Yes**

---

## 6. CHANGE LOG

### v1.1 (March 1, 2026)

⚠️ MODIFIED — Phase 3: Split into Phase 3a (ForensicExtractor) + Phase 3b (LLM Agents)
- **Original:** Agents received sampled raw events
- **Changed to:** ForensicExtractor queries 100% of data programmatically; agents receive complete extraction results
- **Reason:** v1.0 agents saw 0.3% of events, missed 67% of findings
- **Spec gap:** Should have specified data coverage requirements for agents

⚠️ MODIFIED — Added Constraint #15: Never sample when full extraction possible
- **Reason:** Sampling was root cause of agent blindness

⚠️ MODIFIED — Added Bad Output Pattern: Agent Blindness
- **Reason:** Actual failure mode encountered during v1.0 build

⚠️ MODIFIED — Added extractions/ directory to case structure
- **Reason:** Phase 3a/3b separation requires dedicated output location

⚠️ MODIFIED — Added Domain Rules #8 (multi-encoding base64) and #9 (single-source detection logic)
- **Reason:** v1.0 had duplicated detection logic across 3 files
