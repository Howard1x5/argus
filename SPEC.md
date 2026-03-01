# PROJECT SPEC: ARGUS — Automated Response & Guided Unified Security

**Created:** February 27, 2026
**Status:** Draft
**Version:** 1.0
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

1. **Shallow analysis** — ARGUS finds the obvious indicators (failed logons, service installations) but misses encoded PowerShell commands, behavioral timing patterns, cross-system correlation, and absence-based findings. The report reads like a junior analyst's first attempt.
2. **Manual handback** — ARGUS generates partial findings and tells the analyst to "manually review the IIS logs for webshell indicators" instead of analyzing them itself. Work that should be automated gets pushed back to the human.
3. **Phantom findings** — A claim appears in the report, the analyst goes to validate it per the traceability instructions, and the evidence doesn't exist. This wastes analyst time and destroys trust in the tool. This is the worst failure mode.
4. **Hallucination passing validation** — The entity exists in the logs but the interpretation is wrong (e.g., `whoami` classified as privilege escalation instead of reconnaissance). The FVE catches entity existence but misses semantic errors.
5. **Report bloat** — Output is technically correct but so dense it's unusable. Every paragraph must earn its place.

### Platform & Environment

- **Primary target:** REMnux (Linux-based forensic distribution) — provides tshark, volatility, yara, and most forensic tooling pre-installed
- **Secondary target:** Ubuntu/Debian with clean install instructions
- **Language:** Python 3.8+
- **LLM dependency:** Anthropic Claude API (user provides their own API key)
- **Package manager:** pip

### What Already Exists (Prototype Reference)

The Trigonous IR project serves as the prototype. Key files from that project that inform this design:

- `elite_ir_toolkit.py` — Monolithic analysis tool (1,270 lines) with threat intel DB, process tree analysis, recursive analysis passes. **Lesson:** Good analysis logic, but hardcoded paths, no modularity, no CLI interface.
- `triage_all.py` / `triage_eventids.py` / `triage_timeline.py` — Individual triage scripts. **Lesson:** Right approach (small focused scripts), but no orchestration layer.
- `generate_evidence_figures.py` + `figures_config.yaml` + `figure_template.html` — YAML-driven evidence figure generation with HTML rendering and Firefox headless screenshots. **Lesson:** Excellent concept, keep this architecture.
- `generate_sigma_rules.py` — Generates Sigma rules from analysis findings. **Lesson:** Good output, needs to be driven by validated claims instead of hardcoded patterns.
- `generate_final_report.py` — Report generator from JSON analysis outputs. **Lesson:** Right structure, needs FVE integration and analyst note placeholders.
- `threat_intel.py` — IOC extraction and enrichment with API caching. **Lesson:** Good design with rate limiting and caching, keep this pattern.
- `md_to_pdf.py` — Markdown to PDF via WeasyPrint with professional CSS. **Lesson:** Clean output, keep the CSS and approach.
- `deep_analysis.py` — Deep forensic analysis with MITRE mappings and confidence scores. **Lesson:** Good MITRE mapping structure, move to validated claims model.
- `AGENT_ARMY_TEMPLATE.md` — Template for 9 parallel analysis agents + synthesizer. **Lesson:** The agent architecture worked. Formalize it with structured claim output.
- `CLAUDE_CODE_IR_INSTRUCTIONS.md` — Phased analysis instructions. **Lesson:** The phase breakdown was sound. This becomes the pipeline architecture.
- `additional-spec.md` (Forensic Validation Engine) — Specification for ensuring every claim is traceable, reproducible, validated, confidence-scored, and defensible. **Lesson:** This becomes Phase 4 of the pipeline.
- `PROJECT_INTAKE_RETROSPECTIVE.md` — Post-project lessons learned. **Lesson:** Key gaps identified include upfront deliverable definition, audience identification, evidence format detection, and automation vs. manual decision points.

---

## 2. BEHAVIOR

### Pipeline Architecture

```
Phase 0: INIT
Phase 1: INGEST
Phase 2: TRIAGE (2-pass: programmatic + 5 LLM triage agents)
Phase 2.5: HYPOTHESIS GENERATION
Phase 3: DEEP ANALYSIS (9 LLM agents + 1 synthesizer)
Phase 4: VALIDATION (Forensic Validation Engine — pure programmatic)
Phase 5: IOC EXTRACTION & ENRICHMENT
Phase 6: DETECTION ENGINEERING
Phase 7: REPORT GENERATION (pause for analyst notes)
Phase 8: OUTPUT PACKAGING
```

### CLI Interface

ASCII art banner (Argus Panoptes / peacock motif) prints on every command invocation. Clean subcommand structure:

```bash
argus init ./case-001              # Create case directory with config template
argus analyze ./case-001           # Run full pipeline (all phases)
argus triage ./case-001            # Run only Phase 0-2.5
argus report ./case-001            # Regenerate report from existing analysis
argus finalize ./case-001          # Convert reviewed draft to PDF + package output
argus status ./case-001            # Show pipeline progress (which phases complete)
argus run-phase 3 ./case-001       # Re-run a single phase
argus run-phase 3 ./case-001 --guidance notes.md  # Re-run with analyst guidance doc
argus resume ./case-001            # Resume from last completed phase
argus enrich ./case-001            # Run/re-run IOC enrichment separately
argus debrief ./case-001           # Post-case lessons learned interview (LLM-guided)
argus list                         # List all cases tracked by ARGUS
argus add-pattern "name" --regex "pattern"        # Add to pattern library
argus add-false-positive "description"            # Add to false positive list
```

**Default verbosity:** Progress bar with phase indicators. `--verbose` flag streams real-time detail. Full log always written to `./case-001/logs/argus.log`.

**Resume behavior:** Each phase writes a completion marker (`phase_N.complete` with timestamp + checksum) on successful completion. `--resume` starts from the first incomplete phase. Incomplete phases restart from scratch — no partial phase recovery. Clean "cattle not pets" approach.

### Phase 0: INIT

**Trigger:** `argus init ./case-name`

**User inputs:** Case name, date (defaults to today), evidence path (directory or file list).

**Actions:**
1. Create case directory structure (see Section 3: Directory Structure)
2. Copy all evidence files from source path into `evidence/` directory
3. Compute SHA-256 hash of every evidence file, store in `evidence/hashes.json`
4. Set evidence directory to read-only permissions (`chmod -R 444 evidence/`)
5. Generate `argus.yaml` case config with metadata
6. Write `phase_0.complete` marker

**No systems input required.** Systems are auto-detected in Phase 1.

### Phase 1: INGEST

**Trigger:** Automatic after Phase 0, or `argus run-phase 1`

**Actions:**
1. Verify evidence integrity (re-hash and compare against `evidence/hashes.json`). If any file modified, HALT with critical error.
2. Auto-detect file types for each evidence file:
   - `.evtx` → EVTX parser
   - `.xlsx` → Excel event log parser (with Payload column multi-format handling)
   - `.log` → Auto-detect W3C IIS, Apache Combined, Nginx, or generic
   - `.csv` → CSV event parser with header detection
   - `.pcap` / `.pcapng` → PCAP parser (via tshark)
   - `.dmp` / `.raw` / `.vmem` → Memory dump (via volatility)
   - `.reg` / registry hives → Registry parser
   - `.pf` → Prefetch parser
   - `.json` → Cloud log parser (detect CloudTrail, Azure AD, GCP format)
   - `.zeek` / `.log` (Zeek format) → Zeek log parser
   - Unknown → Flag as unparseable with suggested reason
3. Parse each file through appropriate parser module
4. Normalize all events into unified event schema (common fields: timestamp_utc, source_system, event_type, event_id, severity, source_ip, dest_ip, username, process_name, command_line, raw_payload, source_file, source_line)
5. Store normalized data as Parquet files in `parsed/` directory
6. Auto-detect systems from parsed data (hostnames, IPs, OS types, roles)
7. Present detected systems: "Systems identified: [list]. Any additional? [y/N]"
8. Generate ingestion summary (files parsed, events normalized, files failed, systems detected)
9. Write `phase_1.complete` marker

**Payload column handling (Excel exports):** The Payload column may contain three different JSON formats nested inside it. The parser must detect and handle all three: flat key-value, nested objects, and mixed formats. This was a specific problem in the Trigonous prototype.

**Evidence format limitation detection:** When working with Excel exports instead of raw EVTX, note the limitation: "Analysis based on Excel-exported logs. Some fields may be truncated or missing (e.g., Kerberos encryption type in EID 4769). Confidence scores adjusted accordingly."

### Phase 2: TRIAGE

**Trigger:** Automatic after Phase 1, or `argus run-phase 2`

#### Phase 2a: Programmatic Scan (fast, deterministic)

1. **Event ID distribution** per source file — count, sort descending, flag known-suspicious IDs (4624, 4625, 4648, 4672, 4688, 4698, 4720, 4732, 4769, 4771, 7045, Sysmon 1/3/11/13/22)
2. **Timeline boundaries** — min/max timestamps per source, hourly histogram, identify activity spikes
3. **Unique entities** — users, hosts, IPs, cross-system overlap
4. **Web log statistics** (if applicable) — source IPs, methods, status codes, URIs, user agents
5. **Suspicious pattern scan** — regex matching against known-bad patterns:
   - Encoded PowerShell (`-enc`, `-encodedcommand`, base64 blobs)
   - Hidden PowerShell (`-w hidden`, `-nop`)
   - Command execution (`cmd.exe /c`)
   - LOLBins (certutil, mshta, regsvr32, rundll32, wmic, bitsadmin)
   - Scheduled tasks (schtasks)
   - Lateral movement tools (PsExec, WMI, WinRM)
   - Credential tools (mimikatz, sekurlsa, procdump targeting lsass)
   - Web attack patterns (SQL injection, path traversal, webshell indicators in query strings)
   - Base64 strings (50+ character matches)
   - Net enumeration (net user, net localgroup, nltest)
6. Output: `triage/programmatic_scan.json`

#### Phase 2b: LLM Triage Review (5 agents, catches unknown unknowns)

Each agent receives the normalized Parquet data (chunked to fit context limits) and the Phase 2a results.

**Agent T1: Pattern Gap Hunter**
- What did the regex patterns miss?
- Look for: obfuscated commands, encoded payloads in unusual fields, living-off-the-land techniques not in the pattern list, custom tool names, novel attack techniques
- Output: structured findings as JSON claims

**Agent T2: Behavioral Anomaly Agent**
- Statistical and temporal anomalies
- Look for: unusual activity volumes at odd hours, user accounts on unexpected systems, processes with unusual parent chains, timing clusters suggesting automation, suspicious gaps in activity that suggest planning/staging
- Output: structured findings as JSON claims

**Agent T3: Cross-Source Correlation Agent**
- Connections between evidence sources that programmatic scan can't make
- Look for: IPs appearing across web logs and auth events, filenames matching process names across systems, timing relationships between events on different hosts, evidence of lateral movement bridging systems
- Output: structured findings as JSON claims

**Agent T4: Absence & Evasion Agent**
- What SHOULD be there but ISN'T?
- Look for: log gaps, missing Event IDs that should exist on a functioning system, disabled security tools, cleared event logs, suspicious log termination, missing antivirus events, gaps in expected periodic events
- Output: structured findings as JSON claims

**Agent T5: Identity & Privilege Context Agent**
- Role-based analysis of every user, process, and service account
- Look for: accounts operating outside expected role, service accounts with interactive logons, processes spawning children they never should (w3wp.exe → cmd.exe), SYSTEM-level processes doing user-level things, privilege assignments to unexpected accounts
- Output: structured findings as JSON claims

#### Phase 2c: Merge Findings

Combine Phase 2a programmatic results + Phase 2b agent findings into unified triage output. Deduplicate where both found the same thing. Preserve unique findings from each source.

Output: `triage/merged_findings.json`

#### Phase 2d: Hypothesis Generation

Based on merged findings, generate ranked hypotheses. This is a hybrid step:
- Rule-based hypotheses for common patterns (webshell indicators + IIS process spawning → web application compromise hypothesis)
- One LLM call to catch anything rules miss, review the triage summary holistically, and rank hypotheses by likelihood

Output: `triage/hypotheses.json` — each hypothesis has: description, supporting evidence references, confidence level, what Phase 3 should investigate to confirm/deny

### Phase 2.5 → Phase 3 Bridge

The hypotheses from Phase 2d are injected into each Phase 3 agent's context. Agents know what to look for and what to try to prove/disprove. This is the critical link — hypotheses guide investigation.

### Phase 3: DEEP ANALYSIS (Agent Army)

**Trigger:** Automatic after Phase 2, or `argus run-phase 3`

**Architecture:** 9 parallel domain-specific agents + 1 synthesizer. All use Claude API. Each agent receives: relevant evidence chunks (bounded by token limits), triage findings, hypotheses, and domain-specific instructions.

**Each agent outputs structured claims per the FVE spec:**
```json
{
  "claim_id": "A3-017",
  "agent": "agent_03_registry",
  "summary": "Malicious service 'XFBRJVUPQBBNMSAPIGNN' installed via registry",
  "affected_entities": ["DCSRV", "XFBRJVUPQBBNMSAPIGNN"],
  "timestamp_range": ["2025-03-09T08:45:00Z", "2025-03-09T08:46:00Z"],
  "log_sources": ["DCSRV.parquet"],
  "event_ids": [7045, 13],
  "detection_method": "Pattern match on random-named service + registry persistence key",
  "query_used": "EventId == 7045 AND ServiceName matches ^[A-Z]{15,}$",
  "confidence": "HIGH",
  "mitre_technique": "T1543.003",
  "mitre_tactic": "Persistence",
  "raw_evidence_refs": [
    {"file": "DCSRV.parquet", "row_filter": "EventId == 7045", "timestamp": "2025-03-09T08:45:12Z"}
  ],
  "supporting_evidence": "Service name is 20 uppercase random characters with cmd.exe /c in ImagePath",
  "assumptions": [],
  "inferred_vs_direct": "DIRECT"
}
```

#### Agent Definitions

**Agent 1: Process Tree Forensics**
- Sysmon Event ID 1, Windows Event 4688
- Build complete process tree: grandparent → parent → child → grandchild
- Extract: Image, CommandLine, ParentImage, ParentCommandLine, User, ProcessId
- Flag: web server process children, services.exe spawns, encoded commands, LOLBIN abuse
- If no Sysmon data: warn "Process tree analysis limited to EID 4688 — parent command lines unavailable"

**Agent 2: File Operations**
- Sysmon Event ID 11 (FileCreate), 15 (FileCreateStreamHash), 23 (FileDelete)
- Extract: TargetFilename, CreationTime, ProcessId, Image, Hash
- Flag: files in Temp/Public/Downloads/inetpub, executables, scripts, renamed extensions
- Cross-reference ProcessId to identify which process created each file

**Agent 3: Registry Forensics**
- Sysmon Event ID 12 (CreateKey), 13 (SetValue), 14 (RenameKey)
- Extract: EventType, TargetObject, Details, ProcessId
- Flag: Run keys, Services keys, COM objects, any persistence mechanism

**Agent 4: Network Forensics**
- Sysmon Event ID 3 (NetworkConnect), 22 (DNSQuery)
- PCAP data if available (top talkers, protocol distribution, DNS queries, suspicious connections)
- Extract: SourceIp, DestinationIp, DestinationPort, ProcessId, QueryName
- Flag: external connections, internal-to-internal lateral movement, known-bad ports, C2 patterns, beaconing intervals

**Agent 5: Service Analysis**
- Event ID 7045 (ServiceInstall), 7034 (ServiceCrash), 7036 (ServiceStateChange), 4697
- Extract: ServiceName, ImagePath, ServiceType, StartType, AccountName
- Flag: random names (15+ chars all-caps), cmd/powershell in ImagePath, demand start services
- Build service installation timeline

**Agent 6: Authentication Forensics**
- Event ID 4624 (LogonSuccess), 4625 (LogonFail), 4648 (ExplicitCredentials), 4672 (SpecialPrivileges), 4769 (KerberosTGS), 4771 (KerberosPreAuth), 4776 (CredentialValidation)
- Group by LogonType (Type 2=interactive, 3=network, 10=RDP)
- Identify: brute force patterns, password spraying, Kerberoasting (RC4 encryption type), pass-the-hash indicators
- Build authentication timeline per user

**Agent 7: Cross-System Correlation**
- All evidence sources simultaneously
- Map the attack path between systems: which commands on System A led to activity on System B
- Identify: network connections between systems, credential reuse across systems, timing correlations
- Establish lateral movement chain with evidence from both sides

**Agent 8: PowerShell Deep Dive**
- All PowerShell activity: process creation, engine events (400/403/600), ScriptBlock logging (4104)
- Decode ALL encoded commands (-enc, -encodedcommand) — full base64 decode
- Identify: bypass flags, download commands, Invoke- cmdlets, obfuscation techniques
- For web logs: decode URL-encoded PowerShell from query strings

**Agent 9: Anomaly Hunter**
- Wildcard agent — find anything other agents might miss
- Search for: rare Event IDs, time gaps, unusual process names, cryptocurrency addresses
- Look for: cleanup activity, log tampering evidence, anti-forensics
- Examine: events just before and after log boundaries (first/last events often reveal important context)

**Agent 10: Master Synthesizer**
- Reads ALL outputs from Agents 1-9
- Creates unified attack reconstruction:
  - Second-by-second timeline
  - Complete attack chain narrative (as hypothesis — NOT as validated fact)
  - Confidence assessment per phase of the attack
  - Unanswered questions and evidence gaps
  - Consolidated IOC list
  - Consolidated MITRE ATT&CK mapping
- Identifies contradictions between agents (forwarded to Phase 4)

### Phase 4: VALIDATION (Forensic Validation Engine)

**Trigger:** Automatic after Phase 3, or `argus run-phase 4`

**THIS PHASE IS 100% PROGRAMMATIC. NO LLM INVOLVEMENT.**

The FVE validates every structured claim from Phase 3 against raw evidence in the Parquet files.

#### Validation Checks

1. **Entity existence** — Every IP, hostname, username, process name, filename referenced in a claim must exist in the raw Parquet data. If not → `UNVERIFIED_ENTITY`
2. **Timestamp consistency** — Every timestamp in a claim must correspond to a real event within ±2 seconds (configurable tolerance). If not → `TIMESTAMP_MISMATCH`
3. **Event ID correctness** — If a claim says "Sysmon Event ID 1 shows process creation," verify the referenced event actually has that EventId. If not → `EVENT_TYPE_MISMATCH`
4. **Quote verification** — If a claim includes a specific string (command line, filename, service name), search raw evidence for that exact string. If not found → `EVIDENCE_NOT_FOUND`
5. **Cross-reference integrity** — If a claim correlates events across systems, verify both sides. If only one side has evidence → `PARTIAL_CORRELATION`
6. **Contradiction detection** — If two claims make incompatible assertions (different start times, conflicting attributions), flag both → `CONTRADICTION`
7. **Duplicate detection** — If multiple claims describe the same event, flag as potential duplicates

#### Validation Outcomes

Each claim receives a status:
- `VERIFIED` — All checks pass. Claim is included in report.
- `PARTIALLY_VERIFIED` — Most checks pass, minor gaps. Included in report with caveat.
- `UNVERIFIED` — Key evidence not found. Excluded from report, logged for analyst review.
- `CONTRADICTED` — Conflicts with another claim. Both excluded, flagged for analyst resolution.
- `FAILED` — Critical validation failure. Excluded and logged as potential hallucination.

#### Outputs

- `validation/validated_claims.json` — Claims that passed validation
- `validation/validation_failures.md` — Each failed claim with: reason, manual review instructions (which file to open, what to search for, what tool to use, what to expect)
- `validation/claim_traceability.json` — Full traceability matrix: claim → evidence source → query → expected result → validation status
- `validation/hallucination_log.json` — Tracking failed validations that appear to be LLM hallucinations (for long-term pattern analysis)

#### Feedback Loop

If validation catches claims referencing entities or patterns NOT found in triage output (Phase 2), flag: "Warning: Phase 3 agent identified indicator X which was not flagged in Phase 2 triage. Consider re-running triage with expanded pattern set." This does not auto-rerun (avoids infinite loops), but surfaces the gap.

### Phase 5: IOC EXTRACTION & ENRICHMENT

**Trigger:** Automatic after Phase 4, or `argus run-phase 5` or `argus enrich`

**Actions:**
1. Extract IOCs from all evidence + validated analysis outputs using regex patterns:
   - IPv4 addresses (excluding RFC 1918, link-local, loopback, and known case infrastructure IPs)
   - IPv6 addresses
   - Domain names
   - URLs
   - File hashes (MD5, SHA1, SHA256)
   - Email addresses
2. Deduplicate and categorize
3. If API keys configured in user profile:
   - VirusTotal (4 req/min free tier — respect rate limits)
   - AbuseIPDB (1000/day free)
   - URLhaus (free, no key)
   - AlienVault OTX
   - Shodan (if key available)
   - Any additional sources configured
4. Cache all results to avoid redundant API calls
5. Generate risk scores per IOC based on enrichment results
6. If no API keys: output raw IOCs only with message "No enrichment keys configured. Run `argus enrich` after adding keys to enrich IOCs."

**Outputs:**
- `iocs/extracted_iocs.json` — Raw IOC list with context (where found, frequency)
- `iocs/enriched_iocs.json` — IOCs with enrichment data and risk scores

### Phase 6: DETECTION ENGINEERING

**Trigger:** Automatic after Phase 5, or `argus run-phase 6`

**Actions:**
1. **MITRE ATT&CK Mapping** — Map each validated claim to MITRE techniques. Include: technique ID, tactic, evidence reference, confidence level.
2. **Sigma Rule Generation** — For each confirmed TTP, generate a Sigma rule with: title, status, description, logsource, detection logic, false positives, severity level, MITRE tags.
3. **Detection Strategy Brief** — LLM-generated document that:
   - Risk-ranks the TTPs observed (which are most critical to detect)
   - Recommends detection layers (what combination of rules provides defense-in-depth)
   - Identifies coverage gaps (what TTPs have no detection rule)
   - Provides false positive guidance per rule
   - Suggests complementary detections that would catch variations of the observed attack

**Outputs:**
- `detection/mitre_mapping.json`
- `detection/sigma_rules/*.yml`
- `detection/detection_strategy.md`

### Phase 7: REPORT GENERATION

**Trigger:** Automatic after Phase 6, or `argus report`

**Actions:**
1. **Generate evidence figures** — Using the YAML config + HTML template + screenshot pipeline from the prototype. Each figure: filters raw evidence, renders styled HTML table, captures screenshot, adds caption with figure number and description.
2. **Build report markdown** with sections:
   - Executive Summary (1 paragraph, business-impact focused)
   - Scope & Evidence (systems, sources, tools, methodology)
   - Incident Timeline (chronological, organized by attack phase)
   - Attack Chain Narrative (walkthrough with MITRE mappings)
   - Indicators of Compromise (table with context and enrichment)
   - MITRE ATT&CK Mapping (technique table or matrix)
   - Affected Systems & Users
   - Root Cause Analysis
   - Recommendations (prioritized remediation steps)
   - Appendix: Evidence Figures
   - Appendix: Validation Report & Claim Traceability
3. **Insert `[ANALYST NOTE]` placeholders** at every major section with context-specific prompts:
   ```
   [ANALYST NOTE: Review the 70-minute gap between reconnaissance waves.
   What does the timing suggest about attacker behavior?
   Verify: Open triage/merged_findings.json, check timestamps for
   recon commands. Cross-reference claim A1-003 in
   validation/claim_traceability.json for verification steps.]
   ```
4. **Generate validation appendix** with claim traceability matrix and manual review procedures
5. **PAUSE.** Display: "Report draft generated at `./case-001/report/report_draft.md`. Review analyst note sections, fill in your walkthrough, then run `argus finalize ./case-001`."

**The tool does NOT convert to PDF automatically.** The analyst must review and fill in notes first.

### Phase 7.5: ANALYST REVIEW (Human-in-the-loop)

This is not an automated phase. The analyst:
1. Opens `report/report_draft.md`
2. Reviews each `[ANALYST NOTE]` placeholder
3. Uses the verification procedures in `validation/claim_traceability.json` (also rendered as `validation/claim_traceability.md` for readability) to manually validate key findings
4. Dictates their walkthrough observations, fills in analyst notes with their own words
5. Reviews `validation/validation_failures.md` — investigates each failure
6. Runs `argus finalize ./case-001`

### Phase 7.6: FINALIZE

**Trigger:** `argus finalize ./case-001`

**Actions:**
1. Check that `report_draft.md` has been modified (compare hash against original)
2. Warn if any `[ANALYST NOTE]` placeholders remain unfilled
3. Copy draft to `report/report_final.md`
4. Convert markdown to PDF via WeasyPrint with professional CSS (page numbers, headers, CONFIDENTIAL watermark, styled tables)
5. Resolve relative image paths to embedded figures

### Phase 8: OUTPUT PACKAGING

**Trigger:** Automatic after finalize

**Actions:**
1. Copy all deliverables to `output/` directory:
   - `report_final.pdf`
   - `iocs.json` (enriched if available, raw if not)
   - `mitre_mapping.json`
   - `sigma_rules/` directory
   - `figures/` directory
   - `detection_strategy.md`
   - `validation_appendix.md`
   - `validation_failures.md`
2. Generate `output/README.md` listing all deliverables with descriptions
3. Write `phase_8.complete` marker
4. Display summary: files produced, total analysis time, token usage, cost estimate

### Post-Pipeline: DEBRIEF

**Trigger:** `argus debrief ./case-001`

LLM-guided lessons learned interview:
- What did the agents miss?
- What turned out to be false positives?
- What new patterns did you discover?
- What would you do differently?

The LLM processes the debrief and suggests:
- New patterns to add to `~/.argus/pattern_library/custom_regex.yaml`
- New entries for `~/.argus/pattern_library/false_positives.yaml`
- Improvements for future runs

Analyst approves suggested additions: "Create these? [Y/n]"

---

## 3. CONSTRAINTS

### Must NOT Do

1. **Never modify original evidence files.** Evidence is copied into case directory, hashed (SHA-256), and set read-only. Hash verified before every phase. If hash mismatch detected → HALT with critical error.
2. **Never silently drop findings or errors.** Everything is logged, flagged, or surfaced to the analyst.
3. **Never make analytical decisions without analyst knowledge.** Contradictions, ambiguities, and validation failures go to the human. ARGUS presents findings; the analyst constructs the narrative.
4. **Never store API keys in plaintext.** Environment variables or encrypted storage only. Never committed to code. Never in config files.
5. **Never send raw evidence to LLM without size/content controls.** Evidence chunks must be bounded by token limits. No dumping entire Parquet files into API calls.
6. **Never generate a final report with unvalidated claims.** The FVE (Phase 4) must run before report generation (Phase 7). No bypass.
7. **Never assume the attack narrative.** The synthesizer produces a HYPOTHESIS. The analyst validates and constructs the final narrative through their notes.
8. **Never log or store case data outside the case directory.** API responses containing evidence stay in the case. No case data in `~/.argus/` or temp files.
9. **Never transmit evidence to any endpoint other than the configured LLM API.** No telemetry, no analytics, no phoning home with case data.
10. **Never execute remediation actions.** ARGUS analyzes and reports. It does not kill processes, block IPs, quarantine files, reset passwords, or modify firewall rules. It may RECOMMEND these in the report.
11. **Never interact with live systems.** ARGUS works on collected evidence files only. No SSH into production, no live AD queries, no running commands on target systems.
12. **Never present LLM analysis as validated fact without FVE approval.** Report must distinguish between VERIFIED findings and analytical inferences.
13. **Never include case data from one case in another case's output.** Cases are isolated. Pattern library references general patterns, never specific IPs/usernames/hostnames from other cases.
14. **Never make unbounded API calls.** Configurable token/cost ceiling per case (default ~$10-15). Warning at 80%, hard stop at 100%.

### Hard Requirements

**File Formats (all required):**
- Excel-exported event logs (.xlsx)
- Raw EVTX files (.evtx)
- IIS W3C logs (.log)
- CSV event exports (.csv)
- PCAP/PCAPNG files
- Memory dumps (.dmp, .raw, .vmem)
- Registry hives
- Prefetch files (.pf)
- Apache Combined logs
- Nginx logs
- Zeek logs
- Cloud logs: AWS CloudTrail (JSON), Azure AD audit, GCP audit
- Modular parser architecture for adding new formats

**Timestamps:** All timestamps normalized to UTC. If evidence has mixed timezones or ambiguous timestamps, flag immediately. Configurable tolerance window for cross-source correlation (default ±2 seconds).

**Excel export detection:** When working with Excel-exported event logs instead of raw EVTX, detect this automatically and note: "Some fields may be truncated or missing. Confidence scores adjusted."

**Sysmon dependency:** If no Sysmon telemetry detected, warn: "No Sysmon data. Process tree analysis limited to EID 4688 (lacks parent command lines)."

**Event ID mapping:** OS-version dependent. Detect OS version from evidence where possible, use correct mappings.

**Internal IP filtering:** RFC 1918 (10.x, 172.16-31.x, 192.168.x), link-local (169.254.x), loopback (127.x), and case infrastructure IPs excluded from IOC extraction.

### Directory Structure

#### Central ARGUS config (~/.argus/)
```
~/.argus/
├── config.yaml              ← User profile: API keys (env var refs), preferences, defaults
├── cases.log                ← Case registry: name, path, date, status
├── lessons_learned/         ← Post-case debriefs
│   ├── case-001.md
│   └── case-002.md
└── pattern_library/         ← Evolving detection patterns
    ├── custom_regex.yaml    ← User-added patterns from past cases
    └── false_positives.yaml ← Known benign items to suppress
```

#### Per-case directory
```
case-001/
├── argus.yaml              ← Case config (name, date, systems, status)
├── evidence/               ← Copied evidence files (READ-ONLY, hash-verified)
│   ├── hashes.json         ← SHA-256 hashes of all evidence files
│   ├── DCSRV.xlsx
│   ├── WEB01.xlsx
│   └── WEB01_u_ex25030904.log
├── parsed/                 ← Normalized Parquet files from Phase 1
│   ├── DCSRV.parquet
│   ├── WEB01.parquet
│   └── IIS_WEB01.parquet
├── triage/                 ← Phase 2 outputs
│   ├── programmatic_scan.json
│   ├── agent_t1_pattern_gaps.json
│   ├── agent_t2_behavioral.json
│   ├── agent_t3_cross_source.json
│   ├── agent_t4_absence.json
│   ├── agent_t5_privilege.json
│   ├── merged_findings.json
│   └── hypotheses.json
├── analysis/               ← Phase 3 outputs
│   ├── agents/
│   │   ├── agent_01_process_trees.json
│   │   ├── agent_02_file_ops.json
│   │   ├── agent_03_registry.json
│   │   ├── agent_04_network.json
│   │   ├── agent_05_services.json
│   │   ├── agent_06_auth.json
│   │   ├── agent_07_cross_system.json
│   │   ├── agent_08_powershell.json
│   │   └── agent_09_anomalies.json
│   └── synthesis.json
├── validation/             ← Phase 4 outputs
│   ├── validated_claims.json
│   ├── validation_failures.md
│   ├── claim_traceability.json
│   ├── claim_traceability.md   ← Human-readable version with review instructions
│   └── hallucination_log.json
├── iocs/                   ← Phase 5 outputs
│   ├── extracted_iocs.json
│   └── enriched_iocs.json
├── detection/              ← Phase 6 outputs
│   ├── mitre_mapping.json
│   ├── sigma_rules/
│   │   ├── rule_001_webshell_spawn.yml
│   │   └── ...
│   └── detection_strategy.md
├── report/                 ← Phase 7 outputs
│   ├── figures/
│   │   ├── Figure_01.png
│   │   └── ...
│   ├── figures_config.yaml
│   ├── report_draft.md
│   ├── report_final.md
│   ├── report_final.pdf
│   └── validation_appendix.md
├── logs/                   ← Runtime logs
│   ├── argus.log           ← Full verbose log (always written)
│   ├── token_usage.json    ← API token/cost tracking
│   └── phase_completions/
│       ├── phase_0.complete
│       ├── phase_1.complete
│       └── ...
└── output/                 ← Phase 8 final deliverable package
    ├── README.md
    ├── report_final.pdf
    ├── iocs.json
    ├── mitre_mapping.json
    ├── sigma_rules/
    ├── figures/
    ├── detection_strategy.md
    ├── validation_appendix.md
    └── validation_failures.md
```

### Error Handling Rules

**Unparseable evidence files:** Parse everything possible first. At end of ingestion, present list of failures with reasons (corrupted, unknown format, possibly encrypted, encoding issue). Ask user: reparse, ignore, or provide guidance. Never silently skip.

**Missing API keys:** On first run, ARGUS setup (`argus setup`) prompts for API keys and stores references securely. During pipeline, missing keys → skip enrichment, output raw IOCs, continue. Message: "No enrichment keys configured. Outputting raw IOCs only."

**Failed validation claims:** Flag in `validation_failures.md` with manual review instructions. Never silently drop. Each failure includes: the claim, why it failed, and step-by-step instructions to manually verify.

**API failures mid-pipeline:** Exponential backoff retry. If rate limited → pause and wait. If authentication error → save progress, notify user, ask: continue with completed work or stop? If funds exhausted → save progress, display specific error, suggest recharging. Progress is always saved.

**Contradictory findings:** Present BOTH with the contradiction explicitly noted. Never pick one. Generate review instructions for how to resolve. The analyst decides.

**Clock skew between sources:** Use configurable tolerance window (default ±2 seconds) for cross-source timestamp correlation. If systematic clock skew detected (all events from one source consistently offset), warn and suggest adjustment.

### Domain-Specific Rules

1. **Timestamps are everything.** All normalized to UTC. Mixed timezone evidence flagged immediately. A 5-hour timezone error changes the entire attack narrative.
2. **Excel exports lose field fidelity.** Auto-detect and warn. Adjust confidence scores.
3. **Payload column has multiple JSON formats.** Parser must handle all three formats found in the Trigonous prototype.
4. **Process trees require Sysmon.** Without Sysmon EID 1, warn about degraded analysis.
5. **IIS logs and event logs may have clock skew.** Use tolerance windows for correlation.
6. **Internal vs. external IP classification matters.** RFC 1918 + known infrastructure filtered from IOC extraction.
7. **Event ID meanings are OS-version dependent.** Detect OS version, use correct mappings.

---

## 4. EXAMPLES

### Good Output (Happy Path)

**Input:** Evidence directory with `DCSRV.xlsx` (4,860 events), `WEB01.xlsx` (17,565 events), `WEB01_u_ex25030904.log` (~17,495 lines).

**Output (30-45 minutes later):**
```
output/
├── Trigonous_IR_Report.pdf          (25-40 page professional report)
├── iocs.json                        (23 external IPs with enrichment)
├── mitre_mapping.json               (15 techniques mapped)
├── sigma_rules/                     (6 detection rules)
│   ├── rule_001_webshell_process_spawn.yml
│   ├── rule_002_random_service_name.yml
│   └── ...
├── figures/                         (29 evidence screenshots with captions)
├── detection_strategy.md            (risk-ranked detection guidance)
├── validation_appendix.md           (claim traceability + verification procedures)
└── validation_failures.md           (1 failed claim with review instructions)
```

The report identifies the complete attack chain: webshell upload → reconnaissance (two waves with 70-minute gap) → credential theft (LSASS dump via ProcDump) → exfiltration (dump disguised as image) → lateral movement (pass-the-hash to DC) → persistence (6 malicious services) → extortion payload deployment. Every finding is traced to raw evidence. The report includes analyst note placeholders that were filled with the analyst's own walkthrough observations. 43 of 47 claims validated, 1 failed (logged), 3 partially verified (noted with caveats).

### Edge Case Output (Messy Input)

**Input:** Directory containing 2 EVTX files (Windows Server 2012), 1 Excel export (corrupted row in middle), 1 IIS log (mixed timezones), 1 renamed ZIP archive, 1 PCAP.

**ARGUS behavior:**
- Detects the ZIP file is not a valid evidence format → unpacks it, finds evidence files inside, adds them to ingestion
- Parses EVTX with Windows 2012 Event ID mappings
- Parses Excel, handles corrupted row: logs it, examines before/after context, continues with remaining rows
- Normalizes IIS timestamps to UTC, flags the mixed timezone issue
- Parses PCAP via tshark
- Warns: "No Sysmon telemetry detected. Process tree analysis will be limited."
- Produces full report pipeline with clear documentation of limitations:
  - "Row 4,721 in evidence file X.xlsx was corrupted and excluded from analysis"
  - "IIS log contained mixed UTC/EST timestamps. All normalized to UTC."
  - "Process tree analysis limited — no Sysmon data available"
- Final output is the same deliverable package, with limitations documented

### Bad Output (Avoid This)

**Pattern 1: Shallow First Pass**
The triage phase runs only the programmatic scan. LLM triage agents are skipped "to save API costs." Hypotheses are generated from regex hits only. Deep analysis agents investigate obvious indicators but miss the URL-encoded PowerShell in IIS query strings, the 70-minute behavioral gap, and the log termination pattern. The report finds the webshell but misses the full lateral movement chain. **This is wrong because:** The 5 triage agents exist specifically to catch what regex misses. Skipping them undermines the entire pipeline.

**Pattern 2: Manual Handback**
ARGUS produces Phase 2 triage output and then tells the analyst: "Based on triage findings, manually review the IIS logs for webshell command execution patterns. Consider using grep to search for base64-encoded strings in the cs-uri-query field." **This is wrong because:** ARGUS has an agent specifically for this (Agent 8: PowerShell Deep Dive). It should analyze the IIS logs itself, decode the base64 commands, and present findings — not push the work back.

**Pattern 3: Phantom Finding**
Agent 7 (Cross-System Correlation) claims: "User 'svc_backup' authenticated from WEB01 to DCSRV at 08:32:15 UTC using NTLM pass-the-hash." The validation engine checks: does 'svc_backup' exist in the logs? Yes (it's a real service account). Does a logon event at 08:32:15 exist? Yes (but it's a different user). The entity check passes but the correlation is fabricated. **This is wrong because:** The FVE checked entity existence but not the specific relationship. This is a hallucination that partially evaded validation. **Mitigation:** The analyst note placeholder for this section prompts manual verification of the lateral movement chain, and the claim traceability provides the exact query to run. The analyst catches it during review.

**Pattern 4: Report Bloat**
The report is 85 pages. The reconnaissance section alone is 12 pages, listing every single `whoami` output line. The executive summary is 3 pages. Tables include every raw field instead of relevant columns. **This is wrong because:** The report should be 25-40 pages for a case of this scope. Every paragraph earns its place. Tables show relevant fields only. The executive summary is 1 paragraph.

**Pattern 5: Hallucination as Validated Fact**
The report states: "The attacker performed privilege escalation using whoami /priv (T1134 - Access Token Manipulation)." The `whoami` command exists in the evidence, so validation passes. But `whoami /priv` is reconnaissance (T1033), not privilege escalation. **This is wrong because:** The MITRE mapping is semantically incorrect. **Mitigation:** The analyst note for this section prompts review of MITRE technique assignments. Long-term: improve agent prompts with explicit MITRE technique definitions and common misclassification patterns.

---

## 5. TASK DECOMPOSITION

### Task 1: Project Scaffolding
- **Input:** This spec document
- **Action:** Create the project directory structure, README.md, setup.py/pyproject.toml, requirements.txt, `~/.argus/` config structure, CLI entry point with argparse subcommands, ASCII banner
- **Output:** Working `argus --help` that shows all subcommands. `argus init ./test-case` creates the correct directory structure.
- **Validation:** `argus --help` displays correctly. `argus init` creates all directories from the spec. Banner displays.
- **Checkpoint:** Yes — review before proceeding

### Task 2: User Profile & Setup
- **Input:** Task 1 output
- **Action:** Implement `argus setup` — first-run onboarding that prompts for API keys (Claude, VirusTotal, AbuseIPDB, etc.), stores references in `~/.argus/config.yaml` using environment variable references, creates pattern library scaffolding
- **Output:** Working setup flow. Config file with secure key references.
- **Validation:** Keys not stored in plaintext. Config loads correctly. Missing keys handled gracefully.
- **Checkpoint:** No

### Task 3: Evidence Parser Framework
- **Input:** Task 1 output
- **Action:** Build the modular parser architecture. Abstract base parser class. Implement parsers for: Excel (.xlsx with multi-format Payload handling), EVTX (via python-evtx), IIS W3C, CSV, Apache Combined, Nginx, Zeek, PCAP (via tshark subprocess), memory dump (via volatility subprocess), registry hive, prefetch, AWS CloudTrail JSON, Azure AD, GCP audit. Unified event schema. Parquet output.
- **Output:** Each parser can independently parse its format and output normalized Parquet. Auto-detection works for all supported formats.
- **Validation:** Test each parser against sample files. Verify unified schema. Verify Parquet output is queryable.
- **Checkpoint:** Yes — review parser coverage before proceeding

### Task 4: Phase 0 (INIT) Implementation
- **Input:** Tasks 1-3
- **Action:** Implement full Phase 0: case directory creation, evidence copy, SHA-256 hashing, read-only permissions, argus.yaml generation, completion marker
- **Output:** `argus init` creates complete case directory with hashed, read-only evidence
- **Validation:** Evidence hashes match. Permissions set correctly. Attempting to write to evidence/ fails.
- **Checkpoint:** No

### Task 5: Phase 1 (INGEST) Implementation
- **Input:** Tasks 3-4
- **Action:** Implement full Phase 1: hash verification, auto-detection, parsing through framework, normalization, Parquet storage, system detection, ingestion summary
- **Output:** `argus analyze` runs Phase 0+1 and produces Parquet files with correct unified schema
- **Validation:** Parquet files queryable. Systems detected correctly. Unparseable files flagged with reasons.
- **Checkpoint:** Yes — review normalized data before analysis phases

### Task 6: Phase 2a (Programmatic Triage) Implementation
- **Input:** Task 5 output
- **Action:** Implement all programmatic triage: Event ID distribution, timeline, entities, web stats, suspicious pattern scan with full regex pattern library. Include patterns from `~/.argus/pattern_library/` if they exist.
- **Output:** Triage JSON outputs in case `triage/` directory
- **Validation:** Compare output against known Trigonous triage results. All known indicators should be flagged.
- **Checkpoint:** No

### Task 7: Phase 2b (LLM Triage Agents) Implementation
- **Input:** Tasks 5-6
- **Action:** Implement 5 LLM triage agents. Build the agent framework: prompt templates, evidence chunking (respecting token limits), structured JSON claim output parsing, error handling (retry, save progress). Implement agents T1-T5.
- **Output:** 5 agent output files in `triage/`. Each contains structured findings as JSON claims.
- **Validation:** Agents produce valid JSON. Claims have all required FVE fields. Token usage is bounded.
- **Checkpoint:** Yes — review agent output quality before building deep analysis agents

### Task 8: Phase 2c-2d (Merge + Hypotheses) Implementation
- **Input:** Tasks 6-7
- **Action:** Implement finding merger (deduplication, source tagging) and hypothesis generator (rule-based + one LLM call)
- **Output:** `merged_findings.json` and `hypotheses.json`
- **Validation:** No duplicate findings. Hypotheses are ranked and reference supporting evidence.
- **Checkpoint:** No

### Task 9: Phase 3 (Deep Analysis Agent Army) Implementation
- **Input:** Tasks 7-8
- **Action:** Implement 9 domain agents + synthesizer using the agent framework from Task 7. Each agent gets: relevant evidence chunks, triage findings, hypotheses. Structured claim output per FVE spec. Master synthesizer reads all outputs and produces unified reconstruction.
- **Output:** 9 agent JSON files + synthesis.json in `analysis/`
- **Validation:** All claims have required FVE fields. Synthesizer identifies contradictions. Token usage bounded.
- **Checkpoint:** Yes — review analysis quality

### Task 10: Phase 4 (FVE Validation) Implementation
- **Input:** Task 9 output
- **Action:** Implement pure programmatic validation engine: entity checks, timestamp checks, Event ID checks, quote verification, cross-reference checks, contradiction detection, duplicate detection. Generate validation outputs: validated claims, failures with review instructions, traceability matrix, hallucination log.
- **Output:** All validation output files. Claims correctly categorized.
- **Validation:** Test with known-good claims (should pass) and known-bad claims (should fail). Verify review instructions are actionable.
- **Checkpoint:** Yes — this is the most critical module. Review thoroughly.

### Task 11: Phase 5 (IOC) Implementation
- **Input:** Tasks 9-10
- **Action:** Implement IOC extraction (regex patterns, internal IP filtering) and enrichment (API integrations with rate limiting, caching, graceful degradation without keys)
- **Output:** `extracted_iocs.json` and `enriched_iocs.json`
- **Validation:** No internal IPs in output. API rate limits respected. Works with and without keys.
- **Checkpoint:** No

### Task 12: Phase 6 (Detection Engineering) Implementation
- **Input:** Tasks 10-11
- **Action:** Implement MITRE mapping from validated claims, Sigma rule generator, detection strategy brief (LLM-generated)
- **Output:** MITRE JSON, Sigma YAML files, detection strategy markdown
- **Validation:** Sigma rules pass sigma-lint. MITRE mappings reference real technique IDs. Strategy brief is actionable.
- **Checkpoint:** No

### Task 13: Phase 7 (Report Generation) Implementation
- **Input:** Tasks 10-12
- **Action:** Implement: YAML-driven figure generator (HTML render + screenshot), report markdown builder with all sections, analyst note placeholder insertion with context-specific prompts, validation appendix generation, claim traceability markdown generation. PAUSE mechanism.
- **Output:** Complete `report_draft.md` with figures, placeholders, and appendices
- **Validation:** All sections present. Figures render correctly. Placeholders have specific, useful prompts. Draft compiles to valid markdown.
- **Checkpoint:** Yes — review report quality

### Task 14: Phase 7.5-7.6 (Finalize) Implementation
- **Input:** Task 13
- **Action:** Implement `argus finalize`: modification detection, unfilled placeholder warnings, markdown-to-PDF conversion via WeasyPrint with professional CSS (from prototype `md_to_pdf.py`), image path resolution
- **Output:** `report_final.pdf`
- **Validation:** PDF renders correctly with figures, tables, page numbers, CONFIDENTIAL header
- **Checkpoint:** No

### Task 15: Phase 8 (Output Packaging) Implementation
- **Input:** Task 14
- **Action:** Copy all deliverables to `output/`. Generate output README. Display summary with timing and cost.
- **Output:** Complete `output/` directory
- **Validation:** All expected files present. README accurate.
- **Checkpoint:** No

### Task 16: Resume, Run-Phase, Status Implementation
- **Input:** All previous tasks
- **Action:** Implement: `--resume` (check completion markers, restart from next incomplete phase), `run-phase N` (run specific phase, with `--guidance` option), `status` (display phase completion state)
- **Output:** Working resume, re-run, and status commands
- **Validation:** Resume correctly identifies incomplete phases. Run-phase with guidance injects context into agent prompts.
- **Checkpoint:** No

### Task 17: Debrief & Pattern Library Implementation
- **Input:** All previous tasks
- **Action:** Implement `argus debrief` (LLM-guided post-case interview), pattern library management (`add-pattern`, `add-false-positive`), lessons learned storage in `~/.argus/lessons_learned/`
- **Output:** Working debrief flow. Pattern library read during Phase 2a.
- **Validation:** Debrief produces actionable suggestions. Added patterns appear in next case's triage scan.
- **Checkpoint:** No

### Task 18: Integration Testing
- **Input:** All previous tasks
- **Action:** Run full pipeline against Trigonous evidence (DCSRV.xlsx, WEB01.xlsx, WEB01_u_ex25030904.log). Compare output against known Trigonous findings. Verify: all major findings detected, no phantom findings, validation catches known issues, report structure matches spec.
- **Output:** Complete case output. Comparison document.
- **Validation:** Pipeline produces output comparable to the manual Trigonous analysis. No hallucinations in validated claims. Report is professional quality.
- **Checkpoint:** Yes — full review before declaring v1.0

### Task 19: Documentation & Polish
- **Input:** Task 18 output
- **Action:** Write comprehensive README.md (installation, quick start, full usage, architecture overview, configuration, contributing). Write CONTRIBUTING.md. Add inline code documentation. Clean up any rough edges.
- **Output:** Repository ready for public GitHub release
- **Validation:** A new user can follow README to install and run against sample evidence. All commands documented.
- **Checkpoint:** Yes — final review before release

---

## 6. CHANGE LOG

*Empty on creation. Entries added here when spec is modified during build.*

### Format for changes:
⚠️ MODIFIED — Task [N]: [What changed]
- **Original:** [What the spec said]
- **Changed to:** [What it says now]
- **Reason:** [Why the change was needed]
- **Spec gap:** [What the original spec should have said to prevent this]
