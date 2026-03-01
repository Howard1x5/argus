# FORENSIC EXTRACTOR: Atomic Implementation Guide

**Referenced by:** SPEC.md v1.1, Task 8
**Purpose:** Every extraction step broken into substeps small enough that Claude Code cannot miss anything.
**Principle:** Simple steps composed together create powerful results.

---

## Architecture

```
STAGE 1: FIELD EXTRACTION (make data queryable) — 4 Steps, 17 Substeps
STAGE 2: DECODING (make hidden content visible) — 5 Steps, 23 Substeps
STAGE 3: RELATIONSHIP BUILDING (connect events) — 5 Steps, 19 Substeps
STAGE 4: PATTERN DETECTION (find known-bad) — 4 Steps, 16 Substeps
STAGE 5: ANOMALY DETECTION (find unknown-bad) — 6 Steps, 20 Substeps
STAGE 6: CONTEXT ENRICHMENT (make findings richer) — 3 Steps, 10 Substeps
STAGE 7: ASSEMBLY (package for agents) — 3 Steps, 9 Substeps
TOTAL: 30 Steps, 114 Substeps
```

Each Substep is a single function. Input → Action → Output → Test.

```
src/argus/extraction/
├── __init__.py
├── orchestrator.py          ← Runs all stages in order
├── stage1_fields.py
├── stage2_decoding.py
├── stage3_relationships.py
├── stage4_patterns.py
├── stage5_anomalies.py
├── stage6_context.py
├── stage7_assembly.py
├── baselines/
│   ├── process_parents.yaml
│   ├── event_id_db.yaml
│   └── mitre_detections.yaml
└── tests/
    └── test_stage[1-7].py
```

---

## STAGE 1: FIELD EXTRACTION

**Goal:** Raw Parquet → fully queryable data with every field as a first-class column.

### Step 1.1: Column Normalizer

**Substep 1.1.1: Inventory Source Columns**
- Input: Raw Parquet file
- Action: Read all column names and dtypes
- Output: Dict {column_name: dtype}
- Test: All columns present, none dropped

**Substep 1.1.2: Map to Unified Schema**
- Input: Column inventory
- Action: Map each source column to unified name:
  - TimeCreated → timestamp_utc
  - EventId → event_id
  - Computer → source_system
  - UserName → username
  - ExecutableInfo → command_line
  - PayloadData1-6 → keep (unpacked in 1.2)
  - Payload → raw_payload
  - IIS: c-ip → source_ip, cs-uri-stem → uri, cs-method → http_method, sc-status → status_code, cs(User-Agent) → user_agent, cs-uri-query → query_string
  - Unmapped → prefix with raw_
- Output: Rename mapping dict
- Test: Every column mapped. None lost.

**Substep 1.1.3: Apply Renames and Cast Types**
- Input: Parquet + mapping
- Action: Rename columns. Cast event_id to int, timestamps to datetime.
- Output: Renamed Parquet
- Test: Schema matches unified definition

**Substep 1.1.4: Fill Missing Schema Columns**
- Input: Renamed Parquet
- Action: Add any missing unified schema columns as null
- Output: Complete schema Parquet
- Test: All unified columns exist

### Step 1.2: Payload Unpacker

**Substep 1.2.1: Identify Payload Columns**
- Input: Parquet from 1.1
- Action: Find columns: raw_payload, PayloadData1-6, anything with "payload" in name
- Output: List of payload columns
- Test: All payload columns found

**Substep 1.2.2: Detect Format Per Row**
- Input: Each payload value
- Action: Classify format:
  - Starts with { → JSON
  - Key: Value\n pairs → Key-value text
  - Key=Value|Key=Value → Pipe-delimited KV
  - Other → Raw text
- Output: Per-row format tag
- Test: 10 rows per format manually verified

**Substep 1.2.3: Parse JSON Payloads**
- Input: JSON-tagged rows
- Action: json.loads(). Flatten nested with dot notation. Arrays joined with semicolons. Create payload_{key} columns.
- Output: Extracted JSON columns
- Test: No nested JSON remaining. 5 rows spot-checked.

**Substep 1.2.4: Parse Key-Value Payloads**
- Input: KV-tagged rows
- Action: Split on detected delimiter. Create payload_{Key} columns.
- Output: Extracted KV columns
- Test: 5 rows spot-checked

**Substep 1.2.5: Parse PayloadData1-6**
- Input: PayloadData1-6 columns
- Action: These are EvtxECmd pre-parsed fields. Common:
  - PayloadData1: ProcessId, LogonType
  - PayloadData3: Image path
  - PayloadData4: ParentImage, TargetFilename
  Parse using same format detection as 1.2.2.
- Output: Named columns from PayloadData
- Test: Sysmon EID 1 events have process_name, parent_process_name, command_line populated

**Substep 1.2.6: Consolidate to Canonical Fields**
- Input: All extracted columns
- Action: Merge duplicates (command_line from ExecutableInfo vs payload_CommandLine — prefer more complete). Create canonical:
  - command_line, parent_command_line
  - process_name (exe from path), parent_process_name
  - target_filename, service_name, image_path
  - logon_type, source_ip, dest_ip
- Output: Parquet with canonical fields
- Test: Per event type (Sysmon 1, 4624, 7045), canonical fields populated correctly

### Step 1.3: Timestamp Normalizer

**Substep 1.3.1: Identify Timestamp Columns**
- Input: Parquet from 1.2
- Action: Find all columns with "time" or "date" in name
- Output: Timestamp column list
- Test: All timestamp columns found

**Substep 1.3.2: Parse Formats**
- Input: Each timestamp column
- Action: Detect format per value (ISO 8601, Windows FileTime, IIS format, Unix epoch, US date). Parse to datetime.
- Output: Parsed datetimes
- Test: Zero failures on valid timestamps. Failures logged with row number.

**Substep 1.3.3: Detect Timezone**
- Input: Parsed timestamps
- Action: Check for explicit TZ indicator (Z, +00:00). IIS → usually UTC. Windows events → local time (need system TZ). No indicator → assume UTC, set timezone_uncertain=True.
- Output: TZ per timestamp. Uncertain timestamps flagged.
- Test: No silent assumptions. Every ambiguous timestamp flagged.

**Substep 1.3.4: Convert All to UTC**
- Input: Timestamps + TZ info
- Action: Convert everything to UTC datetime64[ns, UTC]
- Output: Consistent timestamp_utc column
- Test: Chronological order verified. 5 rows spot-checked.

**Substep 1.3.5: Detect Cross-Source Clock Skew**
- Input: All Parquet files
- Action: Compare timestamps of events that should be simultaneous across sources. Record systematic offset if found.
- Output: Skew report per source pair
- Test: Skew documented or "none detected"

### Step 1.4: Entity Tagger

**Substep 1.4.1: Extract Unique IPs**
- Input: All IP columns
- Action: Deduplicate all IPs across all evidence
- Output: Unique IP set
- Test: Count matches manual dedup

**Substep 1.4.2: Classify IPs**
- Input: IP set
- Action: 10.x/172.16-31.x/192.168.x → INTERNAL. 127.x → LOOPBACK. 169.254.x → LINK_LOCAL. 0.0.0.0/:: → UNSPECIFIED. Case infrastructure → INFRASTRUCTURE. Else → EXTERNAL.
- Output: IP classification dict
- Test: Known attacker IP = EXTERNAL. Internal servers = INTERNAL.

**Substep 1.4.3: Extract Unique Usernames**
- Input: All username columns
- Action: Deduplicate. Normalize: strip DOMAIN\ prefix, lowercase.
- Output: Username set with original format
- Test: Count matches expected

**Substep 1.4.4: Classify Usernames**
- Input: Username set
- Action: SYSTEM/LOCAL SERVICE/NETWORK SERVICE → SYSTEM_ACCOUNT. Ends with $ → MACHINE_ACCOUNT. svc_/service_ prefix → SERVICE_ACCOUNT. admin/administrator → ADMIN_ACCOUNT. Else → USER_ACCOUNT. Record which systems each user appears on.
- Output: Username classification dict
- Test: System accounts correct. Service accounts identified.

**Substep 1.4.5: Extract Unique Process Names**
- Input: process_name, parent_process_name columns
- Action: Deduplicate. Normalize: lowercase, extract exe name from full path.
- Output: Process name set
- Test: 50-200 unique processes typical

**Substep 1.4.6: Classify Processes**
- Input: Process set
- Action: Match against:
  - System list (svchost, lsass, csrss, etc.) → SYSTEM_PROCESS
  - Windows tools (cmd, powershell, net, whoami, etc.) → WINDOWS_TOOL
  - Attack tools (mimikatz, procdump, psexec, etc.) → KNOWN_ATTACK_TOOL
  - Web servers (w3wp, httpd, nginx) → WEB_SERVER
  - Else → UNKNOWN_PROCESS
- Output: Process classification dict
- Test: w3wp = WEB_SERVER. cmd = WINDOWS_TOOL.

**Substep 1.4.7: Apply All Classifications to Parquet**
- Input: All classification dicts + Parquet
- Action: Join classification columns to every row: source_ip_class, dest_ip_class, username_class, process_class, parent_process_class.
- Output: Fully tagged Parquet
- Test: Every row has classification columns. No nulls (UNKNOWN is valid).

---

## STAGE 2: DECODING

**Goal:** Every encoded/obfuscated string decoded to plaintext.

### Step 2.1: Base64 Finder

**Substep 2.1.1: Define Search Columns**
- Input: Tagged Parquet
- Action: List all text columns: command_line, parent_command_line, raw_payload, payload_*, query_string, PayloadData*
- Output: Column list
- Test: All text columns included

**Substep 2.1.2: Scan for Base64 Patterns**
- Input: Each search column
- Action: Regex [A-Za-z0-9+/]{40,}={0,2} on every row. Record: row_index, column, matched_string, position.
- Output: All base64 candidates
- Test: Count matches grep across all fields

**Substep 2.1.3: Filter False Positives**
- Input: Candidates from 2.1.2
- Action: Remove: 32-char hex (MD5), 40-char hex (SHA1), 64-char hex (SHA256), SID format, GUID format, <40 chars. Try decode: valid text → keep. Only non-printable → mark BINARY.
- Output: Filtered list with confidence (HIGH/MEDIUM/BINARY)
- Test: Trigonous base64 = HIGH. GUIDs/SIDs removed.

**Substep 2.1.4: Record Context**
- Input: Filtered list + Parquet
- Action: For each base64: full source row, what precedes it in field, what follows, event type.
- Output: Contextualized list
- Test: Each entry has sufficient context

### Step 2.2: Base64 Decoder

**Substep 2.2.1: Decode as UTF-8**
- Input: Each base64 string
- Action: b64decode → UTF-8. Record if printable text.
- Output: Decoded or FAILED
- Test: UTF-8 encoded strings decode

**Substep 2.2.2: Decode as UTF-16LE**
- Input: Strings that failed UTF-8 or produced garbled text
- Action: b64decode → UTF-16LE (PowerShell standard)
- Output: Decoded or FAILED
- Test: PowerShell encoded commands decode correctly

**Substep 2.2.3: Decode as ASCII/Latin-1**
- Input: Remaining failures
- Action: Try ASCII, then Latin-1. Keep most readable.
- Output: Decoded or FAILED
- Test: Edge cases caught

**Substep 2.2.4: Fix Padding Issues**
- Input: Any remaining failures
- Action: Add padding (= until length % 4 == 0). Strip whitespace. Retry decode.
- Output: Decoded or final FAILED with reason
- Test: Padding-broken strings now decode

**Substep 2.2.5: Compile Results**
- Input: All results from 2.2.1-2.2.4
- Action: Per base64 string: original, decoded, encoding_used, confidence (HIGH/MEDIUM/LOW), source context from 2.1.4.
- Output: decoded_base64.json
- Test: Every string has a result. Zero unprocessed.

### Step 2.3: URL Decoder

**Substep 2.3.1: Find URL-Encoded Content**
- Input: query_string, uri, columns with %XX patterns
- Action: Scan for %[0-9A-Fa-f]{2}. Record with row context.
- Output: URL-encoded string list
- Test: All IIS encoded query strings found

**Substep 2.3.2: First-Pass Decode**
- Input: Encoded strings
- Action: urllib.parse.unquote()
- Output: Decoded strings
- Test: Standard encoding resolved (%20→space etc.)

**Substep 2.3.3: Check Double Encoding**
- Input: First-pass results
- Action: If result still has %XX, decode again. Max 3 passes.
- Output: Fully decoded with depth noted
- Test: Double-encoded payloads resolved

**Substep 2.3.4: Handle Plus-Encoding**
- Input: Query strings
- Action: Replace + with space in query strings (before other decode). Preserve %2B as literal +.
- Output: Correctly decoded
- Test: "cmd+/c+whoami" → "cmd /c whoami"

### Step 2.4: PowerShell Decoder

**Substep 2.4.1: Find All PowerShell Invocations**
- Input: command_line, decoded base64, decoded URLs
- Action: Find: powershell/pwsh (case-insensitive), -EncodedCommand/-enc/-e, -Command/-c, Invoke-Expression/IEX, & { } or . { } blocks
- Output: All PS invocations with full text
- Test: Both direct and encoded found

**Substep 2.4.2: Extract Encoded Portions**
- Input: Invocations with -enc from 2.4.1
- Action: Extract base64 after -enc flag. Handle: space/no-space, quotes, intervening flags.
- Output: Base64 strings from PS commands
- Test: Every -enc has its base64 extracted

**Substep 2.4.3: Decode PS Encoded Commands**
- Input: Base64 from 2.4.2
- Action: Decode as UTF-16LE (ALWAYS for PowerShell -EncodedCommand)
- Output: Decoded PS scripts
- Test: All encode commands readable

**Substep 2.4.4: Parse Decoded PS Scripts**
- Input: Decoded scripts
- Action: Extract from each:
  - URLs (IWR, wget, curl, DownloadString, DownloadFile, Net.WebClient)
  - Function names (Invoke-Mimikatz, Invoke-SMBExec, Invoke-WMIExec, etc.)
  - Variable assignments ($cred, $target, etc.)
  - Target hosts/IPs
  - Credentials (usernames, password strings, hash values)
  - Pipe chains (| Out-File, | IEX)
- Output: Parsed analysis per script
- Test: Trigonous Invoke-TheHash parsed. URLs extracted. IPs extracted.

**Substep 2.4.5: Parse Direct PS Commands**
- Input: Invocations using -Command (not encoded) from 2.4.1
- Action: Extract command text. Same parsing as 2.4.4.
- Output: Parsed analysis
- Test: Direct commands also parsed

### Step 2.5: Nested Encoding Resolver

**Substep 2.5.1: Check for Further Encoding**
- Input: All decoded content from 2.2-2.4
- Action: Check each for: more base64, more URL encoding, gzip magic bytes, XOR patterns, char()/chr() concatenation
- Output: Strings needing another pass with encoding type
- Test: Double-encoded payloads identified

**Substep 2.5.2: Recursive Decode**
- Input: Strings from 2.5.1
- Action: Decode. Check again. Repeat up to 5 iterations. Stop when plaintext or unchanged.
- Output: Fully decoded with encoding chain
- Test: Chain documented ("URL → Base64 → UTF-16LE → plaintext")

**Substep 2.5.3: Build Master Decoded Index**
- Input: ALL decoded content from all Step 2 substeps
- Action: Single index per decoded item: decoded_id, original_text, final_text, encoding_chain, source_file, source_row, source_column, source_timestamp, source_event_type, source_process_name, contains_urls (bool+list), contains_ips (bool+list), contains_credentials (bool), contains_commands (bool+list)
- Output: decoded_content_index.json
- Test: Every decoded item has full metadata. No orphans.

---

## STAGE 3: RELATIONSHIP BUILDING

**Goal:** Connect isolated events into trees, sessions, cross-system chains.

### Step 3.1: Process Tree Builder

**Substep 3.1.1: Collect Process Creation Events**
- Input: Tagged Parquet
- Action: Filter Sysmon EID 1 + Windows EID 4688. Extract: timestamp_utc, event_id, process_name, PID, parent_process_name, PPID, command_line, parent_command_line, username, source_system.
- Output: Process creation DataFrame
- Test: Row count = EID 1 + EID 4688 count

**Substep 3.1.2: Deduplicate Sysmon + Windows**
- Input: Process DataFrame
- Action: If both Sysmon 1 and Windows 4688 exist for same process (same PID, ±1 sec), keep Sysmon (more fields).
- Output: Deduplicated events
- Test: No duplicates

**Substep 3.1.3: Build Parent-Child Edges**
- Input: Deduplicated events
- Action: Match each child's PPID to a parent's PID on same system. Handle PID reuse: require parent timestamp < child timestamp. No parent found → PARENT_OUTSIDE_EVIDENCE.
- Output: Edge list (parent_event, child_event)
- Test: Every process has parent edge or OUTSIDE_EVIDENCE flag

**Substep 3.1.4: Assemble Trees**
- Input: Edges
- Action: Identify roots (no parent). Recursively attach children. Compute depth per node.
- Output: Tree list with roots, descendants, edges
- Test: Sum of all tree nodes = total process count

**Substep 3.1.5: Compute Tree Metadata**
- Input: Trees
- Action: Per tree: max_depth, node_count, root_process, unique_processes, unique_users, time_span, has_decoded_content (link to Stage 2 by PID/timestamp), has_network_connections (check Sysmon 3 for matching PIDs)
- Output: Tree metadata
- Test: Spot-check metadata accuracy

### Step 3.2: Parent-Child Classifier

**Substep 3.2.1: Load Baseline**
- Input: baselines/process_parents.yaml
- Action: Load expected parent-child pairs and always_suspicious pairs
- Output: Baseline in memory
- Test: File parses correctly

**Substep 3.2.2: Classify Each Edge**
- Input: Edges from 3.1 + baseline
- Action: In expected list → EXPECTED. In always_suspicious → HIGHLY_SUSPICIOUS. Parent has empty expected children (w3wp) → SUSPICIOUS. Not in any list → UNUSUAL.
- Output: Classified edges
- Test: w3wp→cmd = HIGHLY_SUSPICIOUS. explorer→chrome = EXPECTED.

**Substep 3.2.3: Rank Trees by Suspicion**
- Input: Trees + classifications
- Action: Score = count(SUSPICIOUS + HIGHLY_SUSPICIOUS edges) × max_depth_of_suspicious_edge
- Output: Trees ranked by score
- Test: Webshell tree top-ranked

### Step 3.3: Session Grouper

**Substep 3.3.1: Define Session Boundaries**
- Input: All events sorted by time
- Action: Group by: same source entity + same target + continuous activity (gap >30min = new session)
- Output: Session assignments
- Test: 70-minute gap creates session boundary

**Substep 3.3.2: Compute Session Metadata**
- Input: Sessions
- Action: Per session: start, end, duration, event_count, unique_event_ids, unique_processes, unique_commands, unique_ips
- Output: Session summaries
- Test: Complete metadata per session

**Substep 3.3.3: Classify Session Intent**
- Input: Sessions + decoded content + pattern matches
- Action: Tag by content: recon commands → RECONNAISSANCE. Credential tools → CREDENTIAL_ACCESS. Lateral movement → LATERAL_MOVEMENT. Downloads → TOOL_STAGING. Encryption/ransom → IMPACT. Mixed → MULTI_PHASE.
- Output: Sessions with intent tags
- Test: Trigonous sessions correctly tagged

### Step 3.4: Cross-System Correlator

**Substep 3.4.1: Find Cross-System References**
- Input: All events all systems
- Action: Find events on System A referencing System B: network connections to B's IP, auth events from B's IP, commands containing B's hostname/IP, DNS queries for B.
- Output: Cross-reference list (source_system, event, target_system, ref_type)
- Test: WEB01→DCSRV references found

**Substep 3.4.2: Find Matching Target Events**
- Input: Cross-refs + target system events
- Action: Search target system within ±5 sec (adjusted for skew): connection→logon, command→service install, transfer→file creation
- Output: Correlated pairs (A_event, B_event, type, time_delta)
- Test: Each lateral movement command has corresponding DCSRV event

**Substep 3.4.3: Build Attack Path**
- Input: Correlated pairs
- Action: Chain chronologically: A→B→B(as source)→C. Ordered attack path.
- Output: Ordered path: step_number, source, action, target, evidence, timestamp
- Test: Complete WEB01→DCSRV attack path

### Step 3.5: File-to-Process Linker

**Substep 3.5.1: Collect File Events**
- Input: Parquet
- Action: Filter Sysmon 11/15/23. Extract: timestamp, target_filename, creating_PID, creating_process, hash.
- Output: File events DataFrame
- Test: Count matches Sysmon 11+15+23

**Substep 3.5.2: Link to Creator Process**
- Input: File events + process events
- Action: Match creating_PID to process at that timestamp. Record creator's full details.
- Output: File-to-creator links
- Test: forbiden.aspx linked to w3wp.exe

**Substep 3.5.3: Link to Subsequent Execution**
- Input: File creation + process creation events
- Action: Find process creations where image_path matches created file. File creation must precede execution, within 24h.
- Output: File-to-execution chains
- Test: pd.exe creation → pd.exe execution linked

**Substep 3.5.4: Identify Moves and Renames**
- Input: command_lines with move/rename/copy/xcopy/robocopy
- Action: Parse source and destination paths. Link source→destination. Record command, timestamp, user.
- Output: File move chains
- Test: dumpfile.dmp → cool_pic.png captured

---

## STAGE 4: PATTERN DETECTION

**Goal:** Match evidence against known attack signatures and IR-relevant patterns.

### Step 4.1: Signature Matcher

**Substep 4.1.1: Load Pattern Library**
- Input: Built-in patterns + ~/.argus/pattern_library/custom_regex.yaml
- Action: Each pattern: name, regex, target_fields, severity (CRITICAL/HIGH/MEDIUM/LOW), mitre_technique, description
- Output: Compiled patterns
- Test: All patterns compile. No regex errors.

**Substep 4.1.2: Group by Target Field**
- Input: Patterns
- Action: Group: command_line patterns, process_name patterns, service_name patterns, uri patterns, query_string patterns, filename patterns
- Output: Field-grouped dict
- Test: Every pattern assigned to ≥1 field

**Substep 4.1.3: Execute Matching**
- Input: Parquet + grouped patterns
- Action: Per field group, scan ALL rows. Record: row, column, pattern, matched_text, full_row, severity, mitre.
- Output: Raw match list
- Test: All Trigonous patterns match

**Substep 4.1.4: Deduplicate**
- Input: Raw matches
- Action: Group by row. Record per-row: match_count, severities, patterns.
- Output: Deduped matches
- Test: Multi-pattern rows grouped correctly

### Step 4.2: Event ID Analyzer

**Substep 4.2.1: Load Event ID Database**
- Input: baselines/event_id_db.yaml
- Action: Load: event_id, name, category (Security/Execution/Persistence/Credential/Lateral), ir_significance (CRITICAL/HIGH/MEDIUM/LOW/INFO), description, expected_volume_baseline
- Output: Event ID database
- Test: All common IR Event IDs present (4624, 4625, 4648, 4672, 4688, 4698, 4720, 4732, 4769, 4771, 7045, Sysmon 1/3/11/13/22, 1102)

**Substep 4.2.2: Count Per Event ID Per System**
- Input: Parquet
- Action: GROUP BY source_system, event_id → count. Sort descending.
- Output: Event ID frequency table
- Test: Counts match raw data

**Substep 4.2.3: Flag Significant Volumes**
- Input: Frequency table + database
- Action: Flag: count exceeds expected_volume_baseline (e.g., 95 EID 4769 = potential kerberoasting). Flag: CRITICAL/HIGH IDs present at any count. Flag: expected IDs that are MISSING (e.g., no EID 1102 on a DC is normal; no EID 4624 is suspicious).
- Output: Flagged Event ID list with context
- Test: Kerberoasting volume flagged. Service installs flagged.

**Substep 4.2.4: Map to IR Domains**
- Input: Flagged list
- Action: Group findings by IR domain: Execution, Persistence, Credential Access, Lateral Movement, Defense Evasion, Discovery, Collection, Exfiltration, Impact
- Output: Domain-organized Event ID findings
- Test: Each finding in correct domain

### Step 4.3: MITRE Technique Detector

**Substep 4.3.1: Load Detection Rules**
- Input: baselines/mitre_detections.yaml
- Action: Each rule: technique_id, technique_name, tactic, required_indicators (list of conditions that must be true), supporting_indicators (conditions that increase confidence)
- Output: MITRE detection rules
- Test: Top 50 common techniques covered

**Substep 4.3.2: Evaluate Each Technique**
- Input: All Stage 3 relationships + Stage 4.1 signatures + Stage 4.2 Event IDs
- Action: For each technique rule, check: are required_indicators present? How many supporting_indicators present? Score: CONFIRMED (all required met), LIKELY (most required met), POSSIBLE (some indicators), NOT_DETECTED.
- Output: MITRE detection results per technique
- Test: Trigonous 15 techniques detected

**Substep 4.3.3: Build Coverage Map**
- Input: Detection results
- Action: Create matrix: technique × tactic with detection status. Identify gaps.
- Output: MITRE coverage map
- Test: Map is complete. Gaps identified.

### Step 4.4: IOC Scanner

**Substep 4.4.1: Extract Raw IOCs**
- Input: All text fields + decoded content
- Action: Regex for: IPv4, IPv6, domains, URLs, MD5/SHA1/SHA256, email addresses
- Output: Raw IOC list
- Test: Count is reasonable

**Substep 4.4.2: Classify and Deduplicate**
- Input: Raw IOCs + IP classifications from 1.4.2
- Action: Remove INTERNAL/LOOPBACK/LINK_LOCAL IPs. Remove infrastructure IPs. Deduplicate. Record per IOC: type, value, first_seen, last_seen, source_count (how many evidence sources), associated_events.
- Output: Cleaned IOC list
- Test: No internal IPs. No duplicates. 23 external IPs for Trigonous.

**Substep 4.4.3: Determine IOC Context**
- Input: Cleaned IOCs + all relationships
- Action: For each IOC, record: what process used it, what command referenced it, what user was associated, what time window, inbound or outbound.
- Output: Contextualized IOC list
- Test: Each IOC has attribution context

**Substep 4.4.4: Score Preliminary Risk**
- Input: Contextualized IOCs
- Action: Score based on: appears in decoded attack commands → HIGH. Appears in suspicious process network connections → HIGH. Appears only in normal traffic → LOW. Appears in multiple attack stages → CRITICAL.
- Output: Risk-scored IOC list
- Test: Attacker IP scored CRITICAL. Benign IPs scored LOW.

---

## STAGE 5: ANOMALY DETECTION

**Goal:** Find suspicious activity that doesn't match known signatures.

### Step 5.1: Frequency Analyzer

**Substep 5.1.1: Compute Value Frequencies**
- Input: Every column of interest (process_name, username, source_ip, dest_ip, command_line, service_name, target_filename, uri)
- Action: Per column, count occurrences of each unique value. Compute: mean, median, standard deviation.
- Output: Frequency table per column
- Test: Tables complete. Stats accurate.

**Substep 5.1.2: Identify Rare Values**
- Input: Frequency tables
- Action: Flag values appearing ≤3 times when column median is >50. Compute rarity_score = median / count (higher = more rare).
- Output: Rare value list: value, column, count, median, rarity_score
- Test: pd.exe (rare) flagged. svchost.exe (common) not flagged.

**Substep 5.1.3: Cross-Reference Rare Values with Timing**
- Input: Rare values + timestamps
- Action: For each rare value, record: first_seen, last_seen, all timestamps. Check: does it only appear during attack window?
- Output: Rare values with temporal context
- Test: Attack-window-only rare values prioritized

### Step 5.2: Entropy Calculator

**Substep 5.2.1: Select Target Strings**
- Input: service_name, process_name, target_filename, command_line arguments
- Action: Extract individual strings to analyze. For command_line, split into arguments and analyze each separately.
- Output: String list with source context
- Test: All relevant strings collected

**Substep 5.2.2: Calculate Shannon Entropy**
- Input: Each string
- Action: H = -Σ p(x) log2 p(x) for character frequency. Normalize by string length for comparability.
- Output: Per-string entropy score
- Test: Random strings (XFBRJVUPQBBNMSAPIGNN) > 4.0. Normal names (svchost) < 3.0.

**Substep 5.2.3: Flag High-Entropy Strings**
- Input: Entropy scores
- Action: Flag strings > 4.0 entropy for names, > 3.5 for short strings (<10 chars). Record source event context.
- Output: High-entropy list with context
- Test: Random service names flagged. Normal names not flagged.

**Substep 5.2.4: Check Against Known Patterns**
- Input: High-entropy strings
- Action: Check if high-entropy string matches known legitimate patterns (GUIDs, base64 that's already decoded, SIDs). Remove false positives.
- Output: Filtered high-entropy list
- Test: GUIDs removed. Attack strings remain.

### Step 5.3: First-Seen Detector

**Substep 5.3.1: Build Entity First-Seen Timeline**
- Input: All events sorted chronologically
- Action: For each unique entity (user, process, IP, hostname), record its absolute first appearance timestamp.
- Output: First-seen dict: {entity: first_timestamp}
- Test: Entities that exist throughout have early first-seen. Attack entities have later first-seen.

**Substep 5.3.2: Identify Attack Window**
- Input: Triage hypotheses from Phase 2, or fallback to highest activity spike
- Action: Define the suspected attack time window: start, end
- Output: Attack window bounds
- Test: Window covers known attack period

**Substep 5.3.3: Flag New-During-Attack Entities**
- Input: First-seen timeline + attack window
- Action: Flag entities whose first appearance falls within attack window. These are disproportionately likely to be attacker-introduced.
- Output: New-during-attack entity list
- Test: 45.144.29.2 flagged. Internal IPs present before attack NOT flagged.

### Step 5.4: Temporal Cluster Detector

**Substep 5.4.1: Create Sliding Windows**
- Input: All events sorted by time, configurable window size (default 60 seconds)
- Action: Slide window across timeline. For each position, collect all events in window.
- Output: Window contents per position
- Test: Windows overlap correctly. No events missed.

**Substep 5.4.2: Count Indicators Per Window**
- Input: Windows + all Stage 4 pattern matches + Stage 5 rare values + high entropy
- Action: Per window, count: signature_hits, rare_values, high_entropy_strings, first_seen_entities, suspicious_parent_child pairs.
- Output: Indicator count per window
- Test: Attack-period windows have high counts. Quiet-period windows have low counts.

**Substep 5.4.3: Identify Hot Clusters**
- Input: Window indicator counts
- Action: Flag windows with ≥3 co-occurring indicators. Rank by total indicator count. Merge overlapping hot windows into clusters.
- Output: Ranked cluster list: time_range, indicator_count, indicator_types, key_events
- Test: Reconnaissance burst and lateral movement window both detected as hot clusters.

### Step 5.5: Parent-Child Novelty Detector

**Substep 5.5.1: Extract Suspicious Chains**
- Input: Classified edges from Step 3.2 (SUSPICIOUS and HIGHLY_SUSPICIOUS only)
- Action: For each suspicious edge, extract: full process chain (3 levels up, 3 levels down), all command lines, all timestamps, user, system.
- Output: Suspicious chain details
- Test: Every SUSPICIOUS/HIGHLY_SUSPICIOUS edge has full context

**Substep 5.5.2: Score Chain Severity**
- Input: Suspicious chains
- Action: Score based on: chain depth (deeper = more concerning), presence of decoded attack content in chain, presence of network connections in chain, presence of file operations in chain, known-attack-tool in chain.
- Output: Scored chains ranked by severity
- Test: Webshell execution chain scores highest

**Substep 5.5.3: Check for Evasion Patterns**
- Input: Suspicious chains
- Action: Look for evasion: process name mimicking system process (svchost.exe from wrong path), parent spoofing, timestomping indicators, very short-lived processes (< 1 second).
- Output: Evasion flags per chain
- Test: Processes from non-standard paths flagged

### Step 5.6: Network Behavior Profiler

**Substep 5.6.1: Build Per-Process Network Profile**
- Input: All Sysmon EID 3 (network connections) with process context
- Action: Per process: unique_dest_ips, unique_dest_ports, connection_count, first_connection, last_connection, total_bytes (if available)
- Output: Process network profiles
- Test: Profiles complete for all network-active processes

**Substep 5.6.2: Flag Abnormal Processes**
- Input: Profiles + process classifications from 1.4.6
- Action: Flag: SYSTEM_PROCESS with EXTERNAL connections (lsass shouldn't talk externally). WINDOWS_TOOL with many external connections. WEB_SERVER connecting to internal systems on non-web ports. UNKNOWN_PROCESS with any external connection.
- Output: Abnormal network behavior list
- Test: Processes that shouldn't make external connections are flagged

**Substep 5.6.3: Detect Beaconing**
- Input: Connection timestamps per (process, dest_ip) pair
- Action: Compute inter-connection intervals. If intervals are regular (low standard deviation relative to mean), flag as potential beaconing. Threshold: coefficient of variation < 0.3.
- Output: Beaconing candidates with interval stats
- Test: Regular-interval connections flagged. Random connections not flagged.

---

## STAGE 6: CONTEXT ENRICHMENT

**Goal:** Make every finding richer so agents can interpret better.

### Step 6.1: Temporal Context Builder

**Substep 6.1.1: Collect All Findings**
- Input: All flagged items from Stages 4-5
- Action: Create master finding list with: finding_id, source_stage, source_step, timestamp, system, summary
- Output: Unified finding list
- Test: No findings lost. All stages represented.

**Substep 6.1.2: Pull Surrounding Events**
- Input: Each finding + full event timeline
- Action: For each finding, extract events within ±30 seconds on the same system. Record: what happened immediately before, what happened immediately after.
- Output: Finding + temporal_context (before_events, after_events)
- Test: Context window correct. Events from correct system only.

**Substep 6.1.3: Pull Cross-System Simultaneous Events**
- Input: Each finding + all system timelines
- Action: For each finding, extract events within ±5 seconds on OTHER systems. This shows what was happening elsewhere at the same moment.
- Output: Finding + cross_system_context
- Test: Cross-system events from correct time window

### Step 6.2: Lineage Expander

**Substep 6.2.1: Expand Process Findings**
- Input: All process-related findings + process trees from 3.1
- Action: For each finding involving a process, attach: full ancestor chain (up to root), full descendant chain (all children and grandchildren), each ancestor/descendant's command_line and network connections.
- Output: Findings with full process lineage
- Test: Lineage is complete (matches tree from 3.1)

**Substep 6.2.2: Expand File Findings**
- Input: All file-related findings + file-process links from 3.5
- Action: For each finding involving a file, attach: creating process, execution as process (if any), file moves/renames, hash (if available).
- Output: Findings with file lifecycle
- Test: File creation→execution chains present

**Substep 6.2.3: Expand Authentication Findings**
- Input: All auth-related findings + cross-system correlations from 3.4
- Action: For each finding involving authentication, attach: source system activity before logon, target system activity after logon, credential method, any associated lateral movement.
- Output: Findings with auth context
- Test: Lateral movement events have both sides of the connection

### Step 6.3: Counter-Evidence Finder

**Substep 6.3.1: Check for Benign Explanations**
- Input: All findings
- Action: For each finding, search for evidence that could reduce suspicion:
  - Flagged service name matches known legitimate software? (check against whitelist)
  - Flagged logon is from a system that regularly authenticates to target?
  - Flagged process runs regularly at this time? (compare to baseline period before attack)
  - Flagged IP appears in normal traffic before attack window?
- Output: Counter-evidence notes per finding
- Test: Legitimate admin activity has counter-evidence. Attack activity does not.

**Substep 6.3.2: Compute Adjusted Confidence**
- Input: Findings + counter-evidence
- Action: Adjust finding confidence based on counter-evidence:
  - No counter-evidence → confidence unchanged
  - Partial counter-evidence → confidence reduced one level (HIGH→MEDIUM)
  - Strong counter-evidence → confidence reduced two levels, flag for review
- Output: Confidence-adjusted findings
- Test: Attack findings retain high confidence. Benign findings reduced.

---

## STAGE 7: ASSEMBLY

**Goal:** Package all findings into agent-ready files.

### Step 7.1: Domain Packager

**Substep 7.1.1: Define Agent-to-Extraction Mapping**
- Input: Agent definitions from SPEC.md
- Action: Map each agent to its required data:
  - Agent 1 (Process Trees): process_trees.json ← Step 3.1 trees + Step 3.2 classifications + Step 6.2.1 lineage expansion + Step 6.1 temporal context for process findings
  - Agent 2 (File Ops): file_operations.json ← Step 3.5 file links + Step 6.2.2 file lifecycle + Stage 4 pattern matches on filenames
  - Agent 3 (Persistence): persistence.json ← EID 7045 services + Sysmon 13 registry + EID 4698 tasks + Step 5.2 entropy on service names + decoded service ImagePaths from Stage 2
  - Agent 4 (Network): network.json ← Step 5.6 network profiles + Sysmon 3 connections + Step 4.4 IOCs + beaconing detection
  - Agent 5 (Services): services.json ← EID 7045 subset of persistence.json + decoded ImagePath commands + entropy scores + Step 6.1 temporal context
  - Agent 6 (Auth/Lateral): auth_lateral.json ← Step 3.4 cross-system correlations + credential access from Stage 4 + auth timeline + Step 5.3 first-seen entities
  - Agent 7 (Cross-System): cross_system.json ← Step 3.4 attack path + unified timeline (attack window) from Step 3.3
  - Agent 8 (PowerShell): powershell.json ← Step 2.4 parsed PS + Step 2.5 decoded index (PS only) + process context for each PS invocation
  - Agent 9 (Anomalies): anomalies.json ← Step 5.1 rare values + Step 5.2 entropy + Step 5.3 first-seen + Step 5.4 clusters + Step 6.3 counter-evidence + Stage 4 absence findings (missing Event IDs from 4.2.3)
- Output: Mapping config
- Test: Every agent has data sources. Every extraction output goes to at least one agent.

**Substep 7.1.2: Assemble Per-Agent Files**
- Input: All extraction outputs + mapping from 7.1.1
- Action: For each agent, combine its mapped data into a single JSON. Include:
  - extraction_data: the actual findings
  - triage_context: relevant hypotheses from Phase 2
  - statistics: counts and summaries
  - key_questions: specific things this agent should investigate (derived from hypotheses)
- Output: One JSON file per agent in extractions/ directory
- Test: Each file is valid JSON. Contains expected sections.

**Substep 7.1.3: Include Decoded Content References**
- Input: Agent files + decoded content index from 2.5.3
- Action: For each agent file, embed the decoded content relevant to that agent's domain. Don't duplicate — reference the decoded_id and include the decoded text inline where the agent needs to see it.
- Output: Agent files with decoded content inline
- Test: Agents can read decoded commands directly without needing a separate lookup.

### Step 7.2: Summary Generator

**Substep 7.2.1: Compute Global Statistics**
- Input: All extraction outputs
- Action: Total events, events per system, events per type, unique entities, findings per stage, findings per severity, extraction coverage (what % of events appear in at least one extraction).
- Output: Global statistics dict
- Test: Stats are accurate and complete

**Substep 7.2.2: Build Extraction Summary**
- Input: Global stats + per-stage highlights
- Action: Create extraction_summary.json: statistics, key_findings (top 20 by severity), coverage_gaps (any extraction categories with zero results), warnings (timezone issues, missing data types, degraded analysis areas).
- Output: extraction_summary.json
- Test: Summary is accurate. Gaps identified.

**Substep 7.2.3: Build Finding Index**
- Input: All findings from Stages 4-6
- Action: Master index: finding_id, stage, step, severity, summary, affected_entities, timestamp, confidence, mitre_technique. Sorted by severity then timestamp.
- Output: finding_index.json
- Test: Every finding present. Index is sorted correctly.

### Step 7.3: Size Checker

**Substep 7.3.1: Measure Agent File Sizes**
- Input: Per-agent files from 7.1
- Action: Compute token count for each file (chars / 4 as approximation). Compare against LLM context limit (default: 150K tokens to leave room for agent prompt and output).
- Output: Size report per agent file
- Test: Sizes computed for all files

**Substep 7.3.2: Generate Summaries for Oversized Files**
- Input: Any agent file exceeding limit
- Action: Create summary version prioritizing: CRITICAL/HIGH severity findings first, hot cluster items, hypothesis-relevant items, then MEDIUM, then LOW. Truncate at limit. Note in summary: "Full extraction contains N items. Summary shows top M. Full data in extractions/ directory."
- Output: agent_XX_summary.json alongside full file
- Test: Summary fits within limit. Critical items preserved. Note is present.

**Substep 7.3.3: Validate Agent-Readiness**
- Input: All agent files (full or summary)
- Action: Final checks:
  - Every file is valid JSON
  - Every file fits within token limit
  - Every file has required sections (extraction_data, triage_context, statistics, key_questions)
  - No empty extraction_data (if empty, note why)
  - All decoded content is inline (agents shouldn't need external lookups)
- Output: Validation report. PASS or FAIL per agent file with reasons.
- Test: All agents PASS. Any FAIL blocks Phase 3b from proceeding.

---

## TESTING CHECKLIST (Trigonous Case)

After all stages complete, the following MUST be present in extraction outputs:

### Process Trees
- [ ] 30 w3wp.exe child processes found
- [ ] Full chain: w3wp.exe → cmd.exe → whoami/ipconfig/net/etc.
- [ ] All chains classified HIGHLY_SUSPICIOUS

### Decoded Content
- [ ] 11 base64-encoded webshell commands decoded
- [ ] URL-encoded PowerShell from IIS query strings decoded
- [ ] Invoke-WMIExec commands visible in decoded output
- [ ] Invoke-SMBExec commands visible in decoded output
- [ ] Pastebin download URL extracted (e.ps1)
- [ ] All encoding chains documented

### Credential Access
- [ ] pd.exe -accepteula -ma 588 (ProcDump targeting LSASS) found
- [ ] File move: dumpfile.dmp → cool_pic.png captured
- [ ] cool_pic.png exfiltration noted
- [ ] Kerberos TGS requests (95) counted and flagged

### Lateral Movement
- [ ] 5 failed WMI attempts identified
- [ ] Successful Invoke-SMBExec to DCSRV identified
- [ ] Cross-system correlation: WEB01 command → DCSRV logon
- [ ] Attack path: WEB01 → DCSRV with evidence from both sides

### Persistence
- [ ] All 6 randomly-named services found
- [ ] Service names flagged by entropy analysis (>4.0)
- [ ] Service ImagePaths decoded (cmd.exe /c commands visible)
- [ ] Service installation timeline built

### Network
- [ ] 45.144.29.2 identified as EXTERNAL attacker IP
- [ ] Associated with webshell requests
- [ ] All external IPs extracted as IOCs

### Timeline / Anomaly
- [ ] 70-minute gap between recon waves detected
- [ ] Two hot clusters identified (recon burst + lateral/payload)
- [ ] Log termination at 09:09:42 detected
- [ ] First-seen analysis flags attack-window entities

### Assembly
- [ ] All 9 agent files generated
- [ ] All fit within token limits (or have summaries)
- [ ] Decoded content inline in relevant agent files
- [ ] extraction_summary.json accurate

If ANY item is unchecked, the ForensicExtractor is incomplete. Fix before proceeding to Phase 3b.
