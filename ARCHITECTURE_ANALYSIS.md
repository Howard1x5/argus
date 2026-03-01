# ARGUS Architecture Analysis & Strategy Document

## Current State Overview

### What ARGUS Does (Pipeline)
```
Phase 1: INGEST
  └── Parse evidence files (Excel, IIS logs, EVTX, PCAP)
  └── Store as Parquet files in /parsed/

Phase 2: TRIAGE
  └── 2a: Programmatic scan (pattern matching)
  └── 2b: LLM triage agents (5 agents)
  └── 2c: Merge findings
  └── 2d: Generate hypotheses

Phase 3: DEEP ANALYSIS
  └── 10 specialized LLM agents analyze evidence
  └── Synthesizer combines findings

Phase 4-8: Validation, IOC extraction, detection rules, reporting
```

---

## What's Working

### 1. Evidence Ingestion (Phase 1)
- **Excel/EvtxECmd parsing**: Now correctly extracts ~28,958 events
- **IIS log parsing**: Correctly parses web server logs
- **Parquet storage**: Efficient columnar format for querying

### 2. Programmatic Scan Patterns (Phase 2a)
- **Recently added**: Critical patterns (w3wp.exe, pd.exe, Invoke-WMIExec, forbiden.aspx)
- **Priority-based**: Stratified sampling now ensures attack-period findings reach agents

### 3. Report Generation (Phase 7)
- Produces professional IR reports
- MITRE ATT&CK mapping works

---

## What's Falling Short

### 1. Agents Don't Query Data - They Receive Samples

**Current Architecture (PROBLEMATIC):**
```
events = load_all_28958_events()
sample = events[:100]  # Random/filtered sample
agent.analyze(sample)  # Agent only sees 100 events!
```

**Why This Fails:**
- With 28,958 events, a 100-event sample has ~0.3% coverage
- Critical events may not be in the sample
- Agents can't "dig deeper" - they only see what we feed them
- We're trying to solve this by "routing" events correctly, but:
  - Routing logic can be wrong
  - If we route incorrectly, agent gets wrong data
  - We're duplicating detection logic in the router AND the agents

**What Manual Claude Code Analysis Did (that worked):**
```python
# You queried the data directly:
df = pd.read_parquet("WEB01.parquet")
df[df["parent_process_name"].str.contains("w3wp", na=False)]  # 30 results

# Then decoded specific values:
base64.b64decode(encoded_cmd)
```

### 2. Agents Can't Query - They're Stateless

**The Problem:**
Agents receive a JSON blob and produce output. They cannot:
- Query parquet files with filters
- Ask follow-up questions about the data
- Decode base64 strings programmatically
- Correlate across different evidence files

**What We Need:**
Agents should be able to execute code/queries against the evidence, not just analyze pre-filtered samples.

### 3. Detection Logic is Duplicated

**Current State:**
```
phase2_triage.py: SUSPICIOUS_PATTERNS (regex patterns)
event_router.py: SUSPICIOUS_INDICATORS (scoring)
analysis_agents.py: Each agent's system prompt (LLM detection)
```

All three are trying to identify the same things. If we update one, we must update all three.

### 4. LLM Token Limits Force Sampling

**The Math Problem:**
- 28,958 events × ~500 chars each = ~14.5M characters
- Claude context: ~200K tokens (~800K chars)
- We can only fit ~1,600 events maximum (5.5% of data)
- Current approach: 100 events (0.3%)

**This is why agents miss things** - they literally don't see the data.

---

## Root Cause Analysis

### Why Did Manual Analysis Work?

When you used Claude Code to investigate:
1. **You queried specific data**: `df[df["uri"].str.contains("forbiden")]`
2. **You saw results and dug deeper**: Found base64, decoded it
3. **You correlated across sources**: IIS logs → Sysmon processes
4. **You iterated**: Found something suspicious, investigated further

**ARGUS agents can't do this.** They get one shot with a sample.

### Why Did We Only Detect 33%?

| Finding | In Data? | In Sample? | Detected? |
|---------|----------|------------|-----------|
| w3wp.exe → cmd.exe | YES (30 events) | NO (sampling issue) | NO |
| pd.exe credential dump | YES | NO | NO |
| 45.144.29.2 attacker IP | YES | NO | NO |
| Base64 webshell commands | YES | Can't decode in prompt | NO |

The data existed. We just couldn't see it or process it.

---

## Proposed Architecture (Simplified)

### Option A: Agent-as-Code-Executor

Give agents the ability to run Python/SQL against the evidence:

```python
class ProcessTreeAgent:
    def analyze(self, case_path):
        # Agent writes and executes queries
        df = pd.read_parquet(f"{case_path}/parsed/WEB01.parquet")

        # Query 1: Find webshell process chains
        w3wp_children = df[df["parent_process_name"].str.contains("w3wp", na=False)]

        # Query 2: Decode base64 commands
        for cmd in w3wp_children["command_line"]:
            decoded = self.decode_base64(cmd)
            # Analyze decoded command...
```

**Pros:**
- Agents see ALL relevant data
- Can iterate and dig deeper
- No sampling issues
- Matches how manual analysis worked

**Cons:**
- Code generation risk (LLM may write buggy code)
- Need sandboxing
- More complex agent framework

### Option B: Query-Then-Analyze (Hybrid)

Run targeted queries BEFORE calling LLM, pass results:

```python
class ProcessTreeAgent:
    def build_context(self, case_path):
        # Pre-query with known attack patterns
        queries = {
            "w3wp_children": "parent_process_name LIKE '%w3wp%'",
            "credential_dumps": "command_line LIKE '%pd.exe%' OR command_line LIKE '%lsass%'",
            "encoded_commands": "command_line LIKE '%-enc%'",
        }

        results = {}
        for name, query in queries.items():
            results[name] = self.query_parquet(query)

        return results  # Pass to LLM
```

**Pros:**
- Targeted data extraction
- Queries are predictable/testable
- LLM analyzes pre-extracted suspicious data

**Cons:**
- Still need to know what to query for
- Hard-coded queries may miss novel attacks

### Option C: Summary-Then-Deep-Dive (Current path, improved)

1. Phase 2 creates summary statistics and key findings
2. Agents receive summary + ability to request specific data
3. Multi-turn agent conversation with data access

**This is closest to current architecture but requires multi-turn agents.**

---

## Specific Recommendations

### Immediate Fixes (Complexity Reduction)

1. **Remove event_router.py** - It's duplicating detection logic
2. **Increase event sample size** - 100 → 500 events per agent
3. **Target critical patterns directly** - Query for w3wp, pd.exe, etc. before sampling

### Short-Term (1-2 days)

1. **Add query methods to agents** - Let agents query parquet files directly
2. **Pre-extract attack indicators** - Before LLM call, extract:
   - All w3wp.exe children
   - All pd.exe/procdump executions
   - All IIS requests to .aspx files
   - All base64-decoded commands

### Medium-Term (Architectural)

1. **Agent-as-researcher pattern** - Give agents tools to query data
2. **Multi-turn analysis** - Agent finds something, requests more data
3. **Unified detection logic** - One place for all attack pattern definitions

---

## Files Changed in This Session

### New Files
- `src/argus/agents/investigation_playbooks.py` - Attack pattern documentation
- `src/argus/agents/event_router.py` - Event categorization (should probably remove)

### Modified Files
- `src/argus/phases/phase2_triage.py`:
  - Added priority-based pattern matching
  - Added stratified sampling
  - Added new attack patterns (pd.exe, w3wp, Invoke-WMIExec, etc.)

- `src/argus/agents/analysis_agents.py`:
  - Added IISWebshellAgent (agent 9)
  - Updated all agent prompts with attack patterns
  - Added routed_events parameter (complexity we may want to remove)

- `src/argus/phases/phase3_analysis.py`:
  - Added event routing call (complexity we may want to remove)

---

## Key Insight

**The fundamental problem is that LLM agents can't iterate.**

When you manually investigated:
1. Query: "Show me w3wp children" → 30 results
2. Notice: "These have base64" → Decode
3. Discover: "This is reconnaissance" → Look for lateral movement
4. Find: "Invoke-WMIExec to DC" → Confirm attack chain

ARGUS agents do step 1 (analyze sample), but can't do steps 2-4.

**The solution is either:**
- A. Let agents execute code/queries (Claude Code approach)
- B. Pre-extract everything suspicious and pass it all to agents
- C. Multi-turn agents that can request more data

Currently we're attempting (B) with event routing, but it's complex and error-prone.

---

## Questions to Resolve

1. Should agents query data directly (Option A)?
2. Should we remove complexity and just pass MORE data to agents?
3. Should we keep agent count at 10 or reduce to fewer, more capable agents?
4. Is the event router adding value or just complexity?
5. Should we have agents decode base64 programmatically before LLM analysis?
