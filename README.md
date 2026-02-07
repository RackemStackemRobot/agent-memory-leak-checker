# Agent Memory Leak Checker (MVP)

A small forensic CLI tool that detects cross-session and cross-user memory leaks in agent systems.

This tool analyzes JSONL memory read/write logs to surface cases where data written under one user or session context is later accessed by another. That is a common privacy and containment failure in multi-user agent deployments.

## What it detects

- Cross-user key reuse  
  A key written by one user is later read by a different user.

- Cross-trace session contamination  
  Keys in the `session.*` namespace appear across multiple `trace_id` values.

- Suspicious key reads  
  Keys in sensitive namespaces like `auth.*`, `token*`, `secret*`, `api_key*`, `jwt*` are read by a user different than the writer.

This is observability and forensics. It does not prevent leakage by itself.

## Log format

Input is JSONL (one JSON object per line).

Recommended fields:

- trace_id  
- timestamp  
- event: `memory_write` or `memory_read`  
- user_id  
- key  
- value_preview (optional, short and safe)

Example:

```json
{"trace_id":"t-100","timestamp":"2026-02-06T20:10:01Z","event":"memory_write","user_id":"userA","key":"session.temp_summary","value_preview":"summary of doc A"}
{"trace_id":"t-200","timestamp":"2026-02-06T21:15:11Z","event":"memory_read","user_id":"userB","key":"session.temp_summary","value_preview":"summary of doc A"}
```

## Install

No external dependencies.

## Run

Basic run:

```bash
python memory_leak_check.py --log sample_memory.jsonl
```

Write a JSON report:

```bash
python memory_leak_check.py --log sample_memory.jsonl --out report.json
```

## Output

Console output provides:

- counts of writes/reads  
- counts of findings by category  
- top findings with key, reader, writer(s), and preview

JSON report includes:

- counts  
- findings grouped by category  
- enough metadata to feed alerts or CI checks

## Runtime notes

This tool requires you to emit memory read/write events in a consistent format.

If you do not log user identity and trace/session identifiers, the tool cannot reliably detect cross-user or cross-session leakage.

## Disclaimer

See DISCLAIMER.md
