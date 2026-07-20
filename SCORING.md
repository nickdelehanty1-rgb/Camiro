# Camiro Compliance Score — Algorithm

## Output

| Field | Type | Description |
|-------|------|-------------|
| `compliance_score` | integer 0–100 | Higher = more compliant |
| `risk_band` | string A–F | Letter grade derived from score |
| `score_hint` | string | One-line improvement suggestion derived from top finding |

## Risk Bands

| Band | Score range | Meaning |
|------|------------|---------|
| A | 85–100 | Minimal risk, no high-severity findings |
| B | 70–84 | Low risk, minor issues only |
| C | 55–69 | Limited risk, medium-severity gaps |
| D | 40–54 | High risk, significant compliance gaps |
| E | 10–39 | Serious risk, critical findings present |
| F | 0–9 | Prohibited practice detected (automatic floor) |

## Algorithm

### Step 1 — Prohibited floor

If the scanner or LLM identifies `risk_level == "prohibited"`, the score is
immediately clamped to **≤ 10** (band F) regardless of any other findings.
The band label is set to `"F"` and a fixed hint is generated.

### Step 2 — Base score

```
base_score = 100
```

### Step 3 — Deductions

Deductions are applied for each finding in the LLM response:

| Severity | Deduction per finding |
|----------|-----------------------|
| high     | 18 points |
| medium   | 8 points  |
| low      | 3 points  |
| info     | 1 point   |

Deductions are capped: no single severity level can deduct more than its
cap regardless of finding count.

| Severity | Cap |
|----------|-----|
| high     | 54 (3 findings) |
| medium   | 32 (4 findings) |
| low      | 12 (4 findings) |
| info     | 5  (5 findings) |

Total maximum deduction: 103 (floors at 0).

### Step 4 — Adjustments

| Condition | Adjustment |
|-----------|-----------|
| Automated decisions detected AND no human oversight finding | -10 |
| Special category data AND no explicit consent evidence | -8 |
| Third-party data transfer AND no DPA evidence in findings | -5 |

Adjustments also floor at 0.

### Step 5 — Floor for high-risk tier

If `risk_level == "high"`, score is additionally capped at **max 54** (band D
or lower) to prevent a contradictory "B" score with a high-risk classification.

### Step 6 — Band assignment

```
score >= 85  → A
score >= 70  → B
score >= 55  → C
score >= 40  → D
score >= 10  → E
score < 10   → F
```

## Score hint

The hint is derived from the highest-severity finding's recommendation field.
Truncated to 120 characters. For prohibited cases, the hint is fixed:
"Remove or redesign the prohibited practice before any other improvement."
