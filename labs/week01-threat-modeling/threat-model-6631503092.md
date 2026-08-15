# Threat Model — sample-app (Week 1)

**Student:** Thiha Lin · 6631503092 · 2026-08-15
**Target:** `labs/week01-threat-modeling/sample-app/app.py` (Flask, SQLite, local `uploads/`)
**Scope:** design analysis only — this week is *modelling*, not attacking (worksheet ethics note).

> **Status legend** — `[FACT]` read directly from the source; `[GIVEN]` stated by the worksheet
> itself; **`[TODO — mine]`** my own reasoning, required for marks. Fill every TODO before
> submitting: the rubric grades *my* reasoning, and the micro-demo/viva asks me to defend it live.

---

## 1. Data-flow diagram

**[TODO — mine]** Insert the DFD image here. Draw it in draw.io / Excalidraw / on paper + photo.

Elements it must contain (verified against the source):

- **External entity:** web client (browser / `curl`) — outside the boundary
- **Process:** Flask app, `app.run(host="0.0.0.0", port=5000)` — container port 5000
- **Data store 1:** `notes.db` (SQLite, created by `init_db()`)
- **Data store 2:** `uploads/` directory (`os.makedirs(UPLOAD_DIR, exist_ok=True)`)
- **Flows:** `GET/POST /notes` · `POST /upload` · `GET /files/<name>`
- **Trust boundary:** dashed line between web client and Flask app (Internet → app)

---

## 2. Elements & trust boundaries

| Element | Type | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | **yes** — Internet → app. Every request is untrusted input. |
| Flask app | process | It *is* the boundary enforcement point — and enforces nothing today: no authn, no authz, no validation. |
| SQLite DB (`notes.db`) | data store | app → data tier. Reached only via the app; queries are parameterised (`?`), so no SQLi here. |
| `uploads/` store | data store | app → filesystem. **Crossed with attacker-controlled data**: `f.filename` becomes a path component unmodified. |

*All four rows: `[FACT]` from `app.py`.*

---

## 3. STRIDE analysis

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| `/notes` | **`[GIVEN]`** Accepts a client-supplied `owner` with **no auth** — anyone can post as anyone, and read every note back | *[TODO — mine]* | **`[GIVEN]`** No logging anywhere — no record of who wrote what | *[TODO — mine]* | *[TODO — mine]* | *[TODO — mine]* |
| `/upload` | *[TODO — mine]* | **`[GIVEN]`** Saves raw `f.filename` → **arbitrary file write** (`../` escapes `uploads/`) | **`[GIVEN]`** No logging | **`[GIVEN]`** Echoes the resolved save path back in its response | *[TODO — mine]* | *[TODO — mine]* |
| `/files/<name>` | *[TODO — mine]* | *[TODO — mine]* | **`[GIVEN]`** No logging | **`[GIVEN]`** Comparatively **defended** — `send_from_directory` blocks traversal on read (see Task 5); say *why* in my own words | *[TODO — mine]* | *[TODO — mine]* |

> The `[GIVEN]` cells are handed to me in Worksheet Task 2 — they anchor the grid but they are not
> the graded part. The marks are in the `[TODO]` cells and in Task 3b below.

**Supporting facts `[FACT]`:**
- No authentication or session handling exists anywhere in `app.py`.
- No logging of any kind → Repudiation applies to every element.
- No rate limiting, request-size cap, or upload-size cap → DoS surface on `/upload` and `/notes`.
- `notes.db` queries use `?` placeholders — parameterised, so **not** an injection finding.
- `/upload` has no extension allow-list and no `secure_filename()`.

---

## 4. Task 3b — Systems-level pass **[TODO — mine, highest-value section]**

Per-element grids reliably miss system-level threats (Joshi et al. 2024) — this section is
scored on whether I reach past single elements.

- **Boundaries end-to-end:** trace one request client → `notes.db` → back. List every crossing.
  *Which crossing has no check on it?*
- **Assume the Flask process is fully owned:** what does the attacker now reach?
- **Assume `uploads/` is fully owned:** what does the attacker now reach?
- **Chain two "low" findings:** write it as `A → B → consequence`.
- **One-line system claim:** "Even if every element-level mitigation in Task 8 is implemented,
  this system still fails if ______."

---

## 5. Top 5 risks (likelihood × impact) + mitigation **[TODO — mine]**

| # | Threat | Element | Likelihood | Impact | Score | Mitigation |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |

**Then implement ONE (Task 8) and record:**
1. The diff — commit hash on my `wk01` branch: `________`
2. Evidence: the request that succeeded **before** and is refused **after** (both outputs)
3. Why it closes the **class**, not the instance — and if it's an instance fix, what the class fix is.
   *(e.g. `secure_filename()` on `/upload` = instance; "no user-supplied string ever becomes a
   path component" = class.)*

---

## 6. Evidence & integrity

Every screenshot must carry this stamp **in the same image** as the evidence — terminal beside
the browser, whole screen captured (a cropped shot identifies nobody, and this lab's output is
byte-identical for the whole cohort by design):

```bash
printf '%s | %s | ' "$(whoami)" '6631503092'; date '+%F %T %Z'
```
