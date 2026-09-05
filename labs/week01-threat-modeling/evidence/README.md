# Week 1 — evidence capture scripts

Reproducible commands behind the identity-stamped screenshots in the worksheet.
Each prints the required stamp (`whoami | 6631503092 | date`) in the same output.

- `01-capture-before.sh` — Task 0 (env up) + Task 5/8 **before**: path traversal on the
  unfixed app (`:8083`) escapes `uploads/` into `/app` (CWE-22).
- `02-capture-after.sh` — Task 8 **after**: same attack blocked on the fixed app (`:8081`),
  legit upload still works, `.php` rejected, plus the `os.path.join` absolute-path fact-check.

Run each in Terminal, then screenshot the window (⌘⇧4 then Space, click the window),
and save the PNGs beside this file as `ev1-before.png` / `ev2-after.png`.
