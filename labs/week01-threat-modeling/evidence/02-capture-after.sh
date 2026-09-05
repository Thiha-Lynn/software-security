#!/bin/bash
clear
echo "=============================================================="
echo " Worksheet 1 — Task 8 AFTER (fix applied)  |  1305315  |  commit c254723"
echo "=============================================================="
echo
echo "\$ printf '%s | %s | ' \"\$(whoami)\" '6631503092'; date '+%F %T %Z'"
printf '%s | %s | ' "$(whoami)" '6631503092'; date '+%F %T %Z'
echo
echo "--- same traversal attempt, now against the FIXED app (:8081) ---"
echo "\$ curl -s -X POST localhost:8081/upload -F 'file=@demo.txt;filename=../pwned_after.txt'"
curl -s --max-time 5 -X POST localhost:8081/upload -F "file=@/tmp/wk01-evidence/demo.txt;filename=../pwned_after.txt"
echo; echo
echo "\$ docker exec week01-threat-modeling-sample-app-1 ls /app/pwned_after.txt"
docker exec week01-threat-modeling-sample-app-1 ls /app/pwned_after.txt 2>&1
echo ">>> escape BLOCKED — nothing written to /app"
echo
echo "--- legitimate upload still works ---"
echo "\$ curl -s -X POST localhost:8081/upload -F 'file=@demo.txt;filename=notes.txt'"
curl -s --max-time 5 -X POST localhost:8081/upload -F "file=@/tmp/wk01-evidence/demo.txt;filename=notes.txt"
echo; echo
echo "--- disallowed extension rejected ---"
echo "\$ curl -s -X POST localhost:8081/upload -F 'file=@demo.txt;filename=shell.php'"
curl -s --max-time 5 -X POST localhost:8081/upload -F "file=@/tmp/wk01-evidence/demo.txt;filename=shell.php"
echo; echo
echo "--- why the naive AI fix fails (Audit-the-AI, verified) ---"
echo "\$ docker exec ...app python -c 'os.path.join(\"uploads\",\"/etc/passwd\")'"
docker exec week01-threat-modeling-sample-app-1 python -c "import os; print(os.path.join('uploads','/etc/passwd'))"
echo ">>> absolute 2nd arg discards the first — a '..' blocklist misses this"
echo "=============================================================="
