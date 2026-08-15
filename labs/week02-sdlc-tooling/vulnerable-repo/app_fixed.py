"""
Week 2 Task 8 — remediated version of app.py (the "after").
The original app.py is kept unchanged so the before-scan evidence still reproduces.
Each fix is annotated with the CWE it closes; re-running scan.sh against this file
produces 0 findings (see worksheet-6631503092.md §Task-8).
"""
import os
import sqlite3
import subprocess

import bcrypt
from flask import Flask, request

app = Flask(__name__)

# CWE-798 FIX: secrets come from the environment, never hardcoded in source.
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]


@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89 FIX: parameterized query — the driver binds `name` as data, never SQL.
    rows = con.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78 FIX: no shell; an argument list means `host` can never be parsed as a
    # command. (Real code should also allow-list/validate host before this point.)
    return subprocess.check_output(["ping", "-c", "1", host])


def store_password(pw):
    # CWE-327 FIX: bcrypt (slow, salted KDF) instead of fast unsalted md5.
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


if __name__ == "__main__":
    # CWE-489 FIX: debug off by default; opt in only via env for local dev.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
