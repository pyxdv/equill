"""Deliberately vulnerable sample for equill's CI. Never deploy this code.

The `action` job in .github/workflows/ci.yml scans this folder with the default
scanner and rules and expects actionable security findings that carry the
flagged source line. It lives outside tests/ because Semgrep and Opengrep skip
test/ and tests/ paths by default.
"""

import hashlib
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    return subprocess.check_output(request.args.get("cmd"), shell=True)


@app.route("/load")
def load():
    return str(pickle.loads(request.data))


def digest(text):
    return hashlib.md5(text.encode()).hexdigest()


@app.route("/q")
def query():
    conn = sqlite3.connect("x.db")
    sql = "SELECT * FROM t WHERE id = '%s'" % request.args["id"]
    return str(conn.execute(sql).fetchall())
