"""Complete Week 5 defense with output encoding, CSP, cookie flags, and CSRF checks."""
import hmac
import os
import secrets

from flask import Flask, Response, render_template_string, request, session
from markupsafe import escape

app = Flask(__name__)
# Configure a persistent random SECRET_KEY for multi-worker/deployed use.
# The fallback invalidates local lab sessions on process restart.
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_NAME="wk05_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True,
    MAX_CONTENT_LENGTH=16 * 1024,
)
COMMENTS = []

# Signed browser sessions prevent token reuse across different sessions.
# This demonstration still has no account authentication.
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def secure(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return secure(Response("<h1>Hello, " + str(escape(name)) + "!</h1>", mimetype="text/html"))


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not supplied or not hmac.compare_digest(
            supplied.encode("utf-8"), expected.encode("utf-8")
        ):
            return secure(Response("CSRF validation failed\n", status=403, mimetype="text/plain"))
        COMMENTS.append(request.form.get("body", ""))
    template = """<h2>Comments</h2>
    <form method=post>
      <input type=hidden name=csrf_token value="{{ csrf_token }}">
      <input name=body><input type=submit value=Post>
    </form><hr>
    {% for comment in comments %}<div class=comment>{{ comment }}</div>{% endfor %}"""
    page = render_template_string(template, comments=COMMENTS, csrf_token=csrf_token())
    return secure(Response(page, mimetype="text/html"))


@app.route("/")
def index():
    response = Response(
        "<a href=/hello?name=you>hello</a> | <a href=/comments>comments</a>",
        mimetype="text/html",
    )
    csrf_token()
    return secure(response)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
