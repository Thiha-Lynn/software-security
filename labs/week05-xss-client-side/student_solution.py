"""Complete Week 5 defense with output encoding, CSP, cookie flags, and CSRF checks."""
import hmac
import secrets

from flask import Flask, Response, render_template_string, request
from markupsafe import escape

app = Flask(__name__)
COMMENTS = []

# This lab has no real account/session model. A production app should bind a
# synchronizer token to each authenticated server-side session.
CSRF_TOKEN = secrets.token_urlsafe(32)


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
        if not supplied or not hmac.compare_digest(supplied, CSRF_TOKEN):
            return secure(Response("CSRF validation failed\n", status=403, mimetype="text/plain"))
        COMMENTS.append(request.form.get("body", ""))
    template = """<h2>Comments</h2>
    <form method=post>
      <input type=hidden name=csrf_token value="{{ csrf_token }}">
      <input name=body><input type=submit value=Post>
    </form><hr>
    {% for comment in comments %}<div class=comment>{{ comment }}</div>{% endfor %}"""
    page = render_template_string(template, comments=COMMENTS, csrf_token=CSRF_TOKEN)
    return secure(Response(page, mimetype="text/html"))


@app.route("/")
def index():
    response = Response(
        "<a href=/hello?name=you>hello</a> | <a href=/comments>comments</a>",
        mimetype="text/html",
    )
    response.set_cookie("session", "abc123", httponly=True, samesite="Strict", secure=True)
    return secure(response)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
