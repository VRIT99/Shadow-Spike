"""
Local XSS-vulnerable test server for Shadow Spike testing.
Run: python test_server.py
Then scan: http://localhost:8888
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote
import html

class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Silence logs

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        # ── Page 1: Search (Reflected XSS) ─────────────────────────────
        if path in ('/', '/search', '/index'):
            q = params.get('q', params.get('search', params.get('query', [''])))[0]
            # INTENTIONALLY VULNERABLE: no escaping
            body = f"""<!DOCTYPE html><html><head><title>VulnApp - Search</title></head><body>
<h1>Vulnerable Search App</h1>
<form action="/search" method="GET">
  <input type="text" name="q" placeholder="Search..." value="{q}">
  <button type="submit">Search</button>
</form>
{"<p>Results for: " + q + "</p>" if q else ""}
<hr>
<a href="/contact">Contact Us</a> | 
<a href="/login">Login</a> | 
<a href="/comment">Comments</a> |
<a href="/profile?user=admin">Profile</a>
</body></html>"""

        # ── Page 2: Contact form (POST Reflected XSS) ───────────────────
        elif path == '/contact':
            body = """<!DOCTYPE html><html><head><title>Contact</title></head><body>
<h1>Contact Us</h1>
<form action="/contact_submit" method="POST">
  <input type="text" name="name" placeholder="Your Name"><br>
  <input type="email" name="email" placeholder="Email"><br>
  <textarea name="message" placeholder="Message"></textarea><br>
  <input type="submit" value="Send">
</form>
</body></html>"""

        # ── Page 3: Login form ───────────────────────────────────────────
        elif path == '/login':
            msg = params.get('msg', [''])[0]
            body = f"""<!DOCTYPE html><html><head><title>Login</title></head><body>
<h1>Login</h1>
<form action="/login" method="GET">
  <input type="text" name="username" placeholder="Username"><br>
  <input type="password" name="password" placeholder="Password"><br>
  <input type="submit" value="Login">
</form>
{"<div style='color:red'>" + msg + "</div>" if msg else ""}
</body></html>"""

        # ── Page 4: Profile with URL param (Reflected XSS) ──────────────
        elif path == '/profile':
            user = params.get('user', ['guest'])[0]
            # VULNERABLE: directly embeds user param
            body = f"""<!DOCTYPE html><html><head><title>Profile</title></head><body>
<h1>Profile: {user}</h1>
<p>Welcome, {user}! This is your profile page.</p>
<form action="/profile" method="GET">
  <input type="text" name="user" value="{user}" placeholder="Username">
  <input type="submit" value="Update">
</form>
</body></html>"""

        # ── Page 5: Comments (Stored-like XSS) ──────────────────────────
        elif path == '/comment':
            name = params.get('name', [''])[0]
            comment = params.get('comment', [''])[0]
            stored = ""
            if name and comment:
                stored = f"<div class='comment'><b>{name}</b>: {comment}</div>"
            body = f"""<!DOCTYPE html><html><head><title>Comments</title></head><body>
<h1>Comments</h1>
<form action="/comment" method="GET">
  <input type="text" name="name" placeholder="Your name"><br>
  <textarea name="comment" placeholder="Leave a comment"></textarea><br>
  <input type="submit" value="Post">
</form>
{stored}
</body></html>"""

        else:
            body = "<html><body><h1>404</h1></body></html>"
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body.encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body_raw = self.rfile.read(length).decode()
        params = parse_qs(body_raw)
        path = urlparse(self.path).path

        if path == '/contact_submit':
            name = params.get('name', [''])[0]
            msg = params.get('message', [''])[0]
            # VULNERABLE: no sanitization
            body = f"""<!DOCTYPE html><html><head><title>Contact Response</title></head><body>
<h1>Thank you, {name}!</h1>
<p>Your message: {msg}</p>
<a href="/contact">Back</a>
</body></html>"""
        else:
            body = "<html><body><h1>POST received</h1></body></html>"

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == '__main__':
    port = 8888
    server = HTTPServer(('0.0.0.0', port), VulnHandler)
    print(f"[*] Vulnerable test server running at http://localhost:{port}")
    print(f"[*] Pages: /, /search?q=, /login, /profile?user=, /comment, /contact")
    print(f"[*] Scan this with Shadow Spike XSS Scanner!")
    print(f"[*] Press Ctrl+C to stop.")
    server.serve_forever()
