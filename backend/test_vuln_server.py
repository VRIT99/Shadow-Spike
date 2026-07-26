from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/")
def index():
    return HTMLResponse("""
    <html>
    <body>
        <h1>Vulnerable Site</h1>
        <form action="/search" method="get">
            <input type="text" name="q" placeholder="Search...">
            <input type="submit" value="Go">
        </form>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """)

@app.get("/search")
def search(q: str = ""):
    return HTMLResponse(f"<html><body>You searched for: {q}</body></html>")

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    return HTMLResponse(f"<html><body>Login failed for: {username}</body></html>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
