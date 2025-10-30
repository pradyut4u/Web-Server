import asyncio
import os
import mimetypes
import logging
import urllib.parse
import uuid
import re
import aiosqlite
import ssl

# --- Configuration ---
HOST = '127.0.0.1'
PORT = 8080
WEB_ROOT = os.path.abspath("www")
DB_PATH = os.path.abspath("database.db")
UPLOAD_DIR = os.path.abspath("uploads") # NEW: Upload directory
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
# ---

# --- Database init is unchanged ---
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        # This table is unchanged
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                visits INTEGER NOT NULL
            )
        """)
        
        # NEW: Add this table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        await db.commit()
    logging.info(f"Database initialized at {DB_PATH}")

# --- MODIFIED: Request Class ---
class Request:
    def __init__(self, method, path, headers):
        self.method = method
        self.path = path
        self.headers = headers
        # REMOVED: self.body (handlers will read it)
        self.cookies = {}
        self.params = {}
        
        cookie_str = self.headers.get('cookie', '')
        if cookie_str:
            for cookie in cookie_str.split(';'):
                key, value = cookie.strip().split('=', 1)
                self.cookies[key] = value

# --- Router class is unchanged ---
class Router:
    def __init__(self):
        self.routes = {"GET": [], "POST": []}

    def add_route(self, method, path_regex, handler):
        compiled_regex = re.compile(f"^{path_regex}$")
        self.routes[method.upper()].append((compiled_regex, handler))
        logging.info(f"Added route: {method} {path_regex}")

    async def handle_route(self, path, method, reader, writer, request):
        for compiled_regex, handler in self.routes.get(method, []):
            match = compiled_regex.match(path)
            if match:
                request.params = match.groupdict()
                # MODIFIED: Pass the reader to the handler
                await handler(reader, writer, request)
                return

        if method == "GET":
            await handle_static_file(reader, writer, request)
        else:
            await send_404(writer)

# --- Helper functions are unchanged ---
# ... (send_response, send_404, send_redirect) ...
async def send_response(writer, status_line, headers, body=b""):
    try:
        header_str = ""
        for k, v in headers.items():
            header_str += f"{k}: {v}\r\n"
        response = (
            f"{status_line}\r\n"
            f"{header_str}"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode('utf-8') + body
        writer.write(response)
        await writer.drain()
    except Exception as e:
        logging.error(f"Error sending response: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
async def send_404(writer):
    with open(os.path.join(WEB_ROOT, "404.html"), "rb") as f:
        body = f.read()
    await send_response(writer, "HTTP/1.1 404 Not Found", {"Content-Type": "text/html"}, body)
async def send_redirect(writer, location):
    await send_response(writer, "HTTP/1.1 303 See Other", {"Location": location})

# --- MODIFIED: read_request ---
async def read_request(reader):
    """Reads and parses only the request line and headers."""
    headers = {}
    request_line_str = ""
    try:
        request_line = await reader.readline()
        request_line_str = request_line.decode('utf-8').strip()
        
        while True:
            line = await reader.readline()
            if line == b"\r\n": break # End of headers
            if line.strip() == b"": continue
            if b":" in line:
                key, value = line.decode('utf-8').strip().split(":", 1)
                headers[key.lower()] = value.strip()
        
        method, path, _ = request_line_str.split(" ")
        
        # MODIFIED: We DO NOT read the body here.
        # The handlers are now responsible for reading the body
        # from the 'reader' if they expect one.
        
        return Request(method, path, headers)
        
    except Exception as e:
        logging.error(f"Error reading request: {e} (Request line: '{request_line_str}')")
        return None

# --- Route Handlers ---

# (handle_get_index and handle_static_file are unchanged)
async def handle_get_index(reader, writer, request):
    # ... (same as Level 11) ...
    session_id = request.cookies.get("session_id")
    headers = {"Content-Type": "text/html"}
    visit_count = 0
    async with aiosqlite.connect(DB_PATH) as db:
        if not session_id:
            session_id = str(uuid.uuid4())
            visit_count = 1
            await db.execute("INSERT INTO sessions (session_id, visits) VALUES (?, ?)", (session_id, visit_count))
            await db.commit()
            headers["Set-Cookie"] = f"session_id={session_id}; HttpOnly; Path=/"
        else:
            cursor = await db.execute("SELECT visits FROM sessions WHERE session_id = ?", (session_id,))
            row = await cursor.fetchone()
            if not row:
                visit_count = 1
                await db.execute("INSERT INTO sessions (session_id, visits) VALUES (?, ?)", (session_id, visit_count))
            else:
                visit_count = row[0] + 1
                await db.execute("UPDATE sessions SET visits = ? WHERE session_id = ?", (visit_count, session_id))
            await db.commit()
    with open(os.path.join(WEB_ROOT, "index.html"), "rb") as f:
        body = f.read()
    body = body.decode('utf-8').replace("{{VISIT_COUNT}}", str(visit_count))
    body = body.encode('utf-8')
    logging.info(f"User {session_id} on visit {visit_count}")
    await send_response(writer, "HTTP/1.1 200 OK", headers, body)
async def handle_static_file(reader, writer, request):
    # ... (same as Level 11) ...
    path = request.path
    safe_path = path.lstrip('/')
    file_path = os.path.abspath(os.path.join(WEB_ROOT, safe_path))
    if not file_path.startswith(WEB_ROOT) or not os.path.exists(file_path) or not os.path.isfile(file_path):
        await send_404(writer)
        return
    mime_type, _ = mimetypes.guess_type(file_path)
    if mime_type is None:
        mime_type = "application/octet-stream"
    headers = {"Content-Type": mime_type}
    with open(file_path, "rb") as f:
        body = f.read()
    await send_response(writer, "HTTP/1.1 200 OK", headers, body)
# (handle_get_profile is unchanged)
async def handle_get_profile(reader, writer, request):
    # ... (same as Level 11) ...
    username = request.params.get("username", "Guest")
    body = f"""
    <html><head><title>Profile of {username}</title><link rel="stylesheet" href="/style.css"></head>
    <body><h1>Profile Page for: {username.capitalize()}</h1>
    <p>This page is dynamically generated by the server.</p><a href="/">Go back home</a>
    </body></html>""".encode('utf-8')
    headers = {"Content-Type": "text/html"}
    await send_response(writer, "HTTP/1.1 200 OK", headers, body)

# --- MODIFIED: handle_post_submit ---

async def handle_post_submit(reader, writer, request):
    """Handles the contact form submission and saves to DB."""
    try:
        content_length = int(request.headers.get('content-length', 0))
        if content_length == 0: 
            return await send_redirect(writer, "/")
            
        body_bytes = await reader.readexactly(content_length)
        form_data_str = body_bytes.decode('utf-8')
        form_data = urllib.parse.parse_qs(form_data_str)
        
        # Get the name and message
        # .get() returns a list, so we take the first item [0]
        name = form_data.get("username", ["Anonymous"])[0]
        message = form_data.get("message", [""])[0]

        # NEW: Save to database
        if message: # Only save if there's a message
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "INSERT INTO messages (name, message) VALUES (?, ?)",
                    (name, message)
                )
                await db.commit()
            logging.info(f"--- NEW MESSAGE SAVED from {name} ---")
        
        # Redirect back home
        await send_redirect(writer, "/")

    except Exception as e:
        logging.error(f"Error handling POST: {e}")
        await send_response(writer, "HTTP/1.1 500 Internal Error", {})

    except Exception as e:
        logging.error(f"Error handling POST: {e}")
        await send_response(writer, "HTTP/1.1 500 Internal Error", {})

# --- NEW: handle_post_upload ---
async def handle_post_upload(reader, writer, request):
    """Handles file upload using multipart/form-data."""
    try:
        # 1. Get the boundary string from the Content-Type header
        content_type = request.headers.get('content-type', '')
        if 'multipart/form-data' not in content_type:
            return await send_response(writer, "HTTP/1.1 400 Bad Request", {}, b"Not a multipart form")

        boundary = b"--" + content_type.split("boundary=")[1].encode('utf-8')
        logging.info(f"Upload started with boundary: {boundary}")
        
        # 2. Read lines from the reader until we find the file
        file_data = b""
        filename = "unknown_file"
        in_file_data = False
        
        while True:
            line = await reader.readline()
            
            if line.startswith(boundary + b"--"):
                # End of multipart data
                logging.info("End of multipart data.")
                break
                
            if line.startswith(boundary):
                # Start of a new part
                
                # Read the sub-headers for this part
                part_headers = {}
                while True:
                    sub_line = await reader.readline()
                    if sub_line == b"\r\n": break # End of sub-headers
                    if b":" in sub_line:
                        key, value = sub_line.decode('utf-8').strip().split(":", 1)
                        part_headers[key.lower()] = value.strip()
                
                # Check for file info
                content_disposition = part_headers.get('content-disposition', '')
                if 'filename' in content_disposition:
                    # This is our file part!
                    filename = re.search(r'filename="([^"]+)"', content_disposition).group(1)
                    # Sanitize filename (basic security)
                    filename = os.path.basename(filename) 
                    logging.info(f"Found file part. Filename: {filename}")
                    in_file_data = True
                
            elif in_file_data:
                # We are in the file data part, so append the line,
                # but check if it's the *next* boundary
                if line.startswith(boundary):
                    # We hit the next boundary, so the file data just ended.
                    # We need to remove the final \r\n from the data.
                    file_data = file_data[:-2]
                    in_file_data = False
                else:
                    file_data += line

        # 3. Save the file
        if file_data and filename != "unknown_file":
            save_path = os.path.join(UPLOAD_DIR, filename)
            
            # Use asyncio.to_thread to save the file without blocking
            await asyncio.to_thread(lambda: 
                open(save_path, "wb").write(file_data)
            )
            logging.info(f"Successfully saved file to: {save_path}")

        # 4. Redirect back home
        await send_redirect(writer, "/")

    except Exception as e:
        logging.error(f"Error handling upload: {e}")
        await send_response(writer, "HTTP/1.1 500 Internal Error", {})


# --- Client Handler is unchanged ---
async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logging.info(f"\n--- Connected by {addr} ---")
    request = await read_request(reader)
    if request:
        logging.info(f"{addr} - {request.method} {request.path}")
        await router.handle_route(request.path, request.method, reader, writer, request)
    else:
        logging.warning(f"Closing connection from {addr} due to bad request.")
        writer.close()
        await writer.wait_closed()

# --- MODIFIED: Main Server Setup ---
async def main():
    # NEW: Create uploads directory if it doesn't exist
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
        logging.info(f"Created uploads directory at: {UPLOAD_DIR}")
        
    await init_db()

    global router
    router = Router()
    
    # Add our routes
    router.add_route("GET", r"/?$", handle_get_index)
    router.add_route("POST", r"/submit/?$", handle_post_submit)
    router.add_route("GET", r"/profile/(?P<username>[a-zA-Z0-9]+)/?$", handle_get_profile)
    
    # NEW: Add the upload route
    router.add_route("POST", r"/upload/?$", handle_post_upload)
    
    # SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_context.load_cert_chain('cert.pem', 'key.pem')
    except FileNotFoundError:
        logging.error("FATAL: Could not find 'cert.pem' or 'key.pem'.")
        return

    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
        ssl=ssl_context
    )
    
    addr = server.sockets[0].getsockname()
    logging.info(f"--- Server listening on https://{addr[0]}:{addr[1]} ---")
    logging.info(f"--- Serving files from: {WEB_ROOT} ---")
    async with server:
        await server.serve_forever()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\n--- Server shutting down ---")