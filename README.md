Async HTTP Server & Web App from Scratch
This is a complete, high-performance, asynchronous HTTP web server and application framework built from the ground up in Python. It uses only built-in Python libraries (like asyncio, socket, ssl, sqlite3) and has zero third-party dependencies.

The primary goal of this project is to demonstrate a fundamental, low-level understanding of web protocols and modern server architecture by manually implementing every feature, from socket handling to database persistence.

The server currently hosts a complete portfolio resume page, handles POST requests, and saves user messages to a persistent SQLite database.

🚀 Key Features
Asynchronous & Concurrent: Built on asyncio to handle thousands of simultaneous connections on a single thread.

Hybrid Threading Model: Uses a ThreadPoolExecutor (asyncio.to_thread) to offload all blocking I/O (file reads, database writes), preventing the main event loop from ever blocking.

Persistent Database: Integrated with aiosqlite to save user data (sessions, contact form messages) so it survives server restarts.

Dynamic Regex Router: A custom Router class that uses regular expressions to map dynamic URLs (e.g., /profile/alice) to handler functions.

Full POST Handling:

Parses application/x-www-form-urlencoded for text-based forms.

Parses multipart/form-data for file uploads, saving files to the server.

Session Management: Creates a unique session ID (UUID) for new users and tracks them using secure, HttpOnly cookies.

Server-Side Templating: A simple template engine replaces placeholders (like {{VISIT_COUNT}}) in HTML files before serving.

Production-Grade Security:

HTTPS/SSL: Runs on https:// using the ssl module (for local dev).

Path Traversal Mitigation: Actively prevents "dot-dot-slash" (../) attacks by sanitizing all file paths.

MIME-Type Handling: Correctly serves static assets like CSS, JavaScript, and images using the mimetypes library.

Production Ready: The final server is refactored to run as a pure http app server on 127.0.0.1:8000, designed to be run behind a professional reverse proxy like Nginx. A complete nginx.conf is included.

🛠️ Evolution & Technical Deep Dive
This server was built iteratively, with each level solving a critical problem of the previous one.

Level 1: The Concurrency Problem
Problem: A simple socket.accept() loop is blocking. It can only handle one client at a time, forcing all other users to wait in line.

Inefficient Solution (threading): The first fix was to spawn a new thread for every connection. This works, but it's resource-heavy and does not scale to thousands of users (this is the C10k problem).

Level 2: The C10k Problem
Problem: The multi-threaded model is slow and limited by the OS.

Efficient Solution (asyncio): The server was rebuilt on asyncio. It now uses a single-threaded event loop to manage all connections. Network I/O (await reader.read()) is non-blocking, allowing the server to handle thousands of connections concurrently with minimal resource overhead.

Level 3: The Blocking I/O Problem
Problem: Even an asyncio server can be blocked. A "slow" operation like reading a large file from disk (open(...).read()) or a slow database query would freeze the entire event loop, blocking all other users.

Solution (Hybrid Model): We implemented the best-of-both-worlds architecture.

The asyncio event loop handles all high-speed network I/O.

All blocking I/O (like file and database access) is delegated to a separate ThreadPoolExecutor using asyncio.to_thread.

This ensures the main loop never blocks and is always free to handle new requests, resulting in a highly performant and scalable server.

Level 4: The Security Problem
Problem: A naive file server is vulnerable to Path Traversal. A user could request GET /../server.py and steal the server's source code.

Solution (Path Sanitization): We "jail" the file server. Every file path is resolved to its absolute path (os.path.abspath). The server then verifies that this resolved path still starts with the WEB_ROOT directory. If it doesn't, it returns a 403 Forbidden and logs the security attempt.

Level 5: The Static Content Problem
Problem: The browser would receive style.css but render it as plain text because the server sent Content-Type: text/html.

Solution (MIME Types): The server uses the mimetypes library to guess a file's type based on its extension (e.g., .css -> text/css, .png -> image/png) and sends the correct Content-Type header, so the browser renders it properly.

Level 6: The "Static-Only" Problem
Problem: The server could only GET files. It had no way to receive data from a user.

Solution (Application Framework): We built a true application framework on top of the server:

POST Handling: Logic was added to parse both application/x-www-form-urlencoded (for text forms) and multipart/form-data (for file uploads).

Regex Router: A Router class was built to match incoming paths against a list of regular expressions, allowing for dynamic routes like /profile/<username>.

Session Management: The server issues a secure HttpOnly cookie to track user sessions.

Database Persistence: The SESSIONS dictionary and "Contact Me" form submissions are saved to a SQLite database, making user data persistent across server restarts.