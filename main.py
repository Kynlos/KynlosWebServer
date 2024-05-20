import http.server
import socketserver
import json
import os
import subprocess
import logging
import webbrowser
import signal
import sys
from urllib.parse import unquote, urlparse, parse_qs
from io import BytesIO
import ssl
from functools import wraps
from time import time
from collections import defaultdict
from http import HTTPStatus
from concurrent.futures import ThreadPoolExecutor
import mimetypes
import threading
import datetime
import gzip
import brotli
from cert import generate_self_signed_cert, check_cert_expiry, start_cert_renewal_timer

# Load configuration from config file
def load_config(config_file='config.json'):
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file {config_file} not found.")
        raise
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {config_file}.")
        raise

config = load_config()

# ---------------------- SERVER CONFIGURATION ----------------------

# Load all configuration options from config.json
PORT = config.get('server_config', {}).get('port', 8080)
ENTRY_POINT = config.get('server_config', {}).get('entry_point', 'index.html')
HTDOCS_DIR = config.get('server_config', {}).get('htdocs_dir', 'htdocs')
DOWNLOADS_DIR = config.get('server_config', {}).get('downloads_dir', os.path.join(HTDOCS_DIR, 'downloads'))
LOG_FILE = config.get('server_config', {}).get('log_file', 'server.log')

# HTTPS configuration
USE_HTTPS = config.get('server_features', {}).get('use_https', False)
CERTFILE = config.get('https_config', {}).get('certfile', 'cert.pem')
KEYFILE = config.get('https_config', {}).get('keyfile', 'key.pem')
CERT_CONFIG = config.get('https_config', {}).get('cert_config', {})
CERT_RENEWAL_DAYS = config.get('https_config', {}).get('cert_renewal_days', 30)

# Rate limiting configuration
ENABLE_RATE_LIMITING = config.get('server_features', {}).get('enable_rate_limiting', True)
RATE_LIMIT = config.get('rate_limiting_config', {}).get('rate_limit', 10)  # requests per minute
RATE_LIMIT_BURST = config.get('rate_limiting_config', {}).get('rate_limit_burst', 5)  # Allow bursts of requests
rate_limit_data = defaultdict(lambda: {'count': 0, 'last_reset': time()})

# IP Filtering
ENABLE_IP_FILTERING = config.get('server_features', {}).get('enable_ip_filtering', False)
WHITELIST = config.get('ip_filtering_config', {}).get('whitelist', [])
BLACKLIST = config.get('ip_filtering_config', {}).get('blacklist', [])

# Static file caching
ENABLE_STATIC_FILE_CACHE = config.get('server_features', {}).get('enable_static_file_cache', True)
CACHE = {}
CACHE_MAX_SIZE = config.get('caching_config', {}).get('cache_max_size', 10 * 1024 * 1024)  # 10MB
CACHE_TTL = config.get('caching_config', {}).get('cache_ttl', 60)  # 60 seconds

# Compression
ENABLE_GZIP_COMPRESSION = config.get('server_features', {}).get('enable_gzip_compression', True)
ENABLE_BROTLI_COMPRESSION = config.get('server_features', {}).get('enable_brotli_compression', True)

# Basic Authentication
ENABLE_BASIC_AUTH = config.get('server_features', {}).get('enable_basic_auth', False)
AUTH_USERS = config.get('basic_auth_config', {}).get('auth_users', {})

# Virtual Hosts
ENABLE_VIRTUAL_HOSTS = config.get('server_features', {}).get('enable_virtual_hosts', False)
VIRTUAL_HOSTS = config.get('virtual_hosts_config', {}).get('virtual_hosts', {})

# Custom error pages
ENABLE_CUSTOM_ERROR_PAGES = config.get('server_features', {}).get('enable_custom_error_pages', False)
ERROR_PAGES = config.get('error_pages_config', {}).get('error_pages', {})

# URL Redirection
ENABLE_URL_REDIRECTS = config.get('server_features', {}).get('enable_url_redirects', False)
URL_REDIRECTS = config.get('url_redirects_config', {}).get('url_redirects', {})

# ---------------------- DECORATORS ----------------------

def rate_limited(func):
    @wraps(func)
    def wrapper(handler, *args, **kwargs):
        if not ENABLE_RATE_LIMITING:
            return func(handler, *args, **kwargs)

        client_ip = handler.client_address[0]
        data = rate_limit_data[client_ip]

        # Reset rate limit if enough time has passed
        if time() - data['last_reset'] >= 60:
            data['count'] = 0
            data['last_reset'] = time()

        if data['count'] >= RATE_LIMIT:
            handler.send_error(429, "Too Many Requests")
            return

        data['count'] += 1
        return func(handler, *args, **kwargs)

    return wrapper


def ip_allowed(func):
    @wraps(func)
    def wrapper(handler, *args, **kwargs):
        if not ENABLE_IP_FILTERING:
            return func(handler, *args, **kwargs)

        client_ip = handler.client_address[0]
        if WHITELIST and client_ip not in WHITELIST:
            handler.send_error(403, "Forbidden")
            return
        if BLACKLIST and client_ip in BLACKLIST:
            handler.send_error(403, "Forbidden")
            return
        return func(handler, *args, **kwargs)

    return wrapper


def basic_auth(func):
    @wraps(func)
    def wrapper(handler, *args, **kwargs):
        if not ENABLE_BASIC_AUTH:
            return func(handler, *args, **kwargs)

        auth_header = handler.headers.get('Authorization')
        if auth_header:
            auth_type, encoded_credentials = auth_header.split(' ', 1)
            if auth_type.lower() == 'basic':
                try:
                    username, password = encoded_credentials.encode().decode('base64').split(':', 1)
                except:
                    handler.send_error(401, 'Invalid Authorization header')
                    return
                if AUTH_USERS.get(username) == password:
                    return func(handler, *args, **kwargs)
        handler.send_error(401, 'Unauthorized')
        handler.send_header('WWW-Authenticate', 'Basic realm="Restricted Area"')
    return wrapper


# ---------------------- REQUEST HANDLER ----------------------

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.entry_point = kwargs.pop('entry_point', ENTRY_POINT)
        self.executor = kwargs.pop('executor', None)
        super().__init__(*args, directory=HTDOCS_DIR, **kwargs)

    @ip_allowed
    @rate_limited
    @basic_auth
    def do_GET(self):
        # Virtual Host Routing
        if ENABLE_VIRTUAL_HOSTS:
            host = self.headers.get('Host')
            virtual_host = VIRTUAL_HOSTS.get(host)
            if virtual_host:
                self.directory = virtual_host.get('htdocs_dir', HTDOCS_DIR)
                self.entry_point = virtual_host.get('entry_point', ENTRY_POINT)

        # URL Redirection
        if ENABLE_URL_REDIRECTS:
            redirect = URL_REDIRECTS.get(self.path)
            if redirect:
                self.send_response(302)  # Temporary redirect
                self.send_header('Location', redirect)
                self.end_headers()
                return

        if self.path == '/':
            self.path = '/' + self.entry_point
        elif self.path == '/list-downloads':
            self.list_downloads()
        elif self.path.startswith('/downloads/'):
            self.serve_download()
        else:
            self.serve_static_file()

    @ip_allowed
    @rate_limited
    @basic_auth
    def do_POST(self):
        if self.path == '/upload':
            self.handle_file_upload()
        else:
            self.send_error(404, "File not found")

    def handle_php(self):
        try:
            php_file_path = self.translate_path(self.path)
            if not os.path.exists(php_file_path):
                self.send_error(404, "File not found")
                return

            future = self.executor.submit(subprocess.run, ['php', php_file_path], capture_output=True)
            process = future.result()

            if process.returncode != 0:
                self.send_error(500, "PHP execution failed")
                logging.error(f"PHP execution failed: {process.stderr.decode()}")
                return

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(process.stdout)
        except Exception as e:
            self.send_error(500, "Internal server error")
            logging.error(f"Exception while handling PHP file: {e}")

    def handle_file_upload(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        boundary = self.headers['Content-Type'].split("=")[1].encode()
        parts = body.split(boundary)

        for part in parts:
            if b'Content-Disposition' in part:
                headers, content = part.split(b'\r\n\r\n', 1)
                headers = headers.decode()
                filename = headers.split('filename="')[1].split('"')[0]
                filepath = os.path.join(DOWNLOADS_DIR, filename)
                with open(filepath, 'wb') as f:
                    f.write(content.rstrip(b'\r\n--'))

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        response = BytesIO()
        response.write(b"File uploaded successfully")
        self.wfile.write(response.getvalue())

    def serve_static_file(self):
        file_path = self.translate_path(self.path)

        # Check if file exists
        if not os.path.exists(file_path):
            self.send_error(404, 'File not found')
            return

        # Check for custom error document
        if not os.path.exists(file_path):
            error_code = 404
            if hasattr(HTTPStatus, str(error_code)) and ENABLE_CUSTOM_ERROR_PAGES:
                self.send_error(error_code)
                return

        # Serve from cache if available
        if file_path in CACHE:
            entry = CACHE[file_path]
            if time() - entry['timestamp'] < CACHE_TTL:
                self.send_response(200)
                self.send_header("Content-type", entry['content_type'])
                self.send_header("Content-Encoding", entry['content_encoding'])
                self.send_header("Content-Length", entry['content_length'])
                self.end_headers()

                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
                return

        # Open the file
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

        except Exception as e:
            self.send_error(500, f"Internal server error: {e}")
            return

        # Compression
        content_encoding = None
        if ENABLE_GZIP_COMPRESSION and 'gzip' in self.headers.get('Accept-Encoding', ''):
            content_encoding = 'gzip'
            content = gzip.compress(content)
        elif ENABLE_BROTLI_COMPRESSION and 'br' in self.headers.get('Accept-Encoding', ''):
            content_encoding = 'br'
            content = brotli.compress(content)

        # Determine content type
        content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'

        # Cache the file if caching is enabled
        if ENABLE_STATIC_FILE_CACHE:
            if len(CACHE) >= CACHE_MAX_SIZE:
                CACHE.pop(next(iter(CACHE)))
            CACHE[file_path] = {
                'timestamp': time(),
                'content_type': content_type,
                'content_encoding': content_encoding,
                'content_length': len(content)
            }

        # Serve the file
        self.send_response(200)
        self.send_header("Content-type", content_type)
        if content_encoding:
            self.send_header("Content-Encoding", content_encoding)
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)

    def list_downloads(self):
        try:
            files = os.listdir(DOWNLOADS_DIR)
            files = [f for f in files if os.path.isfile(os.path.join(DOWNLOADS_DIR, f))]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"files": files})
            self.wfile.write(response.encode())
        except Exception as e:
            self.send_error(500, "Internal server error")
            logging.error(f"Exception while listing downloads: {e}")

    def serve_download(self):
        file_path = self.path.lstrip('/')
        full_path = os.path.join(HTDOCS_DIR, file_path)
        if os.path.exists(full_path) and os.path.isfile(full_path):
            mime_type, _ = mimetypes.guess_type(full_path)
            self.send_response(200)
            self.send_header("Content-Type", mime_type or "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(full_path)}"')
            self.send_header("Content-Length", str(os.path.getsize(full_path)))
            self.end_headers()
            with open(full_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File not found")

    def list_directory(self, path):
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        f = BytesIO()
        displaypath = unquote(self.path)
        f.write(b'<!DOCTYPE html>\n<html>\n<head>\n<title>Directory listing for %s</title>\n</head>\n' % displaypath.encode())
        f.write(b'<body>\n<h2>Directory listing for %s</h2>\n' % displaypath.encode())
        f.write(b'<hr>\n<ul>\n')
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            f.write(b'<li><a href="%s">%s</a></li>\n' % (linkname.encode(), displayname.encode()))
        f.write(b'</ul>\n<hr>\n</body>\n</html>\n')
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def send_error(self, code, message=None):
        # Use custom error pages if configured
        if ENABLE_CUSTOM_ERROR_PAGES and str(code) in ERROR_PAGES:
            error_page_path = ERROR_PAGES[str(code)]
            try:
                with open(error_page_path, 'rb') as f:
                    content = f.read()
                self.send_response(code)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(content)
                return
            except:
                logging.error(f"Failed to load custom error page: {error_page_path}")

        # Default error handling
        self.error_message_format = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error response</title>
        </head>
        <body>
            <h1>Error response</h1>
            <p>Error code: %(code)d</p>
            <p>Message: %(message)s</p>
        </body>
        </html>
        '''
        super().send_error(code, message)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def log_message(self, format, *args):
        with open(LOG_FILE, "a") as log_file:
            log_file.write("%s - - [%s] %s\n" %
                           (self.client_address[0],
                            self.log_date_time_string(),
                            format % args))


# ---------------------- SERVER FUNCTIONS ----------------------

def run_server():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    try:
        if USE_HTTPS:
            generate_self_signed_cert(CERTFILE, KEYFILE, CERT_CONFIG)
            # Start a timer to check certificate expiry periodically
            timer = start_cert_renewal_timer(CERTFILE, KEYFILE, CERT_CONFIG, CERT_RENEWAL_DAYS)

        with ThreadPoolExecutor() as executor:
            handler = lambda *args, **kwargs: CustomHTTPRequestHandler(*args, entry_point=ENTRY_POINT, executor=executor,
                                                                    **kwargs)
            with socketserver.ThreadingTCPServer(("0.0.0.0", PORT), handler) as httpd:
                if USE_HTTPS:
                    httpd.socket = ssl.wrap_socket(httpd.socket, certfile=CERTFILE, keyfile=KEYFILE, server_side=True)
                    logging.info(f"Serving on port {PORT} with HTTPS")
                    webbrowser.open(f'https://localhost:{PORT}/{ENTRY_POINT}')
                else:
                    logging.info(f"Serving on port {PORT}")
                    webbrowser.open(f'http://localhost:{PORT}/{ENTRY_POINT}')

                # Handle graceful shutdown on Ctrl-C
                def signal_handler(sig, frame):
                    logging.info('Shutting down server...')
                    httpd.shutdown()
                    if USE_HTTPS:
                        timer.cancel()  # Cancel the timer
                    sys.exit(0)

                signal.signal(signal.SIGINT, signal_handler)
                httpd.serve_forever()
    except Exception as e:
        logging.error(f"Failed to start server: {e}")


if __name__ == "__main__":
    run_server()
