import http.server
import socketserver
import json
import os
import subprocess
import logging
import webbrowser
import signal
import sys
from urllib.parse import unquote
from io import BytesIO
import ssl
from functools import wraps
from time import time
from collections import defaultdict
from OpenSSL import crypto
from http import HTTPStatus
from concurrent.futures import ThreadPoolExecutor
import mimetypes

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

# Rate limiting configuration
RATE_LIMIT = config.get('rate_limit', 10)  # requests per minute
rate_limit_data = defaultdict(list)

# IP Whitelisting/Blacklisting
WHITELIST = config.get('whitelist', [])
BLACKLIST = config.get('blacklist', [])

# Static file caching
CACHE = {}

# Directories
HTDOCS_DIR = config.get('htdocs_dir', 'htdocs')
DOWNLOADS_DIR = config.get('downloads_dir', os.path.join(HTDOCS_DIR, 'downloads'))

def rate_limited(func):
    @wraps(func)
    def wrapper(handler, *args, **kwargs):
        client_ip = handler.client_address[0]
        current_time = time()
        request_times = rate_limit_data[client_ip]

        # Remove old requests
        rate_limit_data[client_ip] = [t for t in request_times if current_time - t < 60]

        if len(rate_limit_data[client_ip]) >= RATE_LIMIT:
            handler.send_error(429, "Too Many Requests")
            return

        rate_limit_data[client_ip].append(current_time)
        return func(handler, *args, **kwargs)
    return wrapper

def ip_allowed(func):
    @wraps(func)
    def wrapper(handler, *args, **kwargs):
        client_ip = handler.client_address[0]
        if WHITELIST and client_ip not in WHITELIST:
            handler.send_error(403, "Forbidden")
            return
        if BLACKLIST and client_ip in BLACKLIST:
            handler.send_error(403, "Forbidden")
            return
        return func(handler, *args, **kwargs)
    return wrapper

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.entry_point = kwargs.pop('entry_point', 'index.html')
        self.executor = kwargs.pop('executor', None)
        super().__init__(*args, directory=HTDOCS_DIR, **kwargs)

    @ip_allowed
    def do_GET(self):
        if self.path == '/':
            self.path = '/' + self.entry_point
        elif self.path == '/list-downloads':
            self.list_downloads()
        elif self.path.startswith('/downloads/'):
            self.serve_download()
        else:
            self.serve_static_file()

    @ip_allowed
    def do_POST(self):
        if self.path == '/upload':
            self.handle_file_upload()
        else:
            self.send_error(404, "File not found")

    @rate_limited
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

    @rate_limited
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
        if self.path in CACHE:
            self.send_response(200)
            self.send_header("Content-type", CACHE[self.path]['content_type'])
            self.send_header("Content-Length", str(len(CACHE[self.path]['content'])))
            self.end_headers()
            self.wfile.write(CACHE[self.path]['content'])
        else:
            super().do_GET()

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
        with open(config.get('log_file', 'server.log'), "a") as log_file:
            log_file.write("%s - - [%s] %s\n" %
                           (self.client_address[0],
                            self.log_date_time_string(),
                            format % args))

def generate_self_signed_cert(certfile, keyfile, cert_config):
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        logging.info("Generating self-signed certificate and key...")

        # Create a key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, cert_config.get('key_size', 2048))

        # Create a self-signed cert
        cert = crypto.X509()
        subject = cert.get_subject()
        for key, value in cert_config.get('subject', {}).items():
            setattr(subject, key, value)
        cert.set_serial_number(cert_config.get('serial_number', 1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(cert_config.get('valid_days', 3650) * 24 * 60 * 60)
        cert.set_issuer(subject)
        cert.set_pubkey(key)
        cert.sign(key, cert_config.get('signing_algorithm', 'sha256'))

        with open(certfile, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(keyfile, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        logging.info("Self-signed certificate and key generated.")

def run_server():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    try:
        port = config.get('port', 8080)
        entry_point = config.get('entry_point', 'index.html')
        use_https = config.get('use_https', False)
        certfile = config.get('certfile', 'cert.pem')
        keyfile = config.get('keyfile', 'key.pem')
        cert_config = config.get('cert_config', {})

        if use_https:
            generate_self_signed_cert(certfile, keyfile, cert_config)

        with ThreadPoolExecutor() as executor:
            handler = lambda *args, **kwargs: CustomHTTPRequestHandler(*args, entry_point=entry_point, executor=executor, **kwargs)
            with socketserver.ThreadingTCPServer(("", port), handler) as httpd:
                if use_https:
                    httpd.socket = ssl.wrap_socket(httpd.socket, certfile=certfile, keyfile=keyfile, server_side=True)
                    logging.info(f"Serving on port {port} with HTTPS")
                    webbrowser.open(f'https://localhost:{port}/{entry_point}')
                else:
                    logging.info(f"Serving on port {port}")
                    webbrowser.open(f'http://localhost:{port}/{entry_point}')

                # Handle graceful shutdown on Ctrl-C
                def signal_handler(sig, frame):
                    logging.info('Shutting down server...')
                    httpd.shutdown()
                    sys.exit(0)

                signal.signal(signal.SIGINT, signal_handler)
                httpd.serve_forever()
    except Exception as e:
        logging.error(f"Failed to start server: {e}")

if __name__ == "__main__":
    run_server()
