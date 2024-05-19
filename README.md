# Kynlos Python Web Server with PHP Support

This is a Python-based web server that supports serving static files, executing PHP scripts, file uploads, rate limiting, IP whitelisting/blacklisting, HTTPS using self-signed certificates, CORS support, custom error pages, and static file caching. The server is highly configurable via a `config.json` file.

## Features

- Serves static files from the `htdocs` directory
- Executes PHP scripts using the `php` command
- Supports file uploads via POST requests to `/upload`, with uploaded files saved in the `htdocs/downloads` directory
- Provides a file download page at `htdocs/download.html` for accessing uploaded files
- Rate limiting to prevent abuse (configurable requests per minute)
- IP whitelisting and blacklisting for access control
- HTTPS support using self-signed certificates
- Cross-Origin Resource Sharing (CORS) support
- Serves custom HTML pages for different HTTP error codes
- Implements caching for static files to improve performance
- Customizable entry point (default: `index.html`)
- Logging of requests to a log file
- Graceful shutdown on Ctrl-C
- Opens the entry point in a web browser on server start

## Requirements

- Python 3.x
- `php` command available in PATH (for PHP script execution)
- `OpenSSL` Python library (for HTTPS support)

## Configuration

The server can be configured using a `config.json` file in the same directory as the script. The following options are available:

- `port`: The port number to run the server on (default: 80)
- `entry_point`: The default file to serve when accessing the root URL (default: `index.html`)
- `use_https`: Whether to enable HTTPS using a self-signed certificate (default: `false`)
- `certfile`: The path to the certificate file for HTTPS (default: `cert.pem`)
- `keyfile`: The path to the private key file for HTTPS (default: `key.pem`)
- `rate_limit`: The maximum number of requests per minute per IP (default: `10`)
- `log_file`: The path to the log file for request logging (default: `server.log`)
- `whitelist`: A list of IP addresses that are allowed to access the server (default: `[]`)
- `blacklist`: A list of IP addresses that are blocked from accessing the server (default: `[]`)
- `htdocs_dir`: The directory to serve static files from (default: `htdocs`)
- `downloads_dir`: The directory to save uploaded files to (default: `htdocs/downloads`)
- `cert_config`: Configuration options for generating the self-signed certificate
  - `key_size`: The size of the private key in bits (default: `2048`)
  - `subject`: The subject information for the certificate
    - `C`: Country (default: `US`)
    - `ST`: State (default: `California`)
    - `L`: Locality (default: `San Francisco`)
    - `O`: Organization (default: `My Company`)
    - `OU`: Organizational Unit (default: `My Organization`)
    - `CN`: Common Name (default: `localhost`)
  - `serial_number`: Serial number (default: `1000`)
  - `valid_days`: Number of days the certificate is valid for (default: `3650`)
  - `signing_algorithm`: The signing algorithm to use (default: `sha256`)

## Usage

1. Clone the repository or download the `main.py` file.
2. Create a `config.json` file in the same directory as `main.py` with your desired configuration options.
3. Place your static files and PHP scripts in the `htdocs` directory or subdirectories.
4. Run the server using `python main.py`.
5. Access the server in a web browser at `http://localhost` (or the configured port).
6. Upload files via the `/upload` endpoint and access them from the `htdocs/download.html` page.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is open-source and available under the [MIT License](https://opensource.org/licenses/MIT).
