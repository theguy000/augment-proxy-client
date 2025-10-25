#!/usr/bin/env python3
"""
Simple HTTP proxy client that adds Proxy-Authorization header
Supports both console mode and Windows service mode
"""

import socket
import threading
import base64
import sys
import signal
import os
import time
import logging
from pathlib import Path

# Configuration
LOCAL_HOST = '127.0.0.1'
LOCAL_PORT = 3128
UPSTREAM_HOST = 'proxy.ai-proxy.space'
UPSTREAM_PORT = 6969

# Global variables for service mode
server_socket = None
running = False

# Setup logging
log_dir = Path("C:/Program Files/AugmentProxy/logs")
try:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "proxy_client.log"
except:
    log_file = Path("proxy_client.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def create_auth_header(username, password):
    """Create Basic authentication header"""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return f"Proxy-Authorization: Basic {encoded}"

def handle_client(client_socket, auth_header):
    """Handle client connection"""
    try:
        # Receive request from client
        request = client_socket.recv(8192)
        if not request:
            client_socket.close()
            return

        logging.debug(f"Received {len(request)} bytes")

        # Parse request
        request_str = request.decode('utf-8', errors='ignore')

        # Check if it's a CONNECT request (HTTPS)
        if request_str.startswith('CONNECT'):
            handle_https_tunnel(client_socket, request_str, auth_header)
            return

        # For HTTP, add Proxy-Authorization header
        # Find the end of the first line (request line)
        first_line_end = request_str.find('\r\n')
        if first_line_end == -1:
            logging.error("Invalid HTTP request - no CRLF found")
            client_socket.close()
            return

        request_line = request_str[:first_line_end]
        rest_of_request = request_str[first_line_end + 2:]  # Skip the \r\n

        # Build new request with auth header inserted after request line
        modified_request = f"{request_line}\r\n{auth_header}\r\n{rest_of_request}"

        logging.debug(f"Request line: {request_line}")
        logging.debug(f"Connecting to {UPSTREAM_HOST}:{UPSTREAM_PORT}...")

        # Connect to upstream proxy
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_socket.settimeout(10)
        upstream_socket.connect((UPSTREAM_HOST, UPSTREAM_PORT))

        logging.debug("Connected to upstream proxy")

        # Send modified request
        upstream_socket.sendall(modified_request.encode('utf-8'))

        logging.debug("Sent request to upstream proxy")

        # Forward response back to client
        total_received = 0
        while True:
            data = upstream_socket.recv(8192)
            if not data:
                break
            total_received += len(data)
            client_socket.sendall(data)

        logging.debug(f"Received {total_received} bytes from upstream")

        upstream_socket.close()
        client_socket.close()

    except socket.timeout:
        logging.error("Timeout connecting to upstream proxy")
        try:
            client_socket.close()
        except:
            pass
    except Exception as e:
        logging.error(f"Error handling client: {e}")
        try:
            client_socket.close()
        except:
            pass

def handle_https_tunnel(client_socket, request_str, auth_header):
    """Handle HTTPS CONNECT tunnel"""
    try:
        logging.debug("Handling HTTPS CONNECT tunnel")

        # Extract CONNECT line
        first_line_end = request_str.find('\r\n')
        connect_line = request_str[:first_line_end]

        logging.debug(f"CONNECT line: {connect_line}")

        # Connect to upstream proxy
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_socket.settimeout(10)
        upstream_socket.connect((UPSTREAM_HOST, UPSTREAM_PORT))

        # Send CONNECT request with auth header
        connect_request = f"{connect_line}\r\n{auth_header}\r\n\r\n"
        upstream_socket.sendall(connect_request.encode('utf-8'))

        logging.debug("Sent CONNECT request to upstream")

        # Read response from upstream
        response = upstream_socket.recv(8192)

        logging.debug(f"Received CONNECT response: {response[:100]}")

        # Forward response to client
        client_socket.sendall(response)

        # Check if connection was successful (200)
        if b'200' in response:
            logging.debug("CONNECT successful, starting tunnel")

            # Start bidirectional forwarding
            def forward(source, destination):
                try:
                    while True:
                        data = source.recv(8192)
                        if not data:
                            break
                        destination.sendall(data)
                except:
                    pass
                finally:
                    try:
                        source.close()
                        destination.close()
                    except:
                        pass

            # Create threads for bidirectional forwarding
            client_to_upstream = threading.Thread(target=forward, args=(client_socket, upstream_socket))
            upstream_to_client = threading.Thread(target=forward, args=(upstream_socket, client_socket))

            client_to_upstream.daemon = True
            upstream_to_client.daemon = True

            client_to_upstream.start()
            upstream_to_client.start()

            client_to_upstream.join()
            upstream_to_client.join()
        else:
            logging.error("CONNECT failed")
            upstream_socket.close()
            client_socket.close()

    except Exception as e:
        logging.error(f"Error handling HTTPS tunnel: {e}")
        try:
            client_socket.close()
        except:
            pass

def start_proxy(username, password):
    """Start the proxy server"""
    global server_socket, running
    
    auth_header = create_auth_header(username, password)

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCAL_HOST, LOCAL_PORT))
    server_socket.listen(100)
    server_socket.settimeout(1.0)  # Allow periodic checks for shutdown

    logging.info(f"Proxy listening on {LOCAL_HOST}:{LOCAL_PORT}")
    logging.info(f"Forwarding to {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    logging.info(f"Username: {username}")

    running = True

    try:
        while running:
            try:
                client_socket, addr = server_socket.accept()
                logging.debug(f"Accepted connection from {addr}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket, auth_header))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                # Timeout is expected, allows us to check running flag
                continue
            except Exception as e:
                if running:
                    logging.error(f"Error accepting connection: {e}")
    except KeyboardInterrupt:
        logging.info("Shutting down proxy...")
    finally:
        running = False
        if server_socket:
            server_socket.close()

def stop_proxy():
    """Stop the proxy server"""
    global running, server_socket
    logging.info("Stop signal received")
    running = False
    if server_socket:
        try:
            server_socket.close()
        except:
            pass

def main():
    """Main entry point"""
    if len(sys.argv) < 3:
        logging.error("Usage: proxy_client.exe <username> <password>")
        logging.error("Example: proxy_client.exe user_d99cfdfd NUqvdSuFzztEBPQC")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logging.info("Shutting down proxy...")
        stop_proxy()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    start_proxy(username, password)

if __name__ == '__main__':
    main()
