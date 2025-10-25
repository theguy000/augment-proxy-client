#!/usr/bin/env python3
"""
Simple HTTP proxy client that adds Proxy-Authorization header
"""

import socket
import threading
import base64
import sys
import signal

# Configuration
LOCAL_HOST = '127.0.0.1'
LOCAL_PORT = 3128
UPSTREAM_HOST = 'proxy.ai-proxy.space'
UPSTREAM_PORT = 6969

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

        print(f"[DEBUG] Received {len(request)} bytes")

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
            print("[ERROR] Invalid HTTP request - no CRLF found")
            client_socket.close()
            return

        request_line = request_str[:first_line_end]
        rest_of_request = request_str[first_line_end + 2:]  # Skip the \r\n

        # Build new request with auth header inserted after request line
        modified_request = f"{request_line}\r\n{auth_header}\r\n{rest_of_request}"
        
        print(f"[DEBUG] Request line: {request_line}")
        print(f"[DEBUG] Auth header: {auth_header}")
        print(f"[DEBUG] Connecting to {UPSTREAM_HOST}:{UPSTREAM_PORT}...")

        # Connect to upstream proxy
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_socket.settimeout(10)
        upstream_socket.connect((UPSTREAM_HOST, UPSTREAM_PORT))
        
        print("[DEBUG] Connected to upstream proxy")
        print(f"[DEBUG] Sending: {modified_request[:200]}")

        # Send modified request
        upstream_socket.sendall(modified_request.encode('utf-8'))
        
        print("[DEBUG] Sent request to upstream proxy")

        # Forward response back to client
        total_received = 0
        while True:
            data = upstream_socket.recv(8192)
            if not data:
                break
            total_received += len(data)
            client_socket.sendall(data)
        
        print(f"[DEBUG] Received {total_received} bytes from upstream")
        
        upstream_socket.close()
        client_socket.close()

    except socket.timeout:
        print("[ERROR] Timeout connecting to upstream proxy")
        try:
            client_socket.close()
        except:
            pass
    except Exception as e:
        print(f"[ERROR] Error handling client: {e}")
        import traceback
        traceback.print_exc()
        try:
            client_socket.close()
        except:
            pass

def handle_https_tunnel(client_socket, request_str, auth_header):
    """Handle HTTPS CONNECT tunnel"""
    try:
        print("[DEBUG] Handling HTTPS CONNECT tunnel")
        
        # Extract CONNECT line
        first_line_end = request_str.find('\r\n')
        connect_line = request_str[:first_line_end]
        
        print(f"[DEBUG] CONNECT line: {connect_line}")

        # Connect to upstream proxy
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream_socket.settimeout(10)
        upstream_socket.connect((UPSTREAM_HOST, UPSTREAM_PORT))

        # Send CONNECT request with auth header
        connect_request = f"{connect_line}\r\n{auth_header}\r\n\r\n"
        upstream_socket.sendall(connect_request.encode('utf-8'))
        
        print("[DEBUG] Sent CONNECT request to upstream")

        # Read response from upstream
        response = upstream_socket.recv(8192)
        
        print(f"[DEBUG] Received CONNECT response: {response[:100]}")

        # Forward response to client
        client_socket.sendall(response)

        # Check if connection was successful (200)
        if b'200' in response:
            print("[DEBUG] CONNECT successful, starting tunnel")
            
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
            print("[ERROR] CONNECT failed")
            upstream_socket.close()
            client_socket.close()

    except Exception as e:
        print(f"[ERROR] Error handling HTTPS tunnel: {e}")
        import traceback
        traceback.print_exc()
        try:
            client_socket.close()
        except:
            pass

def start_proxy(username, password):
    """Start the proxy server"""
    auth_header = create_auth_header(username, password)

    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCAL_HOST, LOCAL_PORT))
    server_socket.listen(100)

    print(f"[INFO] Proxy listening on {LOCAL_HOST}:{LOCAL_PORT}")
    print(f"[INFO] Forwarding to {UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f"[INFO] Username: {username}")
    print(f"[INFO] Auth header: {auth_header}")
    print("[INFO] Press Ctrl+C to stop")

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n[INFO] Shutting down proxy...")
        server_socket.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"[DEBUG] Accepted connection from {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, auth_header))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down proxy...")
    finally:
        server_socket.close()

def main():
    """Main entry point"""
    if len(sys.argv) != 3:
        print("Usage: proxy_client.exe <username> <password>")
        print("Example: proxy_client.exe user_d99cfdfd NUqvdSuFzztEBPQC")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    start_proxy(username, password)

if __name__ == '__main__':
    main()

