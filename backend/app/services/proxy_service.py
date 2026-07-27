import asyncio
import socket
import json
import logging
import uuid
import ssl
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable
from app.services.ca_service import ca_service
from app.config import settings


logger = logging.getLogger("shadow_spike.proxy")

class ProxyServer:
    """
    A lightweight asynchronous HTTP/HTTPS Proxy server that captures traffic.
    Currently supports:
    - HTTP Request/Response logging
    - HTTPS (via CONNECT) relaying (logging metadata only, not encrypted content yet)
    - Request Interception (Pause & Modify)
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8888, on_capture: Optional[Callable] = None, on_intercept: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_capture = on_capture
        self.on_intercept = on_intercept
        self._server: Optional[asyncio.Server] = None
        self._running = False

    async def start(self):
        if self._running:
            return
        
        try:
            self._server = await asyncio.start_server(self.handle_client, self.host, self.port)
            self._running = True
            logger.info(f"Proxy started on {self.host}:{self.port}")
            async with self._server:
                await self._server.serve_forever()
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            self._running = False

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._running = False
            logger.info("Proxy stopped")

    async def handle_client(self, client_reader, client_writer):
        try:
            # Read initial request line and headers
            header_data = await client_reader.read(16384)
            if not header_data:
                client_writer.close()
                return

            print(f"[PROXY] New connection, data length: {len(header_data)}")

            # Basic parsing of the first line
            lines = header_data.split(b'\r\n')
            if not lines:
                client_writer.close()
                return
            
            request_line = lines[0].decode('utf-8', errors='ignore')
            parts = request_line.split(' ')
            if len(parts) < 3:
                client_writer.close()
                return
            
            method, url, version = parts
            
            # Extract headers
            headers = {}
            for line in lines[1:]:
                if not line: break
                try:
                    k, v = line.decode('utf-8', errors='ignore').split(': ', 1)
                    headers[k] = v
                except:
                    continue

            # Identify if this is Shadow Spike's own backend traffic
            # URL might be full or relative
            host_header = headers.get('Host', '')
            is_own_backend = (
                'localhost:8000' in host_header
                or '127.0.0.1:8000' in host_header
                or (settings.BACKEND_HOST and settings.BACKEND_HOST in host_header)
            )

            if is_own_backend:
                print(f"[PROXY] Bypassing own backend: {url}")
                await self.handle_bypass(client_reader, client_writer, host_header, header_data)
                return

            # Handle HTTPS Tunneling (CONNECT)
            print(f"[PROXY] Request: {method} {url}")
            if method.upper() == 'CONNECT':
                await self.handle_connect(client_reader, client_writer, url, header_data, headers)
            else:
                await self.handle_http(client_reader, client_writer, method, url, header_data, headers)

        except Exception as e:
            logger.error(f"Error handling client: {e}")
            client_writer.close()

    async def handle_connect(self, client_reader, client_writer, target_host_port, header_data, headers):
        """Handle HTTPS CONNECT requests - Upgrading to MITM decrypted stream."""
        try:
            # target_host_port is like "google.com:443"
            host = target_host_port.split(':')[0]
            port = int(target_host_port.split(':')[1]) if ':' in target_host_port else 443

            if self.on_capture:
                print(f"[PROXY] MITM Attempt for {target_host_port}")
                await self.on_capture({
                    "method": "CONNECT",
                    "url": target_host_port,
                    "host": host,
                    "request_headers": json.dumps(headers)
                })

            # 1. Send 200 Connection Established (Plaintext)
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            # 2. Dynamic Certificate Generation
            cert_path, key_path = await ca_service.generate_site_cert(host)
            
            # 3. Create SSL Context for Client
            client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            client_context.load_cert_chain(cert_path, key_path)
            
            # 4. Perform TLS Handshake with Client
            try:
                loop = asyncio.get_event_loop()
                # Use wait_for to prevent hanging on handshake failures
                new_client_reader, new_client_writer = await asyncio.wait_for(
                    self._upgrade_to_ssl(client_reader, client_writer, client_context, server_side=True),
                    timeout=5.0
                )
            except Exception as e:
                print(f"[PROXY] TLS Handshake failed with client {host}: {e}")
                client_writer.close()
                return

            # 5. Read the Decrypted request from the new stream
            # We recursively call handle_client or handle_http logic here
            # But we need to handle it in a loop because one CONNECT can have multiple HTTP requests (HTTP/1.1)
            await self.handle_decrypted_stream(new_client_reader, new_client_writer, host, port)

        except Exception as e:
            logger.debug(f"MITM error for {target_host_port}: {e}")
            client_writer.close()

    async def _upgrade_to_ssl(self, reader, writer, ssl_context, server_side=True, server_hostname=None):
        """Helper to upgrade a raw stream to SSL/TLS."""
        transport = writer.transport
        protocol = transport.get_protocol()
        
        # This is a bit low-level but necessary for asyncio MITM
        loop = asyncio.get_event_loop()
        new_transport = await loop.start_tls(
            transport, protocol, ssl_context,
            server_side=server_side,
            server_hostname=server_hostname
        )
        
        # Create new reader/writer
        new_reader = asyncio.StreamReader()
        new_protocol = asyncio.StreamReaderProtocol(new_reader)
        new_transport.set_protocol(new_protocol)
        new_writer = asyncio.StreamWriter(new_transport, new_protocol, new_reader, loop)
        
        return new_reader, new_writer

    async def handle_decrypted_stream(self, reader, writer, host, port):
        """Processes a decrypted HTTPS stream just like standard HTTP."""
        try:
            while not reader.at_eof():
                # Read next decrypted request
                header_data = await reader.read(16384)
                if not header_data: break
                
                # Basic parsing
                lines = header_data.split(b'\r\n')
                if not lines: break
                
                request_line = lines[0].decode('utf-8', errors='ignore')
                parts = request_line.split(' ')
                if len(parts) < 3: break
                method, path, version = parts
                
                # Extract headers for this sub-request
                headers = {}
                for line in lines[1:]:
                    if not line: break
                    try:
                        k, v = line.decode('utf-8', errors='ignore').split(': ', 1)
                        headers[k] = v
                    except: continue

                # Reconstruct full URL for storage (decrypted HTTPS)
                full_url = f"https://{host}{path}"
                
                # Now handle it like a standard HTTP request
                # We need a special forwarder that uses SSL for the remote side
                await self.handle_http(reader, writer, method, full_url, header_data, headers, is_https=True, target_host=host, target_port=port)
                
        except Exception as e:
            print(f"[PROXY] Decrypted stream error: {e}")
        finally:
            writer.close()

    async def handle_http(self, client_reader, client_writer, method, url, header_data, headers, is_https=False, target_host=None, target_port=None):
        """Handle standard HTTP requests - capture and forward."""
        try:
            # Parse Host and Path from URL
            if not target_host:
                if url.startswith('http'):
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    target_host = parsed.hostname
                    target_port = parsed.port or (443 if is_https else 80)
                else:
                    target_host = headers.get('Host', '').split(':')[0]
                    target_port = 80
                    if ':' in headers.get('Host', ''):
                        target_port = int(headers.get('Host', '').split(':')[1])

            if not target_host:
                client_writer.close()
                return

            # Identify if this is Shadow Spike's own backend traffic
            host_header = headers.get('Host', '')
            is_own_backend = (
                'localhost:8000' in host_header
                or '127.0.0.1:8000' in host_header
                or (settings.BACKEND_HOST and settings.BACKEND_HOST in host_header)
            )

            if is_own_backend:
                print(f"[PROXY] Bypassing own backend: {url}")
                await self.handle_bypass(client_reader, client_writer, host_header, header_data)
                return

            # Check for Interception
            if proxy_manager.intercept_enabled and self.on_intercept:
                request_id = str(uuid.uuid4())
                intercept_info = {
                    "id": request_id,
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": header_data.split(b'\r\n\r\n', 1)[1].decode('utf-8', errors='ignore') if b'\r\n\r\n' in header_data else ""
                }
                
                # Signal UI
                await self.on_intercept(intercept_info)
                
                # Wait for user decision
                event = asyncio.Event()
                proxy_manager.intercepted_requests[request_id] = {"event": event, "action": "forward", "new_data": None}
                
                try:
                    await asyncio.wait_for(event.wait(), timeout=60.0) # 1 min timeout
                except asyncio.TimeoutError:
                    proxy_manager.intercepted_requests[request_id]["action"] = "drop"
                
                decision = proxy_manager.intercepted_requests.pop(request_id)
                if decision["action"] == "drop":
                    client_writer.close()
                    return
                
                # Update data if modified
                if decision["new_data"]:
                    header_data = self._normalize_modified_request(decision["new_data"])

            # --- FORWARD TO REMOTE ---
            if is_https:
                remote_context = ssl.create_default_context()
                # Important: for MITM we often need to ignore certificate validation errors for the backend
                # but better to trust the real world. Let's stick with default first.
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port, ssl=remote_context)
            else:
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
            
            # Send initial data (headers + first chunk of body)
            remote_writer.write(header_data)
            await remote_writer.drain()

            # For standard HTTP, we relay bidirectional in parallel to avoid deadlocks (POST bodies)
            async def relay_request():
                try:
                    while not client_reader.at_eof():
                        chunk = await client_reader.read(8192)
                        if not chunk: break
                        remote_writer.write(chunk)
                        await remote_writer.drain()
                except: pass
                finally: remote_writer.close()

            async def relay_response():
                first_chunk_read = False
                try:
                    while not remote_reader.at_eof():
                        chunk = await remote_reader.read(8192)
                        if not chunk: break
                        
                        if not first_chunk_read:
                            # Log the response metadata from the first chunk
                            if self.on_capture:
                                await self.on_capture({
                                    "method": method,
                                    "url": url,
                                    "host": target_host,
                                    "request_headers": json.dumps(headers),
                                    "status_code": self.parse_status_code(chunk)
                                })
                            first_chunk_read = True
                            
                        client_writer.write(chunk)
                        await client_writer.drain()
                except: pass
                finally: client_writer.close()

            await asyncio.gather(relay_request(), relay_response())

        except Exception as e:
            logger.debug(f"HTTP error for {url}: {e}")
            client_writer.close()

    async def handle_bypass(self, client_reader, client_writer, host_header, header_data):
        """Pure bypass for self-backend traffic to avoid any proxy overhead/deadlock."""
        try:
            target_host = '127.0.0.1'
            target_port = 8000
            
            remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
            remote_writer.write(header_data)
            await remote_writer.drain()
            
            await asyncio.gather(
                self.relay(client_reader, remote_writer),
                self.relay(remote_reader, client_writer)
            )
        except:
            client_writer.close()

    async def relay(self, reader, writer):
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except:
            pass
        finally:
            writer.close()

    def _normalize_modified_request(self, raw_text: str) -> bytes:
        """
        Normalize a modified HTTP request from the UI:
        1. Convert bare \n to \r\n (textarea sends LF, HTTP requires CRLF)
        2. Recalculate Content-Length based on actual body size
        """
        # Step 1: Normalize line endings — replace \r\n with \n first, then convert all \n to \r\n
        normalized = raw_text.replace('\r\n', '\n').replace('\r', '\n')
        
        # Step 2: Split headers and body on \n\n
        if '\n\n' in normalized:
            header_part, body_part = normalized.split('\n\n', 1)
        else:
            header_part = normalized
            body_part = ''
        
        # Step 3: Recalculate Content-Length
        body_bytes = body_part.encode('utf-8')
        header_lines = header_part.split('\n')
        new_header_lines = []
        for line in header_lines:
            if line.lower().startswith('content-length:'):
                new_header_lines.append(f'Content-Length: {len(body_bytes)}')
            else:
                new_header_lines.append(line)
        
        # Step 4: Rejoin with proper CRLF
        final_headers = '\r\n'.join(new_header_lines)
        final_request = final_headers + '\r\n\r\n' + body_part
        return final_request.encode('utf-8')

    def parse_status_code(self, response_data: bytes) -> Optional[int]:
        try:
            line = response_data.split(b'\r\n')[0].decode('utf-8')
            return int(line.split(' ')[1])
        except:
            return None

# Singleton manager
class ProxyManager:
    _instance = None
    
    def __init__(self):
        self.active_proxy: Optional[ProxyServer] = None
        self.stop_event = asyncio.Event()
        self.intercept_enabled = False
        self.intercepted_requests = {} # id -> {event, action, new_data}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ProxyManager()
        return cls._instance

    async def start_proxy(self, user_id: str, on_capture: Callable, on_intercept: Callable):
        if self.active_proxy:
            await self.stop_proxy()
        
        self.active_proxy = ProxyServer(on_capture=on_capture, on_intercept=on_intercept)
        # Run in background
        task = asyncio.create_task(self.active_proxy.start())
        # Give it a moment to bind and check if it failed
        await asyncio.sleep(0.5)
        if not self.active_proxy._running:
            self.active_proxy = None
            raise Exception("Port 8888 is busy or proxy failed to start. Try stopping Oracle or changing the port.")
        return True

    async def stop_proxy(self):
        if self.active_proxy:
            await self.active_proxy.stop()
            self.active_proxy = None
        return True

    async def release_request(self, request_id: str, action: str, new_data: Optional[str] = None):
        if request_id in self.intercepted_requests:
            req = self.intercepted_requests[request_id]
            req["action"] = action
            req["new_data"] = new_data
            req["event"].set()
            return True
        return False

    async def clear_pending_intercepts(self):
        """Drop all pending intercepted requests immediately."""
        ids = list(self.intercepted_requests.keys())
        for request_id in ids:
            req = self.intercepted_requests.get(request_id)
            if req:
                req["action"] = "drop"
                req["event"].set()
        self.intercepted_requests.clear()
        logger.info(f"[Proxy] Cleared {len(ids)} pending intercepts.")
        return len(ids)

proxy_manager = ProxyManager.get_instance()
