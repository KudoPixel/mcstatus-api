#!/usr/bin/env python3
import sys
import socket
import json
import struct
import re
import subprocess
import time
import os
import threading
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Configuration & Global Thread Lock for Cache File Safety
CACHE_FILE = "cache.json"
cache_lock = threading.Lock()
CACHE_TTL = 0  # Default disabled (0 seconds)

def query_srv_record(domain):
    """Queries the SRV record using system nslookup to find custom ports."""
    srv_domain = f"_minecraft._tcp.{domain}"
    try:
        result = subprocess.run(
            ["nslookup", "-query=SRV", srv_domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if result.returncode == 0:
            output = result.stdout
            port_match = re.search(r'port\s*=\s*(\d+)', output, re.IGNORECASE)
            target_match = re.search(r'target\s*=\s*([a-zA-Z0-9.-]+)', output, re.IGNORECASE)
            
            if port_match and target_match:
                srv_host = target_match.group(1).rstrip('.')
                srv_port = int(port_match.group(1))
                return srv_host, srv_port
    except Exception:
        pass
    return domain, 25565

def write_varint(data):
    """Encodes an integer into a valid Minecraft VarInt byte sequence."""
    packed = b""
    data &= 0xFFFFFFFF
    while True:
        byte = data & 0x7F
        data >>= 7
        if data:
            packed += struct.pack("B", byte | 0x80)
        else:
            packed += struct.pack("B", byte)
            break
    return packed

def read_varint(sock):
    """Reads a single Minecraft VarInt from the network socket stream."""
    data = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Socket closed prematurely by the remote host.")
        b = byte[0]
        data |= (b & 0x7F) << (7 * i)
        if not (b & 0x80):
            return data
    raise ValueError("VarInt exceeds the maximum allowed 5-byte size sequence.")

def measure_exact_ping(host, port, samples=3, timeout=3):
    """Measures the standard Minecraft Ping/Pong latency over multiple samples."""
    latencies = []
    for _ in range(samples):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            hs_packet = write_varint(0x00) + write_varint(765) + write_varint(len(host.encode('utf-8'))) + host.encode('utf-8') + struct.pack(">H", port) + write_varint(1)
            sock.sendall(write_varint(len(hs_packet)) + hs_packet)
            
            status_packet = write_varint(0x00)
            sock.sendall(write_varint(len(status_packet)) + status_packet)
            
            total_len = read_varint(sock)
            packet_id = read_varint(sock)
            json_len = read_varint(sock)
            
            remaining = json_len
            while remaining > 0:
                chunk = sock.recv(min(remaining, 8192))
                if not chunk:
                    break
                remaining -= len(chunk)
            
            timestamp_payload = struct.pack(">Q", int(time.time() * 1000))
            ping_packet = write_varint(0x01) + timestamp_payload
            
            start_time = time.perf_counter()
            sock.sendall(write_varint(len(ping_packet)) + ping_packet)
            
            pong_len = read_varint(sock)
            pong_packet_id = read_varint(sock)
            sock.recv(8)
            end_time = time.perf_counter()
            
            if pong_packet_id == 0x01:
                latencies.append((end_time - start_time) * 1000)
                
            sock.close()
            time.sleep(0.05)
        except Exception:
            continue

    if not latencies:
        return None
    return round(sum(latencies) / len(latencies), 1)

def get_minecraft_status(host, port, timeout=4):
    """Fetches the raw JSON state from the Minecraft server."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return {"error": f"Connection failed: {e}"}

    try:
        hs_packet = write_varint(0x00) + write_varint(765) + write_varint(len(host.encode('utf-8'))) + host.encode('utf-8') + struct.pack(">H", port) + write_varint(1)
        sock.sendall(write_varint(len(hs_packet)) + hs_packet)

        status_packet = write_varint(0x00)
        sock.sendall(write_varint(len(status_packet)) + status_packet)

        total_len = read_varint(sock)
        packet_id = read_varint(sock)
        json_len = read_varint(sock)
        
        json_data = b""
        while len(json_data) < json_len:
            chunk = sock.recv(min(json_len - len(json_data), 8192))
            if not chunk:
                break
            json_data += chunk

        return json.loads(json_data.decode('utf-8'))
    except Exception as e:
        return {"error": f"Parsing failed: {e}"}
    finally:
        sock.close()

def get_cached_response(address):
    """Retrieves valid data from the JSON cache file if it has not expired."""
    if CACHE_TTL <= 0:
        return None
        
    with cache_lock:
        if not os.path.exists(CACHE_FILE):
            return None
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
                
            if address in cache_data:
                record = cache_data[address]
                # Check if the elapsed time is within the allowed TTL window
                if time.time() - record["timestamp"] < CACHE_TTL:
                    payload = record["payload"]
                    payload["meta"]["cached"] = True  # Inject cache flag dynamically
                    return payload
        except Exception:
            pass
    return None

def save_to_cache(address, payload):
    """Saves the API payload with a current timestamp to the local JSON file."""
    if CACHE_TTL <= 0:
        return
        
    with cache_lock:
        cache_data = {}
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
            except Exception:
                cache_data = {}
                
        cache_data[address] = {
            "timestamp": time.time(),
            "payload": payload
        }
        
        try:
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=4, ensure_ascii=False)
        except Exception:
            pass

def parse_target(target_str):
    if ":" in target_str:
        host, port_str = target_str.rsplit(":", 1)
        try:
            return host, int(port_str), False
        except ValueError:
            return target_str, 25565, True
    return target_str, 25565, True

def parse_motd(motd_raw):
    if isinstance(motd_raw, dict):
        text = motd_raw.get("text", "")
        if "extra" in motd_raw:
            for part in motd_raw["extra"]:
                text += parse_motd(part)
        return text
    return str(motd_raw)

class MinecraftRESTHandler(BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        sys.stdout.write(f"[API LOG] - {self.address_string()} - {format%args}\n")

    def do_GET(self):
        parsed_url = urlparse(self.path)
        
        if parsed_url.path == '/api/v1/status':
            query_params = parse_qs(parsed_url.query)
            address_param = query_params.get('address', [None])[0]
            
            if not address_param:
                self.send_json_response(400, {"status": "error", "message": "Missing address parameter"})
                return

            # --- 1. Check Cache Storage First ---
            cached_payload = get_cached_response(address_param)
            if cached_payload:
                self.send_json_response(200, cached_payload)
                return

            # --- 2. Live Query (Cache Miss or Expired) ---
            host, port, check_srv = parse_target(address_param)
            
            if check_srv:
                resolved_host, resolved_port = query_srv_record(host)
                if resolved_port != 25565 or resolved_host != host:
                    host, port = resolved_host, resolved_port

            avg_ping = measure_exact_ping(host, port, samples=3)
            raw_response = get_minecraft_status(host, port)
            
            if "error" in raw_response:
                self.send_json_response(502, {
                    "status": "error",
                    "queried_address": address_param,
                    "details": raw_response["error"]
                })
                return

            motd_clean = re.sub(r'§[0-9a-fk-orxX]', '', parse_motd(raw_response.get("description", ""))).strip()

            api_payload = {
                "status": "success",
                "meta": {
                    "queried_address": address_param,
                    "resolved_host": host,
                    "resolved_port": port,
                    "cached": False
                },
                "summary": {
                    "version": raw_response.get("version", {}).get("name", "Unknown"),
                    "protocol": raw_response.get("version", {}).get("protocol", "Unknown"),
                    "players_online": raw_response.get("players", {}).get("online", 0),
                    "players_max": raw_response.get("players", {}).get("max", 0),
                    "ping_ms": avg_ping if avg_ping is not None else "Timeout",
                    "motd": motd_clean
                },
                "raw": raw_response
            }
            
            # Save the fresh data into our JSON cache file
            save_to_cache(address_param, api_payload)
            self.send_json_response(200, api_payload)
        else:
            self.send_json_response(404, {"status": "error", "message": "Route not found"})

    def send_json_response(self, status_code, payload):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=4, ensure_ascii=False).encode('utf-8'))

def main():
    global CACHE_TTL
    
    # Setting up standard argument parsing for CLI switches
    parser = argparse.ArgumentParser(description="Minecraft REST API Server with High-fidelity Sampling and Storage Caching.")
    parser.add_argument(
        '-c', '--cache', 
        type=int, 
        default=0, 
        help="Enable JSON file caching and set validity duration time-to-live (TTL) in seconds. Set to 0 to disable."
    )
    
    args = parser.parse_args()
    CACHE_TTL = args.cache

    server = ThreadingHTTPServer(("0.0.0.0", 7676), MinecraftRESTHandler)
    
    print(f"[SUCCESS] Production API running on port 7676.")
    if CACHE_TTL > 0:
        print(f"[CACHE CONFIG] Smart caching is ENABLED. TTL: {CACHE_TTL} seconds. Storing data in '{CACHE_FILE}'")
    else:
        print("[CACHE CONFIG] Caching is DISABLED (Real-time network pooling active).")
        
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == "__main__":
    main()

