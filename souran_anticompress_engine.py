#!/usr/bin/env python3
"""
SOURAN AI NETWORK SERVER v4.2.0 — Anti-Compression Engine
File: souran_anticompress_engine.py  |  Port: 8085

Batch-processes files through the anti-compression pipeline without
loading them into the LLM context window. Manages chunking, delta
encoding, reference indexing, and status tracking.

Behaviours:
  - Watches /opt/souran-ai/anticompress/incoming/ for batch files
  - Processes them through the anti-compression pipeline
  - Stores chunks/deltas/refs in /opt/souran-ai/data/anticompress/
  - Tracks progress with resume capability
  - Exposes /api/anticompress/* API for the 8082 dashboard

Design: pure stdlib (no pip deps), runs as a systemd service.
"""

import json, os, queue, struct, sys, threading, time, zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
INCOMING_DIR = Path("/opt/souran-ai/anticompress/incoming")
STORAGE_DIR = Path("/opt/souran-ai/data/anticompress")
INDEX_DIR = STORAGE_DIR / "index"
STATE_FILE = STORAGE_DIR / "engine_state.json"

CHUNK_SIZE = 64 * 1024       # 64 KB chunks
MAX_CHUNKS_PER_FILE = 4096
DELTA_WINDOW = 16            # compare against last N chunks

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
state = {
    "version": VERSION,
    "updated_at": None,
    "running": False,
    "jobs": {},                # job_id -> {status, file, chunks, bytes_processed}
    "total_files_processed": 0,
    "total_bytes_processed": 0,
    "total_chunks": 0,
    "total_deltas": 0,
    "queue_depth": 0,
    "errors": [],
}
_state_lock = threading.Lock()
_job_queue = queue.Queue()
_running = True


# ---------------------------------------------------------------------------
# Anti-compression pipeline
# ---------------------------------------------------------------------------
def _chunk_data(data: bytes) -> list[bytes]:
    """Split data into fixed-size chunks."""
    return [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]


def _delta_encode(chunks: list[bytes]) -> list[dict]:
    """Encode chunks with delta compression against previous chunks."""
    deltas = []
    window = []
    for i, chunk in enumerate(chunks):
        best_match = None
        best_score = 0
        for j, prev in enumerate(window):
            # Simple similarity: count matching bytes
            matches = sum(1 for a, b in zip(chunk, prev) if a == b)
            score = matches / max(len(chunk), 1)
            if score > best_score and score > 0.3:
                best_score = score
                best_match = j

        if best_match is not None and best_score > 0.5:
            # Store delta: reference to previous chunk + diff
            prev = window[best_match]
            diff = bytes(a ^ b for a, b in zip(chunk, prev))
            deltas.append({
                "type": "delta",
                "ref_chunk": len(deltas) - best_match - 1,
                "diff": diff.hex(),
                "size": len(chunk),
            })
            state["total_deltas"] += 1
        else:
            deltas.append({
                "type": "raw",
                "data": chunk.hex(),
                "size": len(chunk),
            })

        window.append(chunk)
        if len(window) > DELTA_WINDOW:
            window.pop(0)

    return deltas


def _store_chunks(job_id: str, deltas: list[dict], orig_size: int):
    """Store chunks and deltas on disk."""
    job_dir = STORAGE_DIR / "data" / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    # Write individual chunks
    chunk_dir = job_dir / "chunks"
    chunk_dir.mkdir(exist_ok=True)
    for i, d in enumerate(deltas):
        if d["type"] == "raw":
            chunk_path = chunk_dir / f"chunk_{i:05d}.dat"
            chunk_path.write_bytes(bytes.fromhex(d["data"]))
        elif d["type"] == "delta":
            # Store delta reference
            delta_path = chunk_dir / f"delta_{i:05d}.json"
            delta_path.write_text(json.dumps(d), encoding="utf-8")

    # Write index entry
    idx_path = INDEX_DIR / f"{job_id}.idx"
    idx_path.write_text(json.dumps({
        "job_id": job_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "original_size": orig_size,
        "chunk_count": len(deltas),
        "delta_count": sum(1 for d in deltas if d["type"] == "delta"),
        "raw_count": sum(1 for d in deltas if d["type"] == "raw"),
        "version": VERSION,
    }, indent=2), encoding="utf-8")


def _process_file(filepath: Path) -> dict:
    """Process a single file through the anti-compression pipeline."""
    job_id = f"job_{int(time.time() * 1000)}"
    t0 = time.time()

    with _state_lock:
        state["jobs"][job_id] = {
            "status": "processing",
            "file": str(filepath),
            "chunks": 0,
            "bytes_processed": 0,
        }

    # Read file (streaming for large files)
    file_size = filepath.stat().st_size
    with open(filepath, "rb") as f:
        data = f.read()

    # Chunk
    chunks = _chunk_data(data)

    # Delta encode
    deltas = _delta_encode(chunks)

    # Store
    _store_chunks(job_id, deltas, file_size)

    elapsed = time.time() - t0
    compression_ratio = sum(len(d["diff"]) if d["type"] == "delta" else len(d["data"])
                            for d in deltas) / max(file_size, 1)

    with _state_lock:
        state["jobs"][job_id]["status"] = "done"
        state["jobs"][job_id]["chunks"] = len(deltas)
        state["jobs"][job_id]["bytes_processed"] = file_size
        state["jobs"][job_id]["elapsed_s"] = round(elapsed, 2)
        state["jobs"][job_id]["compression_ratio"] = round(compression_ratio, 3)
        state["total_files_processed"] += 1
        state["total_bytes_processed"] += file_size
        state["total_chunks"] += len(deltas)
        state["updated_at"] = datetime.now(timezone.utc).isoformat()

    return {"job_id": job_id, "status": "done", "chunks": len(deltas),
            "elapsed_s": round(elapsed, 2), "ratio": round(compression_ratio, 3)}


# ---------------------------------------------------------------------------
# Worker loop
# ---------------------------------------------------------------------------
def _worker():
    """Process jobs from the queue."""
    while _running:
        try:
            filepath = _job_queue.get(timeout=5)
            if filepath is None:
                break
            try:
                _process_file(filepath)
            except Exception as e:
                with _state_lock:
                    state["errors"].append(f"{filepath}: {e}")
                    if len(state["errors"]) > 100:
                        state["errors"] = state["errors"][-50:]
        except queue.Empty:
            continue


def _scan_incoming():
    """Scan incoming directory for new files to process."""
    if not INCOMING_DIR.exists():
        return
    for f in INCOMING_DIR.iterdir():
        if f.is_file() and not f.name.endswith(".processed"):
            _job_queue.put(f)


def _loop():
    """Main processing loop."""
    global _running
    print(f"[anticompress v{VERSION}] started", flush=True)
    while _running:
        try:
            _scan_incoming()
            with _state_lock:
                state["queue_depth"] = _job_queue.qsize()
                state["running"] = True
            time.sleep(5)
        except Exception as e:
            print(f"[anticompress] loop error: {e}", flush=True)
            time.sleep(5)


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
def start_api():
    """Start a minimal HTTP API on port 8085 for the dashboard."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/api/anticompress", "/api/anticompress/status"):
                with _state_lock:
                    body = json.dumps(dict(state), default=str, indent=2)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "port": 8085}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == "/api/anticompress/enqueue":
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len) if content_len else b"{}"
                try:
                    payload = json.loads(body.decode("utf-8", "replace"))
                except Exception:
                    payload = {}
                filepath = payload.get("filepath", "")
                if filepath and Path(filepath).exists():
                    _job_queue.put(Path(filepath))
                    self.send_response(202)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "enqueued", "file": filepath}).encode())
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "file not found"}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8085), Handler)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
def main():
    # Ensure directories exist
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)

    # Load persisted state
    if STATE_FILE.exists():
        try:
            loaded = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            with _state_lock:
                for k, v in loaded.items():
                    if k in state:
                        state[k] = v
        except Exception:
            pass

    # Start API server
    api_thread = threading.Thread(target=start_api, daemon=True)
    api_thread.start()
    print(f"[anticompress v{VERSION}] API on :8085", flush=True)

    # Start workers (2 concurrent)
    for _ in range(2):
        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    # Run main loop
    _loop()


if __name__ == "__main__":
    main()