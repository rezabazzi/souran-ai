#!/usr/bin/env python3
"""Anti-Compression Engine - Batch process files without loading into context"""

import os, sys, hashlib, json
from pathlib import Path

class AntiCompressEngine:
    def __init__(self, work_dir="/opt/souran-ai/data"):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True)
        self.processed = set()
    
    def hash_file(self, filepath):
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def process_file(self, filepath, operation="extract"):
        path = Path(filepath)
        if not path.exists():
            return {"error": "File not found", "file": str(filepath)}
        file_hash = self.hash_file(path)
        if file_hash in self.processed:
            return {"status": "already_processed", "file": str(filepath)}
        result = {"file": str(filepath), "size": path.stat().st_size, "hash": file_hash, "operation": operation, "status": "completed"}
        if operation == "extract":
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()
                result["lines"] = len(lines)
                result["first_line"] = lines[0].strip()[:100] if lines else ""
        self.processed.add(file_hash)
        return result
    
    def batch_process(self, directory, pattern="*.txt"):
        results = []
        path = Path(directory)
        if not path.exists():
            return {"error": "Directory not found"}
        for file in path.glob(pattern):
            results.append(self.process_file(file, "extract"))
        return {"processed": len(results), "results": results}
    
    def save_state(self, state_file="/opt/souran-ai/data/processed_state.json"):
        with open(state_file, 'w') as f:
            json.dump({"processed_hashes": list(self.processed)}, f, indent=2)

def main():
    engine = AntiCompressEngine()
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isfile(target):
            print(json.dumps(engine.process_file(target), indent=2))
        elif os.path.isdir(target):
            print(json.dumps(engine.batch_process(target), indent=2))
    else:
        print(json.dumps(engine.batch_process("/opt/souran-ai/data"), indent=2))
    engine.save_state()

if __name__ == '__main__':
    main()
