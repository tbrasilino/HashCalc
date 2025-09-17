# app.py - Python version using Pyodide

import hashlib
import time

def buffer_to_hex(buffer):
    return ''.join(f'{b:02x}' for b in buffer)

def run_benchmarks(file_data):
    results = []
    for algo_name, algo_func in [
        ('MD5', hashlib.md5),
        ('SHA-1', hashlib.sha1),
        ('SHA-256', hashlib.sha256),
        ('SHA-512', hashlib.sha512),
    ]:
        start = time.time()
        hash_obj = algo_func(file_data)
        hash_hex = hash_obj.hexdigest()
        end = time.time()
        results.append({
            'name': f'{algo_name} (Python)',
            'hash': hash_hex,
            'time': (end - start) * 1000  # ms
        })
    return results

# Pyodide will call this
def benchmark(file_bytes):
    return run_benchmarks(file_bytes)