import os
import sys
import certstream
import logging
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

# Ensure project root is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensics.collector import EvidenceCollector

# Target Keywords for filtering
TARGET_KEYWORDS = ["microsoft", "google", "binance", "netflix"]

# Initialize Forensics Collector and ThreadPoolExecutor
collector = EvidenceCollector()
executor = ThreadPoolExecutor(max_workers=5)

def print_callback(message: Dict[str, Any], context: Any) -> None:
    """
    Callback function that processes certificates from CertStream.
    Filters for target keywords and triggers asynchronous forensics collection.
    """
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        issuer = message['data']['leaf_cert']['issuer']['O']

        for domain in all_domains:
            if any(keyword in domain.lower() for keyword in TARGET_KEYWORDS):
                # Remove wildcard prefix for browser compatibility
                clean_domain = domain.lstrip("*.")
                print(f"[+] Match Found: {domain} | Issuer: {issuer}")
                
                # Submit to ThreadPool to avoid blocking the listener stream
                executor.submit(collector.collect_evidence, clean_domain)

def start_monitor():
    """Starts the CertStream listener."""
    print("[*] Hydra-Mapper: Starting CertStream Monitoring...")
    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
    certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')

if __name__ == "__main__":
    try:
        start_monitor()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Hydra-Mapper...")
        executor.shutdown(wait=False)
