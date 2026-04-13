import certstream
import logging
from typing import Dict, Any

# Target Keywords for filtering
TARGET_KEYWORDS = ["microsoft", "google", "binance", "netflix"]

def print_callback(message: Dict[str, Any], context: Any) -> None:
    """
    Callback function that processes certificates from CertStream.
    Filters for target keywords and prints domain and issuer.
    """
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        issuer = message['data']['leaf_cert']['issuer']['O']

        for domain in all_domains:
            if any(keyword in domain.lower() for keyword in TARGET_KEYWORDS):
                print(f"[+] Match Found: {domain} | Issuer: {issuer}")
                # Future: Trigger evidence collection in forensics/ module

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
