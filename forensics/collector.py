import hashlib
import os
from datetime import datetime
from playwright.sync_api import sync_playwright

class EvidenceCollector:
    def __init__(self):
        """Initializes the EvidenceCollector and ensures directory structure exists."""
        self.screenshot_dir = "forensics/evidence/screenshots"
        self.html_dir = "forensics/evidence/html"
        os.makedirs(self.screenshot_dir, exist_ok=True)
        os.makedirs(self.html_dir, exist_ok=True)

    def generate_hash(self, file_path: str) -> str:
        """
        Calculates the SHA-256 hash of a file and saves it in a .hash file.
        Returns the hex digest.
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        hex_digest = sha256_hash.hexdigest()
        
        # Save the hash string in a .hash file alongside the target file
        with open(f"{file_path}.hash", "w") as hash_file:
            hash_file.write(hex_digest)
            
        return hex_digest

    def collect_evidence(self, domain: str):
        """
        Uses Playwright to capture a screenshot and HTML dump of the target domain.
        Includes timestamped filenames and Chain of Custody hashing.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_filename = f"{domain.replace('*', 'wildcard')}_{timestamp}.png"
        html_filename = f"{domain.replace('*', 'wildcard')}_{timestamp}.html"
        
        screenshot_path = os.path.join(self.screenshot_dir, screenshot_filename)
        html_path = os.path.join(self.html_dir, html_filename)

        print(f"[*] Forensics: Collecting evidence for {domain}...")

        try:
            with sync_playwright() as p:
                # Launching Chromium in headless mode
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                # Prepend http:// if not present (CertStream provides domains)
                url = f"http://{domain}" if not domain.startswith("http") else domain
                
                # Navigate with a timeout
                page.goto(url, timeout=30000)
                
                # Wait for some network activity to settle
                page.wait_for_load_state("networkidle")

                # Capture Screenshot
                page.screenshot(path=screenshot_path)
                self.generate_hash(screenshot_path)

                # Capture HTML
                html_content = page.content()
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                self.generate_hash(html_path)

                browser.close()
                print(f"[+] Forensics: Evidence captured for {domain}. (Hash: {os.path.basename(screenshot_path)}.hash)")
        
        except Exception as e:
            print(f"[!] Forensics: Error collecting evidence for {domain}: {str(e)}")

if __name__ == "__main__":
    # Quick standalone test
    collector = EvidenceCollector()
    collector.collect_evidence("example.com")
