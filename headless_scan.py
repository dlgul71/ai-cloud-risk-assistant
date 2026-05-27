from datetime import datetime
from scan_engine import run_scan
import time


def banner():

    print("\n" + "=" * 70)
    print("DGS SENTINEL AI - AUTONOMOUS HEADLESS SCANNER")
    print("=" * 70)

    print(f"Started: {datetime.utcnow()}")
    print("=" * 70 + "\n")


def main():

    banner()

    try:

        print("[+] Initializing scan engine...")
        time.sleep(1)

        run_scan()

        print("\n[+] Security scan completed successfully")

    except Exception as e:

        print(f"\n[ERROR] Scan failure: {e}")

    finally:

        print("\n" + "=" * 70)
        print("DGS SENTINEL AI HEADLESS MODE COMPLETE")
        print("=" * 70)


if __name__ == "__main__":
    main()
