from datetime import datetime, UTC
import time

from scan_engine import run_scan


def banner():
    print("\n" + "=" * 70)
    print("DGS SENTINEL AI - AUTONOMOUS HEADLESS SCANNER")
    print("=" * 70)
    print(f"Started: {datetime.now(UTC)}")
    print("=" * 70 + "\n")


def main():
    banner()

    try:
        print("[+] Initializing scan engine...")
        time.sleep(1)
        run_scan()
        print("\n[+] Security scan completed successfully")
        return 0
    except Exception as e:
        print(f"\n[ERROR] Scan failure: {e}")
        return 1
    finally:
        print("\n" + "=" * 70)
        print("DGS SENTINEL AI HEADLESS MODE COMPLETE")
        print("=" * 70)


if __name__ == "__main__":
    raise SystemExit(main())
