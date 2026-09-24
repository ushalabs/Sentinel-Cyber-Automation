from __future__ import annotations

import time
import httpx

BASE_URL = "http://127.0.0.1:8000"
RUNNING_TIMEOUT = 20
OFFLINE_TIMEOUT = 25
POLL_INTERVAL = 2

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    print(f"[{'PASS' if condition else 'FAIL'}] {name}")
    if detail:
        print(f"       {detail}")
    if condition:
        passed += 1
    else:
        failed += 1


def get_status(client: httpx.Client) -> dict:
    response = client.get(BASE_URL + "/system/status")
    response.raise_for_status()
    return response.json()


def wait_for_collector(
    client: httpx.Client,
    wanted: str,
    timeout: int,
) -> tuple[bool, dict]:
    deadline = time.time() + timeout
    last = {}

    while time.time() < deadline:
        last = get_status(client)
        current = last.get("collector")

        print(
            f"       collector={current}",
            end="\r",
            flush=True,
        )

        if current == wanted:
            print(" " * 40, end="\r")
            return True, last

        time.sleep(POLL_INTERVAL)

    print(" " * 40, end="\r")
    return False, last


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 7")
    print("COLLECTOR DISCONNECT / RECONNECT VALIDATION")
    print("=" * 80)

    with httpx.Client(timeout=10.0) as client:
        try:
            initial = get_status(client)
        except Exception as exc:
            print(
                f"\nERROR: FastAPI is not reachable at {BASE_URL}: {exc}"
            )
            return 2

        check(
            "FastAPI/system-status preflight succeeds",
            initial.get("api") == "ONLINE",
            str(initial),
        )

        print(
            "\n1) Start the REAL Sentinel collector in a separate "
            "Administrator PowerShell."
        )
        print("   Use your normal command: python collector.py")
        input(
            "   After the collector starts and shows 'Listening for live traffic...', "
            "press ENTER here..."
        )

        running_ok, running_status = wait_for_collector(
            client,
            wanted="RUNNING",
            timeout=RUNNING_TIMEOUT,
        )

        check(
            "Collector heartbeat transitions status to RUNNING",
            running_ok,
            str(running_status),
        )

        print(
            "\n2) Stop the collector with Ctrl+C in its PowerShell window."
        )
        input(
            "   After it has fully stopped, press ENTER here..."
        )

        print(
            "   Waiting for the 15-second heartbeat freshness window to expire..."
        )

        offline_ok, offline_status = wait_for_collector(
            client,
            wanted="OFFLINE",
            timeout=OFFLINE_TIMEOUT,
        )

        check(
            "Collector status transitions to OFFLINE after heartbeat loss",
            offline_ok,
            str(offline_status),
        )

        print(
            "\n3) Restart the SAME collector in Administrator PowerShell."
        )
        input(
            "   After it starts again, press ENTER here..."
        )

        recovery_ok, recovery_status = wait_for_collector(
            client,
            wanted="RUNNING",
            timeout=RUNNING_TIMEOUT,
        )

        check(
            "Collector reconnects and returns to RUNNING without FastAPI restart",
            recovery_ok,
            str(recovery_status),
        )

        final_status = get_status(client)

        check(
            "Core services remain healthy after collector reconnect",
            (
                final_status.get("api") == "ONLINE"
                and final_status.get("database") == "ONLINE"
                and final_status.get("model") == "LOADED"
            ),
            str(final_status),
        )

    print("\n" + "=" * 80)
    print("STEP 7 RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    if failed == 0:
        print("STATUS : PASS")
        print(
            "\nSentinel correctly detected collector heartbeat loss and "
            "recovered when the collector reconnected, without restarting FastAPI."
        )
        return 0

    print("STATUS : CHECK FAILURES")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
