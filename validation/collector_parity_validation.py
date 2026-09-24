from __future__ import annotations

import importlib.util
import json
import math
import statistics
import sys
from pathlib import Path

import joblib
from scapy.all import IP, TCP, UDP, Raw


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "collector" / "collector.py"
FEATURES_PATH = (
    ROOT / "ML Models" / "XGBoost" / "sentinel_feature_columns_v1.joblib"
)

RESULTS_DIR = ROOT / "validation" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORT_PATH = RESULTS_DIR / "phase10_step3_collector_parity_report.json"

ABS_TOL = 1e-6
REL_TOL = 1e-9

passed = 0
failed = 0
checks: list[dict] = []


def load_collector():
    spec = importlib.util.spec_from_file_location(
        "sentinel_collector_phase10",
        COLLECTOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load collector.py")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def record_check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed

    print(f"[{'PASS' if condition else 'FAIL'}] {name}")
    if detail:
        print(f"       {detail}")

    checks.append(
        {
            "name": name,
            "passed": bool(condition),
            "detail": detail,
        }
    )

    if condition:
        passed += 1
    else:
        failed += 1


def close(a: float, b: float) -> bool:
    return math.isclose(
        float(a),
        float(b),
        rel_tol=REL_TOL,
        abs_tol=ABS_TOL,
    )


def expected_fixture_features() -> dict[str, float]:
    # Independent reference calculation for the deterministic fixture below.
    #
    # Records:
    # 0.0s FWD payload=0   SYN
    # 0.1s FWD payload=100 ACK+PSH
    # 0.2s BWD payload=50  ACK
    # 0.3s FWD payload=200 ACK+PSH
    # 6.5s BWD payload=0   ACK
    # 6.6s BWD payload=25  FIN+ACK
    #
    # Historical CICFlowMeter packet-length quirk:
    # first packet payload appears twice in flow-length stats.
    fwd_lengths = [0.0, 100.0, 200.0]
    bwd_lengths = [50.0, 0.0, 25.0]
    flow_lengths = [0.0, 0.0, 100.0, 50.0, 200.0, 0.0, 25.0]

    flow_iats = [
        100_000.0,
        100_000.0,
        100_000.0,
        6_200_000.0,
        100_000.0,
    ]
    fwd_iats = [100_000.0, 200_000.0]
    bwd_iats = [6_300_000.0, 100_000.0]

    duration_us = 6_600_000.0
    duration_s = duration_us / 1_000_000.0

    def mean(values):
        return statistics.fmean(values) if values else 0.0

    def std(values):
        return statistics.stdev(values) if len(values) > 1 else 0.0

    def var(values):
        return statistics.variance(values) if len(values) > 1 else 0.0

    expected = {
        "Protocol": 6.0,
        "Flow Duration": duration_us,
        "Total Fwd Packets": 3.0,
        "Total Backward Packets": 3.0,
        "Fwd Packets Length Total": 300.0,
        "Bwd Packets Length Total": 75.0,
        "Fwd Packet Length Max": 200.0,
        "Fwd Packet Length Min": 0.0,
        "Fwd Packet Length Mean": mean(fwd_lengths),
        "Fwd Packet Length Std": std(fwd_lengths),
        "Bwd Packet Length Max": 50.0,
        "Bwd Packet Length Min": 0.0,
        "Bwd Packet Length Mean": mean(bwd_lengths),
        "Bwd Packet Length Std": std(bwd_lengths),
        "Flow Bytes/s": 375.0 / duration_s,
        "Flow Packets/s": 6.0 / duration_s,
        "Flow IAT Mean": mean(flow_iats),
        "Flow IAT Std": std(flow_iats),
        "Flow IAT Max": max(flow_iats),
        "Flow IAT Min": min(flow_iats),
        "Fwd IAT Total": sum(fwd_iats),
        "Fwd IAT Mean": mean(fwd_iats),
        "Fwd IAT Std": std(fwd_iats),
        "Fwd IAT Max": max(fwd_iats),
        "Fwd IAT Min": min(fwd_iats),
        "Bwd IAT Total": sum(bwd_iats),
        "Bwd IAT Mean": mean(bwd_iats),
        "Bwd IAT Std": std(bwd_iats),
        "Bwd IAT Max": max(bwd_iats),
        "Bwd IAT Min": min(bwd_iats),
        "Fwd PSH Flags": 2.0,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": 60.0,
        "Bwd Header Length": 60.0,
        "Fwd Packets/s": 3.0 / duration_s,
        "Bwd Packets/s": 3.0 / duration_s,
        "Packet Length Min": min(flow_lengths),
        "Packet Length Max": max(flow_lengths),
        "Packet Length Mean": mean(flow_lengths),
        "Packet Length Std": std(flow_lengths),
        "Packet Length Variance": var(flow_lengths),
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 1.0,
        "RST Flag Count": 0.0,
        "PSH Flag Count": 2.0,
        "ACK Flag Count": 5.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 1.0,
        # CICFlowMeter quirk reproduced by collector:
        # flow-length-stat sum divided by real packet count.
        "Avg Packet Size": sum(flow_lengths) / 6.0,
        "Avg Fwd Segment Size": mean(fwd_lengths),
        "Avg Bwd Segment Size": mean(bwd_lengths),
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        # One >1s gap => sf_count=1, so totals survive integer division.
        "Subflow Fwd Packets": 3.0,
        "Subflow Fwd Bytes": 300.0,
        "Subflow Bwd Packets": 3.0,
        "Subflow Bwd Bytes": 75.0,
        "Init Fwd Win Bytes": 1000.0,
        # Collector intentionally mirrors CICFlowMeter's effective last BWD window.
        "Init Bwd Win Bytes": 500.0,
        # First packet is excluded from addPacket() active-data counting.
        "Fwd Act Data Packets": 2.0,
        "Fwd Seg Size Min": 20.0,
        # Gap from 0.3s -> 6.5s is >5s.
        "Active Mean": 300_000.0,
        "Active Std": 0.0,
        "Active Max": 300_000.0,
        "Active Min": 300_000.0,
        "Idle Mean": 6_200_000.0,
        "Idle Std": 0.0,
        "Idle Max": 6_200_000.0,
        "Idle Min": 6_200_000.0,
    }

    return expected


def make_fixture_flow(c):
    records = [
        c.PacketRecord(
            timestamp_us=0,
            direction="FWD",
            payload_length=0,
            header_length=20,
            syn=1,
            tcp_window=1000,
        ),
        c.PacketRecord(
            timestamp_us=100_000,
            direction="FWD",
            payload_length=100,
            header_length=20,
            psh=1,
            ack=1,
            tcp_window=900,
        ),
        c.PacketRecord(
            timestamp_us=200_000,
            direction="BWD",
            payload_length=50,
            header_length=20,
            ack=1,
            tcp_window=800,
        ),
        c.PacketRecord(
            timestamp_us=300_000,
            direction="FWD",
            payload_length=200,
            header_length=20,
            psh=1,
            ack=1,
            tcp_window=700,
        ),
        c.PacketRecord(
            timestamp_us=6_500_000,
            direction="BWD",
            payload_length=0,
            header_length=20,
            ack=1,
            tcp_window=600,
        ),
        c.PacketRecord(
            timestamp_us=6_600_000,
            direction="BWD",
            payload_length=25,
            header_length=20,
            fin=1,
            ack=1,
            tcp_window=500,
        ),
    ]

    return c.Flow(
        protocol_name="TCP",
        protocol_number=6,
        fwd_src_ip="192.0.2.10",
        fwd_src_port=50000,
        fwd_dst_ip="198.51.100.20",
        fwd_dst_port=443,
        first_seen_us=0,
        last_seen_us=6_600_000,
        records=records,
    )


def main() -> int:
    print("=" * 80)
    print("SENTINEL PHASE 10 - STEP 3")
    print("COLLECTOR FEATURE-CONTRACT + DETERMINISTIC PARITY VALIDATION")
    print("=" * 80)

    c = load_collector()
    saved_features = list(joblib.load(FEATURES_PATH))

    # ------------------------------------------------------------------
    # Contract checks
    # ------------------------------------------------------------------

    record_check(
        "Collector exports exactly 77 feature names",
        len(c.EXPECTED_FEATURES) == 77,
        f"count={len(c.EXPECTED_FEATURES)}",
    )

    record_check(
        "Collector feature order exactly matches saved XGBoost contract",
        c.EXPECTED_FEATURES == saved_features,
    )

    record_check(
        "CICFlow activity timeout is 5 seconds",
        c.ACTIVITY_TIMEOUT_US == 5_000_000,
        f"value={c.ACTIVITY_TIMEOUT_US} us",
    )

    record_check(
        "Subflow/bulk gap threshold is 1 second",
        c.ONE_SECOND_US == 1_000_000,
        f"value={c.ONE_SECOND_US} us",
    )

    # This is intentionally a known operational deviation, not a failed test.
    timeout_deviation = c.LIVE_IDLE_FLUSH_SECONDS != 120.0

    print(
        "[INFO] Live idle flush vs CICFlow offline timeout"
        f" = {c.LIVE_IDLE_FLUSH_SECONDS:.0f}s vs 120s"
    )
    print(
        "       Known Phase 9/10 operational deviation; "
        "documented rather than hidden."
    )

    # ------------------------------------------------------------------
    # Flow-key direction symmetry
    # ------------------------------------------------------------------

    key_forward = c.make_flow_key(
        "192.0.2.10", 50000,
        "198.51.100.20", 443,
        "TCP",
    )
    key_reverse = c.make_flow_key(
        "198.51.100.20", 443,
        "192.0.2.10", 50000,
        "TCP",
    )

    record_check(
        "Bidirectional packets resolve to the same flow key",
        key_forward == key_reverse,
    )

    # ------------------------------------------------------------------
    # PacketReader-style transport parsing checks
    # ------------------------------------------------------------------

    tcp_packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(
            sport=50000,
            dport=443,
            flags="PA",
            window=4096,
        )
        / Raw(load=b"sentinel")
    )

    tcp_details = c.packet_details(tcp_packet)

    record_check(
        "TCP packet parsing uses transport payload length",
        (
            tcp_details is not None
            and tcp_details["protocol_number"] == 6
            and tcp_details["payload_length"] == len(b"sentinel")
            and tcp_details["header_length"] == 20
            and tcp_details["psh"] == 1
            and tcp_details["ack"] == 1
            and tcp_details["tcp_window"] == 4096
        ),
        str(tcp_details),
    )

    udp_packet = (
        IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=53000, dport=53)
        / Raw(load=b"abcd")
    )

    udp_details = c.packet_details(udp_packet)

    record_check(
        "UDP packet parsing uses 8-byte transport header and payload bytes",
        (
            udp_details is not None
            and udp_details["protocol_number"] == 17
            and udp_details["header_length"] == 8
            and udp_details["payload_length"] == 4
        ),
        str(udp_details),
    )

    # ------------------------------------------------------------------
    # Deterministic 77-feature parity fixture
    # ------------------------------------------------------------------

    flow = make_fixture_flow(c)
    actual = c.build_feature_vector(flow)
    expected = expected_fixture_features()

    record_check(
        "Fixture output contains exactly 77 finite features",
        (
            len(actual) == 77
            and list(actual.keys()) == saved_features
            and all(math.isfinite(float(v)) for v in actual.values())
        ),
    )

    mismatches = []

    for name in saved_features:
        a = float(actual[name])
        e = float(expected[name])

        if not close(a, e):
            mismatches.append(
                {
                    "feature": name,
                    "expected": e,
                    "actual": a,
                    "difference": a - e,
                }
            )

    record_check(
        "All 77 deterministic fixture values match independent expectations",
        len(mismatches) == 0,
        (
            "all 77 matched"
            if not mismatches
            else json.dumps(mismatches[:10], indent=2)
        ),
    )

    # Grouped checks make failures easier to understand if collector code changes.
    groups = {
        "packet/direction counts": [
            "Protocol",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Fwd Packets Length Total",
            "Bwd Packets Length Total",
        ],
        "IAT semantics": [
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Bwd IAT Total",
        ],
        "flags and headers": [
            "Fwd PSH Flags",
            "Bwd PSH Flags",
            "FIN Flag Count",
            "SYN Flag Count",
            "ACK Flag Count",
            "Fwd Header Length",
            "Bwd Header Length",
        ],
        "subflow/window/active-data": [
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "Init Fwd Win Bytes",
            "Init Bwd Win Bytes",
            "Fwd Act Data Packets",
            "Fwd Seg Size Min",
        ],
        "active/idle": [
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min",
        ],
    }

    for group_name, names in groups.items():
        group_ok = all(close(actual[name], expected[name]) for name in names)

        record_check(
            f"Fixture group matches: {group_name}",
            group_ok,
        )

    print("\n" + "=" * 80)
    print("STEP 3 RESULT")
    print("=" * 80)
    print(f"Passed : {passed}")
    print(f"Failed : {failed}")

    status = "PASS" if failed == 0 else "CHECK FAILURES"
    print(f"STATUS : {status}")

    report = {
        "phase": 10,
        "step": 3,
        "test": "collector_feature_contract_and_deterministic_parity",
        "status": status,
        "passed": passed,
        "failed": failed,
        "feature_count": len(actual),
        "feature_contract_matches_saved_model": (
            c.EXPECTED_FEATURES == saved_features
        ),
        "known_timeout_deviation": {
            "live_idle_flush_seconds": c.LIVE_IDLE_FLUSH_SECONDS,
            "cicflow_offline_timeout_seconds": 120,
            "different": timeout_deviation,
            "classification": "KNOWN_OPERATIONAL_DEVIATION",
        },
        "fixture_mismatches": mismatches,
        "checks": checks,
        "limitations": [
            (
                "This validates the Collector against deterministic, "
                "independently calculated source-aligned feature fixtures."
            ),
            (
                "It does not prove byte-for-byte parity against an official "
                "CICFlowMeter export of the same raw PCAP because the local "
                "Parquet files do not contain their originating packets."
            ),
        ],
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"\nReport saved: {REPORT_PATH}")

    if failed == 0:
        print("\nInterpretation:")
        print("- Saved 77-feature contract matches the Collector exactly.")
        print("- TCP/UDP transport parsing checks passed.")
        print("- Direction, timing, flags, windows, subflow and active/idle fixture")
        print("  semantics matched independent expected values.")
        print("- The 10s live flush vs 120s offline timeout remains a documented")
        print("  operational difference and is NOT being hidden as 'exact parity'.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
