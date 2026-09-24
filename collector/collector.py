import json
import math
import statistics
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass, field
import hashlib

from scapy.all import sniff, IP, TCP, UDP


HEARTBEAT_URL = "http://127.0.0.1:8000/collector/heartbeat"
PREDICT_URL = "http://127.0.0.1:8000/predict"
HEARTBEAT_INTERVAL = 5

# Keep automation OFF during the first live-inference validation.
# The backend will still save predictions and broadcast them to the dashboard.
TRIGGER_AUTOMATION = True

INTERFACE_NAME = "Ethernet"
LOCAL_IP = "192.168.100.3"

# Live operational flush: an inactive flow is emitted after this many seconds.
# CICFlowMeter's offline flow timeout is 120 seconds from flow start; for the
# live prototype we keep a shorter inactivity flush so the SOC receives flows
# promptly. Phase 10 replay validation will quantify this difference.
LIVE_IDLE_FLUSH_SECONDS = 10.0

# Canonical CICFlowMeter activity threshold.
ACTIVITY_TIMEOUT_US = 5_000_000

# Canonical CICFlowMeter subflow / bulk gap threshold.
ONE_SECOND_US = 1_000_000

EXPECTED_FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Avg Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init Fwd Win Bytes",
    "Init Bwd Win Bytes",
    "Fwd Act Data Packets",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


@dataclass
class PacketRecord:
    timestamp_us: int
    direction: str

    # CICFlowMeter PacketReader stores transport payload bytes and
    # transport header bytes (TCP/UDP), not full Ethernet/IP sizes.
    payload_length: int
    header_length: int

    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    urg: int = 0
    cwr: int = 0
    ece: int = 0

    tcp_window: int = 0


@dataclass
class Flow:
    protocol_name: str
    protocol_number: int

    fwd_src_ip: str
    fwd_src_port: int
    fwd_dst_ip: str
    fwd_dst_port: int

    first_seen_us: int
    last_seen_us: int

    records: list[PacketRecord] = field(default_factory=list)


flows: dict[tuple, Flow] = {}
flows_lock = threading.Lock()


def safe_mean(values):
    return statistics.fmean(values) if values else 0.0


def safe_std(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def safe_variance(values):
    return statistics.variance(values) if len(values) > 1 else 0.0


def min_or_zero(values):
    return min(values) if values else 0.0


def max_or_zero(values):
    return max(values) if values else 0.0


def differences(values):
    if len(values) <= 1:
        return []

    return [
        values[i] - values[i - 1]
        for i in range(1, len(values))
    ]


def iat_stats(timestamps):
    values = differences(timestamps)

    return {
        "total": float(sum(values)) if values else 0.0,
        "mean": safe_mean(values),
        "std": safe_std(values),
        "max": max_or_zero(values),
        "min": min_or_zero(values),
    }


def send_heartbeat():
    request = urllib.request.Request(
        HEARTBEAT_URL,
        data=b"",
        method="POST",
    )

    with urllib.request.urlopen(
        request,
        timeout=3,
    ) as response:
        return response.status


def heartbeat_loop():
    while True:
        try:
            send_heartbeat()
        except Exception as exc:
            print(f"[Heartbeat] Failed: {exc}")

        time.sleep(HEARTBEAT_INTERVAL)

def build_request_id(flow: Flow) -> str:
    raw = (
        f"{flow.protocol_name}|"
        f"{flow.fwd_src_ip}|"
        f"{flow.fwd_src_port}|"
        f"{flow.fwd_dst_ip}|"
        f"{flow.fwd_dst_port}|"
        f"{flow.first_seen_us}"
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()

def send_flow_for_prediction(
    flow: Flow,
    features: dict[str, float],
):
    observed_at = datetime.fromtimestamp(
        flow.first_seen_us / 1_000_000,
        tz=timezone.utc,
    ).isoformat()

    payload = {
        "request_id": build_request_id(flow),
        "features": features,
        "metadata": {
            "source_ip": flow.fwd_src_ip,
            "destination_ip": flow.fwd_dst_ip,
            "source_port": flow.fwd_src_port,
            "destination_port": flow.fwd_dst_port,
            "transport_protocol": flow.protocol_name,
            "observed_at": observed_at,
        },
        "trigger_automation": TRIGGER_AUTOMATION,
    }

    body = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        PREDICT_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=20,
        ) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

            return result

    except urllib.error.HTTPError as exc:
        response_body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"FastAPI returned HTTP "
            f"{exc.code}: {response_body}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not reach FastAPI: "
            f"{exc.reason}"
        ) from exc


def make_flow_key(
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    protocol,
):
    endpoint_a = (source_ip, source_port)
    endpoint_b = (destination_ip, destination_port)

    ordered = sorted(
        [endpoint_a, endpoint_b]
    )

    return (
        protocol,
        ordered[0],
        ordered[1],
    )


def packet_details(packet):
    if TCP in packet:
        tcp = packet[TCP]
        flags = int(tcp.flags)

        return {
            "protocol_name": "TCP",
            "protocol_number": 6,
            "source_port": int(tcp.sport),
            "destination_port": int(tcp.dport),
            "header_length": int(
                (tcp.dataofs or 5) * 4
            ),
            "payload_length": len(
                bytes(tcp.payload)
            ),
            "fin": 1 if flags & 0x01 else 0,
            "syn": 1 if flags & 0x02 else 0,
            "rst": 1 if flags & 0x04 else 0,
            "psh": 1 if flags & 0x08 else 0,
            "ack": 1 if flags & 0x10 else 0,
            "urg": 1 if flags & 0x20 else 0,
            "ece": 1 if flags & 0x40 else 0,
            "cwr": 1 if flags & 0x80 else 0,
            "tcp_window": int(tcp.window),
        }

    if UDP in packet:
        udp = packet[UDP]

        return {
            "protocol_name": "UDP",
            "protocol_number": 17,
            "source_port": int(udp.sport),
            "destination_port": int(udp.dport),
            "header_length": 8,
            "payload_length": len(
                bytes(udp.payload)
            ),
            "fin": 0,
            "syn": 0,
            "rst": 0,
            "psh": 0,
            "ack": 0,
            "urg": 0,
            "ece": 0,
            "cwr": 0,
            "tcp_window": 0,
        }

    return None


def process_packet(packet):
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    if (
        source_ip != LOCAL_IP
        and destination_ip != LOCAL_IP
    ):
        return

    details = packet_details(packet)

    if details is None:
        return

    source_port = details["source_port"]
    destination_port = details[
        "destination_port"
    ]

    key = make_flow_key(
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        details["protocol_name"],
    )

    timestamp_us = int(
        float(packet.time) * 1_000_000
    )

    with flows_lock:
        flow = flows.get(key)

        if flow is None:
            # First observed packet defines the forward direction.
            flow = Flow(
                protocol_name=details[
                    "protocol_name"
                ],
                protocol_number=details[
                    "protocol_number"
                ],
                fwd_src_ip=source_ip,
                fwd_src_port=source_port,
                fwd_dst_ip=destination_ip,
                fwd_dst_port=destination_port,
                first_seen_us=timestamp_us,
                last_seen_us=timestamp_us,
            )

            flows[key] = flow

        is_forward = (
            source_ip == flow.fwd_src_ip
            and source_port == flow.fwd_src_port
            and destination_ip == flow.fwd_dst_ip
            and destination_port == flow.fwd_dst_port
        )

        flow.last_seen_us = timestamp_us

        flow.records.append(
            PacketRecord(
                timestamp_us=timestamp_us,
                direction=(
                    "FWD"
                    if is_forward
                    else "BWD"
                ),
                payload_length=details[
                    "payload_length"
                ],
                header_length=details[
                    "header_length"
                ],
                fin=details["fin"],
                syn=details["syn"],
                rst=details["rst"],
                psh=details["psh"],
                ack=details["ack"],
                urg=details["urg"],
                cwr=details["cwr"],
                ece=details["ece"],
                tcp_window=details[
                    "tcp_window"
                ],
            )
        )


def canonical_active_idle(records):
    """
    Mirrors BasicFlow.updateActiveIdleTime behavior:
    active/idle values are committed only when a >5s gap occurs.
    The final active period is NOT force-added at live flush.
    """
    if len(records) <= 1:
        return [], []

    ordered = sorted(
        records,
        key=lambda record: record.timestamp_us,
    )

    start_active = ordered[0].timestamp_us
    end_active = ordered[0].timestamp_us

    active_values = []
    idle_values = []

    for record in ordered[1:]:
        current = record.timestamp_us

        if (
            current - end_active
            > ACTIVITY_TIMEOUT_US
        ):
            active_duration = (
                end_active - start_active
            )

            if active_duration > 0:
                active_values.append(
                    active_duration
                )

            idle_values.append(
                current - end_active
            )

            start_active = current
            end_active = current
        else:
            end_active = current

    return active_values, idle_values


def canonical_subflow_values(records):
    """
    Matches CICFlowMeter's sfCount behavior.
    sfCount increments for each >1s inter-packet gap.
    If sfCount stays 0, exported subflow values are 0.
    """
    if not records:
        return 0, 0, 0, 0

    ordered = sorted(
        records,
        key=lambda record: record.timestamp_us,
    )

    sf_count = 0
    previous = ordered[0].timestamp_us

    for record in ordered[1:]:
        if (
            record.timestamp_us - previous
            > ONE_SECOND_US
        ):
            sf_count += 1

        previous = record.timestamp_us

    if sf_count <= 0:
        return 0, 0, 0, 0

    fwd = [
        record
        for record in ordered
        if record.direction == "FWD"
    ]

    bwd = [
        record
        for record in ordered
        if record.direction == "BWD"
    ]

    return (
        len(fwd) // sf_count,
        sum(
            record.payload_length
            for record in fwd
        ) // sf_count,
        len(bwd) // sf_count,
        sum(
            record.payload_length
            for record in bwd
        ) // sf_count,
    )


def bulk_features(records, direction):
    """
    CICFlowMeter-style bulk approximation:
    >=4 payload packets in the same direction, with <=1s gaps.
    Opposite-direction payload resets the candidate.
    """
    ordered = sorted(
        records,
        key=lambda record: record.timestamp_us,
    )

    start_us = None
    last_us = None
    helper_packets = 0
    helper_bytes = 0

    state_count = 0
    packet_count = 0
    byte_count = 0
    duration_us = 0

    last_opposite_payload = None

    for record in ordered:
        if record.payload_length <= 0:
            continue

        if record.direction != direction:
            last_opposite_payload = (
                record.timestamp_us
            )
            continue

        if (
            start_us is not None
            and last_opposite_payload is not None
            and last_opposite_payload > start_us
        ):
            start_us = None
            last_us = None
            helper_packets = 0
            helper_bytes = 0

        if start_us is None:
            start_us = record.timestamp_us
            last_us = record.timestamp_us
            helper_packets = 1
            helper_bytes = (
                record.payload_length
            )
            continue

        if (
            record.timestamp_us - last_us
            > ONE_SECOND_US
        ):
            start_us = record.timestamp_us
            last_us = record.timestamp_us
            helper_packets = 1
            helper_bytes = (
                record.payload_length
            )
            continue

        helper_packets += 1
        helper_bytes += record.payload_length

        if helper_packets == 4:
            state_count += 1
            packet_count += helper_packets
            byte_count += helper_bytes
            duration_us += (
                record.timestamp_us - start_us
            )

        elif helper_packets > 4:
            packet_count += 1
            byte_count += record.payload_length
            duration_us += (
                record.timestamp_us - last_us
            )

        last_us = record.timestamp_us

    if state_count == 0:
        return 0.0, 0.0, 0.0

    avg_bytes = byte_count // state_count
    avg_packets = packet_count // state_count

    avg_rate = 0.0

    if duration_us > 0:
        avg_rate = float(
            int(
                byte_count
                / (duration_us / 1_000_000)
            )
        )

    return (
        float(avg_bytes),
        float(avg_packets),
        avg_rate,
    )


def build_feature_vector(flow: Flow):
    records = sorted(
        flow.records,
        key=lambda record: record.timestamp_us,
    )

    if len(records) < 2:
        raise RuntimeError(
            "CICFlow output requires >1 packet."
        )

    fwd = [
        record
        for record in records
        if record.direction == "FWD"
    ]

    bwd = [
        record
        for record in records
        if record.direction == "BWD"
    ]

    fwd_lengths = [
        record.payload_length
        for record in fwd
    ]

    bwd_lengths = [
        record.payload_length
        for record in bwd
    ]

    # BasicFlow.firstPacket() adds the first packet's payload to
    # flowLengthStats twice. Reproduce that historical quirk because
    # CIC-IDS2017 was generated from CICFlowMeter-style output.
    flow_length_stats = [
        records[0].payload_length,
        records[0].payload_length,
    ] + [
        record.payload_length
        for record in records[1:]
    ]

    all_times = [
        record.timestamp_us
        for record in records
    ]

    fwd_times = [
        record.timestamp_us
        for record in fwd
    ]

    bwd_times = [
        record.timestamp_us
        for record in bwd
    ]

    flow_duration_us = max(
        0,
        flow.last_seen_us
        - flow.first_seen_us,
    )

    duration_seconds = (
        flow_duration_us / 1_000_000
        if flow_duration_us > 0
        else 0.0
    )

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)
    total_bytes = (
        total_fwd_bytes
        + total_bwd_bytes
    )

    flow_iat = iat_stats(all_times)
    fwd_iat = iat_stats(fwd_times)
    bwd_iat = iat_stats(bwd_times)

    active, idle = (
        canonical_active_idle(records)
    )

    (
        subflow_fwd_packets,
        subflow_fwd_bytes,
        subflow_bwd_packets,
        subflow_bwd_bytes,
    ) = canonical_subflow_values(
        records
    )

    (
        fwd_bulk_bytes,
        fwd_bulk_packets,
        fwd_bulk_rate,
    ) = bulk_features(
        records,
        "FWD",
    )

    (
        bwd_bulk_bytes,
        bwd_bulk_packets,
        bwd_bulk_rate,
    ) = bulk_features(
        records,
        "BWD",
    )

    # Forward initial window is the first forward TCP window.
    init_fwd_window = (
        fwd[0].tcp_window
        if fwd
        else 0
    )

    # CICFlowMeter updates backward init window on backward addPacket(),
    # so the exported value is effectively the last backward TCP window.
    init_bwd_window = (
        bwd[-1].tcp_window
        if bwd
        else 0
    )

    # Act_data_pkt_forward is incremented in addPacket(), not firstPacket().
    fwd_active_data_packets = sum(
        1
        for index, record in enumerate(records)
        if (
            index > 0
            and record.direction == "FWD"
            and record.payload_length >= 1
        )
    )

    fwd_header_lengths = [
        record.header_length
        for record in fwd
    ]

    bwd_header_lengths = [
        record.header_length
        for record in bwd
    ]

    # Saved training column uses "CWE", while CICFlowMeter exports CWR.
    cwr_count = sum(
        record.cwr
        for record in records
    )

    # Java implementation uses integer division before casting to double.
    down_up_ratio = (
        float(len(bwd) // len(fwd))
        if fwd
        else 0.0
    )

    avg_packet_size = (
        sum(flow_length_stats) / len(records)
        if records
        else 0.0
    )

    features = {
        "Protocol": float(flow.protocol_number),
        "Flow Duration": float(flow_duration_us),
        "Total Fwd Packets": float(len(fwd)),
        "Total Backward Packets": float(len(bwd)),
        "Fwd Packets Length Total": float(total_fwd_bytes),
        "Bwd Packets Length Total": float(total_bwd_bytes),

        "Fwd Packet Length Max": float(max_or_zero(fwd_lengths)),
        "Fwd Packet Length Min": float(min_or_zero(fwd_lengths)),
        "Fwd Packet Length Mean": float(safe_mean(fwd_lengths)),
        "Fwd Packet Length Std": float(safe_std(fwd_lengths)),

        "Bwd Packet Length Max": float(max_or_zero(bwd_lengths)),
        "Bwd Packet Length Min": float(min_or_zero(bwd_lengths)),
        "Bwd Packet Length Mean": float(safe_mean(bwd_lengths)),
        "Bwd Packet Length Std": float(safe_std(bwd_lengths)),

        "Flow Bytes/s": (
            float(total_bytes / duration_seconds)
            if duration_seconds > 0
            else 0.0
        ),
        "Flow Packets/s": (
            float(len(records) / duration_seconds)
            if duration_seconds > 0
            else 0.0
        ),

        "Flow IAT Mean": float(flow_iat["mean"]),
        "Flow IAT Std": float(flow_iat["std"]),
        "Flow IAT Max": float(flow_iat["max"]),
        "Flow IAT Min": float(flow_iat["min"]),

        "Fwd IAT Total": float(fwd_iat["total"]),
        "Fwd IAT Mean": float(fwd_iat["mean"]),
        "Fwd IAT Std": float(fwd_iat["std"]),
        "Fwd IAT Max": float(fwd_iat["max"]),
        "Fwd IAT Min": float(fwd_iat["min"]),

        "Bwd IAT Total": float(bwd_iat["total"]),
        "Bwd IAT Mean": float(bwd_iat["mean"]),
        "Bwd IAT Std": float(bwd_iat["std"]),
        "Bwd IAT Max": float(bwd_iat["max"]),
        "Bwd IAT Min": float(bwd_iat["min"]),

        "Fwd PSH Flags": float(sum(record.psh for record in fwd)),
        "Bwd PSH Flags": float(sum(record.psh for record in bwd)),
        "Fwd URG Flags": float(sum(record.urg for record in fwd)),
        "Bwd URG Flags": float(sum(record.urg for record in bwd)),

        "Fwd Header Length": float(sum(fwd_header_lengths)),
        "Bwd Header Length": float(sum(bwd_header_lengths)),

        "Fwd Packets/s": (
            float(len(fwd) / duration_seconds)
            if duration_seconds > 0
            else 0.0
        ),
        "Bwd Packets/s": (
            float(len(bwd) / duration_seconds)
            if duration_seconds > 0
            else 0.0
        ),

        "Packet Length Min": float(min_or_zero(flow_length_stats)),
        "Packet Length Max": float(max_or_zero(flow_length_stats)),
        "Packet Length Mean": float(safe_mean(flow_length_stats)),
        "Packet Length Std": float(safe_std(flow_length_stats)),
        "Packet Length Variance": float(safe_variance(flow_length_stats)),

        "FIN Flag Count": float(sum(record.fin for record in records)),
        "SYN Flag Count": float(sum(record.syn for record in records)),
        "RST Flag Count": float(sum(record.rst for record in records)),
        "PSH Flag Count": float(sum(record.psh for record in records)),
        "ACK Flag Count": float(sum(record.ack for record in records)),
        "URG Flag Count": float(sum(record.urg for record in records)),
        "CWE Flag Count": float(cwr_count),
        "ECE Flag Count": float(sum(record.ece for record in records)),

        "Down/Up Ratio": down_up_ratio,
        "Avg Packet Size": float(avg_packet_size),
        "Avg Fwd Segment Size": float(safe_mean(fwd_lengths)),
        "Avg Bwd Segment Size": float(safe_mean(bwd_lengths)),

        "Fwd Avg Bytes/Bulk": float(fwd_bulk_bytes),
        "Fwd Avg Packets/Bulk": float(fwd_bulk_packets),
        "Fwd Avg Bulk Rate": float(fwd_bulk_rate),
        "Bwd Avg Bytes/Bulk": float(bwd_bulk_bytes),
        "Bwd Avg Packets/Bulk": float(bwd_bulk_packets),
        "Bwd Avg Bulk Rate": float(bwd_bulk_rate),

        "Subflow Fwd Packets": float(subflow_fwd_packets),
        "Subflow Fwd Bytes": float(subflow_fwd_bytes),
        "Subflow Bwd Packets": float(subflow_bwd_packets),
        "Subflow Bwd Bytes": float(subflow_bwd_bytes),

        "Init Fwd Win Bytes": float(init_fwd_window),
        "Init Bwd Win Bytes": float(init_bwd_window),
        "Fwd Act Data Packets": float(fwd_active_data_packets),
        "Fwd Seg Size Min": float(min_or_zero(fwd_header_lengths)),

        "Active Mean": float(safe_mean(active)),
        "Active Std": float(safe_std(active)),
        "Active Max": float(max_or_zero(active)),
        "Active Min": float(min_or_zero(active)),

        "Idle Mean": float(safe_mean(idle)),
        "Idle Std": float(safe_std(idle)),
        "Idle Max": float(max_or_zero(idle)),
        "Idle Min": float(min_or_zero(idle)),
    }

    if list(features.keys()) != EXPECTED_FEATURES:
        raise RuntimeError(
            "77-feature name/order mismatch."
        )

    if len(features) != 77:
        raise RuntimeError(
            f"Expected 77 features, got {len(features)}."
        )

    for name, value in features.items():
        if not math.isfinite(value):
            raise RuntimeError(
                f"Non-finite feature {name}={value}"
            )

    return features


def print_completed_flow(
    flow,
    features,
    prediction_result,
):
    print()
    print("=" * 80)
    print(
        "LIVE FLOW CLASSIFIED - 77 FEATURES -> XGBOOST"
    )
    print("=" * 80)

    print(
        f"{flow.fwd_src_ip}:"
        f"{flow.fwd_src_port}"
        f"  <->  "
        f"{flow.fwd_dst_ip}:"
        f"{flow.fwd_dst_port}"
    )

    print(
        f"Protocol              : "
        f"{flow.protocol_name} "
        f"({flow.protocol_number})"
    )

    print(
        "Feature contract      : 77/77"
    )

    print(
        f"Flow Duration         : "
        f"{features['Flow Duration']:.0f} us"
    )

    print(
        f"Fwd / Bwd packets     : "
        f"{features['Total Fwd Packets']:.0f}"
        f" / "
        f"{features['Total Backward Packets']:.0f}"
    )

    print(
        f"Prediction            : "
        f"{prediction_result.get('prediction')}"
    )

    print(
        f"Confidence            : "
        f"{prediction_result.get('confidence')}"
    )

    print(
        f"Attack probability    : "
        f"{prediction_result.get('attack_probability')}"
    )

    print(
        f"Detection ID          : "
        f"{prediction_result.get('detection_id')}"
    )

    print(
        f"Automation            : "
        f"{'ENABLED' if TRIGGER_AUTOMATION else 'DISABLED FOR LIVE VALIDATION'}"
    )

    print(
        "Pipeline              : "
        "CAPTURE -> FLOW -> 77 FEATURES -> /predict -> DB -> WEBSOCKET"
    )


def flow_expiration_loop():
    while True:
        now_us = int(
            time.time() * 1_000_000
        )

        expired = []

        with flows_lock:
            for key, flow in list(
                flows.items()
            ):
                idle_seconds = (
                    now_us
                    - flow.last_seen_us
                ) / 1_000_000

                if (
                    idle_seconds
                    >= LIVE_IDLE_FLUSH_SECONDS
                ):
                    expired.append(flow)
                    del flows[key]

        for flow in expired:
            if len(flow.records) < 2:
                continue

            try:
                features = build_feature_vector(
                    flow
                )

                prediction_result = (
                    send_flow_for_prediction(
                        flow,
                        features,
                    )
                )

                print_completed_flow(
                    flow,
                    features,
                    prediction_result,
                )

            except Exception as exc:
                print(
                    "[Collector Pipeline] "
                    f"Flow rejected: {exc}"
                )

        time.sleep(1)


def start_capture():
    print("=" * 80)
    print(
        "Sentinel Live XGBoost Flow Collector"
    )
    print("=" * 80)

    print(
        f"Interface             : {INTERFACE_NAME}"
    )

    print(
        f"Local IP              : {LOCAL_IP}"
    )

    print(
        "Feature semantics     : "
        "CICFlowMeter source-aligned"
    )

    print(
        f"Live idle flush       : "
        f"{LIVE_IDLE_FLUSH_SECONDS:.0f}s"
    )

    print(
        "Training flow timeout : "
        "120s (validated separately in Phase 10 replay)"
    )

    print(
        "XGBoost inference     : ENABLED"
    )

    print(
        f"n8n automation        : "
        f"{'ENABLED' if TRIGGER_AUTOMATION else 'DISABLED (validation mode)'}"
    )

    print("=" * 80)
    print("\nListening for live traffic...")

    sniff(
        iface=INTERFACE_NAME,
        filter="ip and (tcp or udp)",
        prn=process_packet,
        store=False,
    )


def main():
    heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        daemon=True,
    )

    expiration_thread = threading.Thread(
        target=flow_expiration_loop,
        daemon=True,
    )

    heartbeat_thread.start()
    expiration_thread.start()

    start_capture()


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            "\nSentinel Collector stopped."
        )
