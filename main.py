import time
from src.pipeline import ThreatDetectionPipeline

def main():
    print("Starting Threat Detection Pipeline...")
    pipeline = ThreatDetectionPipeline()

    # Simulate a stream of mock packets for a specific flow (e.g., a potential DDoS attack)
    mock_traffic = [
        {"timestamp": 1.0, "flow_id": "flow_999", "rate": 50.0, "syn_ack_ratio": 0.8},
        {"timestamp": 1.5, "flow_id": "flow_999", "rate": 80.0, "syn_ack_ratio": 0.9},
        {"timestamp": 2.0, "flow_id": "flow_999", "rate": 120.0, "syn_ack_ratio": 1.0},
        {"timestamp": 2.5, "flow_id": "flow_888", "rate": 5.0, "syn_ack_ratio": 0.1}, # Normal traffic
    ]

    for packet in mock_traffic:
        print(f"\n[Ingest] Processing packet for {packet['flow_id']} at t={packet['timestamp']}")
        alert = pipeline.process_packet(packet)

        if alert:
            print(">>> [ALERT] Threat Detected! <<<")
            print(f"    Threat Class: {alert.threat_class}")
            print(f"    Confidence: {alert.confidence:.2f}")
            print(f"    Severity: {alert.severity:.2f}")
            print(f"    Flow ID: {alert.flow_id}")
        else:
            print("    [Info] Packet processed, no alert triggered (buffered or benign).")

        time.sleep(0.1)

if __name__ == "__main__":
    main()
