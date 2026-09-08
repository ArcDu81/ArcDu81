import pytest
from src.schemas import FlowFeatures, L1ThreatScores, L1Output, AlertRecord
from src.models import (
    DDoSModel, C2BeaconingModel, DGAModel, EncryptedMalwareModel,
    ReconModel, DataExfiltrationModel, L1AggregatorModel, TemporalDependencyModel
)
from src.pipeline import ThreatDetectionPipeline, Layer2Temporal

def test_models_return_float():
    features = FlowFeatures(
        timestamp=1.0, flow_id="f1", rate=10.0, syn_ack_ratio=0.5, src_ip_entropy=0.0,
        inter_arrival_cv=0.1, autocorrelation=0.2, fft_peak=0.0, entropy=0.8,
        n_gram=0.5, query_len=10.0, nxdomain=1.0, ja3_ja4=0.9, size=100.0,
        timing_sequence_stats=0.0, dst_port_fan_out=2.0, syn_no_ack_ratio=0.5,
        byte_ratio=0.7, outbound_total=500.0, dest_rarity=0.1
    )

    models = [
        DDoSModel(), C2BeaconingModel(), DGAModel(),
        EncryptedMalwareModel(), ReconModel(), DataExfiltrationModel()
    ]

    for model in models:
        score = model.predict(features)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

def test_l1_aggregator_structure():
    scores = L1ThreatScores(
        ddos=0.8, c2_beaconing=0.2, dga=0.1,
        encrypted_malware=0.3, recon=0.4, data_exfiltration=0.5
    )

    aggregator = L1AggregatorModel()
    result = aggregator.predict(scores)

    assert isinstance(result, dict)
    assert "threat_class" in result
    assert "confidence" in result
    assert result["threat_class"] == "DDoS"
    assert result["confidence"] == 0.8

def test_layer2_temporal():
    layer2 = Layer2Temporal(n_sequential=3)

    scores = L1ThreatScores(0.8, 0.0, 0.0, 0.0, 0.0, 0.0)
    output_1 = L1Output(1.0, "f1", "DDoS", 0.8, scores, scores)
    output_2 = L1Output(2.0, "f1", "DDoS", 0.9, scores, scores)
    output_3 = L1Output(3.0, "f1", "DDoS", 0.7, scores, scores)

    # First output shouldn't trigger keep (streak=1, vote=1 < threshold)
    res_1 = layer2.process(output_1)
    assert res_1 is None

    # Second output hits vote=2, should trigger KEEP
    res_2 = layer2.process(output_2)
    assert res_2 is not None
    assert res_2.flow_id == "f1"

def test_full_pipeline():
    pipeline = ThreatDetectionPipeline()

    # High threat packet
    raw_packet_1 = {
        "timestamp": 1.0, "flow_id": "flow_123",
        "rate": 100.0, "syn_ack_ratio": 1.0
    }
    raw_packet_2 = {
        "timestamp": 2.0, "flow_id": "flow_123",
        "rate": 150.0, "syn_ack_ratio": 1.0
    }

    # First packet - probably won't alert due to temporal dependency
    alert_1 = pipeline.process_packet(raw_packet_1)
    assert alert_1 is None

    # Second packet - should trigger alert due to temporal dependency model rules
    alert_2 = pipeline.process_packet(raw_packet_2)
    assert alert_2 is not None
    assert isinstance(alert_2, AlertRecord)
    assert alert_2.flow_id == "flow_123"
    assert alert_2.threat_class == "DDoS"
