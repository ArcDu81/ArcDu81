from typing import List, Dict, Optional
from src.schemas import FlowFeatures, L1ThreatScores, L1Output, AlertRecord
from src.models import (
    DDoSModel, C2BeaconingModel, DGAModel, EncryptedMalwareModel,
    ReconModel, DataExfiltrationModel, L1AggregatorModel, TemporalDependencyModel
)

class Stage1Ingest:
    def __init__(self):
        # Mock streaming feature extraction
        pass

    def extract_features(self, raw_data: dict) -> FlowFeatures:
        # Takes raw packet data dict and returns features
        return FlowFeatures(
            timestamp=raw_data.get("timestamp", 0.0),
            flow_id=raw_data.get("flow_id", "unknown_flow"),
            rate=raw_data.get("rate", 0.0),
            syn_ack_ratio=raw_data.get("syn_ack_ratio", 0.0),
            src_ip_entropy=raw_data.get("src_ip_entropy", 0.0),
            inter_arrival_cv=raw_data.get("inter_arrival_cv", 0.0),
            autocorrelation=raw_data.get("autocorrelation", 0.0),
            fft_peak=raw_data.get("fft_peak", 0.0),
            entropy=raw_data.get("entropy", 0.0),
            n_gram=raw_data.get("n_gram", 0.0),
            query_len=raw_data.get("query_len", 0.0),
            nxdomain=raw_data.get("nxdomain", 0.0),
            ja3_ja4=raw_data.get("ja3_ja4", 0.0),
            size=raw_data.get("size", 0.0),
            timing_sequence_stats=raw_data.get("timing_sequence_stats", 0.0),
            dst_port_fan_out=raw_data.get("dst_port_fan_out", 0.0),
            syn_no_ack_ratio=raw_data.get("syn_no_ack_ratio", 0.0),
            byte_ratio=raw_data.get("byte_ratio", 0.0),
            outbound_total=raw_data.get("outbound_total", 0.0),
            dest_rarity=raw_data.get("dest_rarity", 0.0)
        )

class Layer1Pipeline:
    def __init__(self):
        self.ddos = DDoSModel()
        self.c2 = C2BeaconingModel()
        self.dga = DGAModel()
        self.malware = EncryptedMalwareModel()
        self.recon = ReconModel()
        self.exfil = DataExfiltrationModel()
        self.aggregator = L1AggregatorModel()

    def process(self, features: FlowFeatures) -> L1Output:
        scores = L1ThreatScores(
            ddos=self.ddos.predict(features),
            c2_beaconing=self.c2.predict(features),
            dga=self.dga.predict(features),
            encrypted_malware=self.malware.predict(features),
            recon=self.recon.predict(features),
            data_exfiltration=self.exfil.predict(features)
        )

        agg_result = self.aggregator.predict(scores)

        return L1Output(
            timestamp=features.timestamp,
            flow_id=features.flow_id,
            threat_class=agg_result["threat_class"],
            confidence=agg_result["confidence"],
            evidence=scores,  # using scores as evidence mock
            l1_votes=scores
        )

class Layer2Temporal:
    def __init__(self, n_sequential: int = 3):
        self.n_sequential = n_sequential
        self.buckets: Dict[str, List[L1Output]] = {}
        self.temporal_model = TemporalDependencyModel()

    def process(self, l1_output: L1Output) -> Optional[L1Output]:
        flow_id = l1_output.flow_id
        if flow_id not in self.buckets:
            self.buckets[flow_id] = []

        self.buckets[flow_id].append(l1_output)

        # Keep window size N
        if len(self.buckets[flow_id]) > self.n_sequential:
            self.buckets[flow_id].pop(0)

        bucket = self.buckets[flow_id]

        # Calculate bucket summary features
        streak_length = len([x for x in bucket if x.confidence > 0.5])
        vote_count = sum([1 for x in bucket if x.threat_class == l1_output.threat_class and x.confidence > 0.5])

        bucket_features = {
            "streak_length": streak_length,
            "vote_count": vote_count,
            "confidence_trend_slope": 0.0 # Mock slope
        }

        decision = self.temporal_model.predict(bucket_features)

        if decision == 1:
            return l1_output
        return None

class Stage3Alerting:
    def __init__(self):
        pass

    def format_alert(self, l1_output: L1Output) -> AlertRecord:
        severity = l1_output.confidence * 10.0 # Mock severity mapping
        return AlertRecord(
            timestamp=l1_output.timestamp,
            flow_id=l1_output.flow_id,
            threat_class=l1_output.threat_class,
            confidence=l1_output.confidence,
            severity=severity,
            evidence=l1_output.evidence,
            l1_votes=l1_output.l1_votes
        )

class ThreatDetectionPipeline:
    def __init__(self):
        self.stage1 = Stage1Ingest()
        self.layer1 = Layer1Pipeline()
        self.layer2 = Layer2Temporal()
        self.stage3 = Stage3Alerting()

    def process_packet(self, raw_data: dict) -> Optional[AlertRecord]:
        features = self.stage1.extract_features(raw_data)
        l1_output = self.layer1.process(features)
        temporal_decision = self.layer2.process(l1_output)

        if temporal_decision is not None:
            return self.stage3.format_alert(temporal_decision)
        return None
