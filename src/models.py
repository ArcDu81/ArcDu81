import random
from typing import Dict, Any, List
from src.schemas import FlowFeatures, L1ThreatScores

class DDoSModel:
    def predict(self, features: FlowFeatures) -> float:
        # returns float between 0 and 1
        return min(max(features.rate * 0.1 + features.syn_ack_ratio * 0.5, 0.0), 1.0)

class C2BeaconingModel:
    def predict(self, features: FlowFeatures) -> float:
        return min(max(features.inter_arrival_cv * 0.3 + features.autocorrelation * 0.3, 0.0), 1.0)

class DGAModel:
    def predict(self, features: FlowFeatures) -> float:
        return min(max(features.entropy * 0.5 + features.nxdomain * 0.2, 0.0), 1.0)

class EncryptedMalwareModel:
    def predict(self, features: FlowFeatures) -> float:
        return min(max(features.ja3_ja4 * 0.5 + features.size * 0.1, 0.0), 1.0)

class ReconModel:
    def predict(self, features: FlowFeatures) -> float:
        return min(max(features.dst_port_fan_out * 0.4 + features.syn_no_ack_ratio * 0.4, 0.0), 1.0)

class DataExfiltrationModel:
    def predict(self, features: FlowFeatures) -> float:
        return min(max(features.byte_ratio * 0.5 + features.outbound_total * 0.3, 0.0), 1.0)

class L1AggregatorModel:
    def predict(self, scores: L1ThreatScores) -> Dict[str, Any]:
        # Simple logistic regression mock
        threats = {
            "DDoS": scores.ddos,
            "C2_Beaconing": scores.c2_beaconing,
            "DGA": scores.dga,
            "Encrypted_Malware": scores.encrypted_malware,
            "Recon": scores.recon,
            "Data_Exfiltration": scores.data_exfiltration
        }

        highest_threat = max(threats.items(), key=lambda x: x[1])
        return {
            "threat_class": highest_threat[0],
            "confidence": highest_threat[1]
        }

class TemporalDependencyModel:
    def predict(self, bucket_features: Dict[str, float]) -> int:
        # Takes bucket summary features: streak_length, vote_count, confidence_trend_slope
        # Returns 1 (KEEP) or 0 (DISCARD)
        streak_length = bucket_features.get("streak_length", 0)
        vote_count = bucket_features.get("vote_count", 0)

        if streak_length >= 3 or vote_count >= 2:
            return 1
        return 0
