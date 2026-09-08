from dataclasses import dataclass
from typing import Dict, Any, List, Optional

@dataclass
class FlowFeatures:
    timestamp: float
    flow_id: str
    rate: float
    syn_ack_ratio: float
    src_ip_entropy: float
    inter_arrival_cv: float
    autocorrelation: float
    fft_peak: float
    entropy: float
    n_gram: float
    query_len: float
    nxdomain: float
    ja3_ja4: float
    size: float
    timing_sequence_stats: float
    dst_port_fan_out: float
    syn_no_ack_ratio: float
    byte_ratio: float
    outbound_total: float
    dest_rarity: float


@dataclass
class L1ThreatScores:
    ddos: float
    c2_beaconing: float
    dga: float
    encrypted_malware: float
    recon: float
    data_exfiltration: float

@dataclass
class L1Output:
    timestamp: float
    flow_id: str
    threat_class: str
    confidence: float
    evidence: L1ThreatScores
    l1_votes: L1ThreatScores


@dataclass
class AlertRecord:
    timestamp: float
    flow_id: str
    threat_class: str
    confidence: float
    severity: float
    evidence: L1ThreatScores
    l1_votes: L1ThreatScores
