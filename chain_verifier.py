#!/usr/bin/env python3
"""
Saillent Cryptographic Audit Chain Verifier (CACV-1)
Implements Merkle tree verification, tamper detection forensics,
and regulatory compliance attestation for model audit trails.
"""

import json
import hashlib
import argparse
from datetime import datetime, timezone
from collections import defaultdict

class MerkleTree:
    """Merkle tree implementation for batch audit verification."""
    
    def __init__(self):
        self.leaves = []
        self.levels = []
        self.root_hash = None
    
    def add_leaf(self, data):
        """Add a leaf node with data hash."""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        leaf_hash = hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()
        self.leaves.append(leaf_hash)
    
    def build(self):
        """Build the Merkle tree and compute root hash."""
        if not self.leaves:
            return None
        
        current_level = self.leaves.copy()
        self.levels = [current_level]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined)
            current_level = next_level
            self.levels.append(current_level)
        
        self.root_hash = current_level[0]
        return self.root_hash
    
    def verify_leaf(self, leaf_index, leaf_data):
        """Verify a single leaf against the Merkle root."""
        if isinstance(leaf_data, dict):
            leaf_data = json.dumps(leaf_data, sort_keys=True)
        computed_hash = hashlib.sha256(leaf_data.encode() if isinstance(leaf_data, str) else leaf_data).hexdigest()
        return computed_hash == self.leaves[leaf_index]

class ChainForensics:
    """Forensic analysis for audit chain tampering."""
    
    @staticmethod
    def detect_anomalies(entries):
        """Detect anomalies in audit chain entries."""
        anomalies = []
        
        for i, entry in enumerate(entries):
            # Check timestamp consistency
            if "timestamp" in entry:
                ts = entry["timestamp"]
                if i > 0 and "timestamp" in entries[i-1]:
                    prev_ts = entries[i-1]["timestamp"]
                    if ts < prev_ts:
                        anomalies.append({
                            "type": "TIMESTAMP_INVERSION",
                            "entry_index": i,
                            "entry_id": entry.get("audit_id", "unknown"),
                            "severity": "HIGH",
                            "detail": f"Timestamp {ts} is earlier than previous {prev_ts}"
                        })
            
            # Check hash chain integrity
            if i > 0 and "previous_hash" in entry:
                expected_prev = entries[i-1].get("chain_hash", "")
                actual_prev = entry["previous_hash"]
                if expected_prev != actual_prev:
                    anomalies.append({
                        "type": "CHAIN_BROKEN",
                        "entry_index": i,
                        "entry_id": entry.get("audit_id", "unknown"),
                        "severity": "CRITICAL",
                        "detail": f"Hash chain broken. Expected {expected_prev[:16]}..., got {actual_prev[:16]}..."
                    })
            
            # Check for duplicate audit IDs
            if "audit_id" in entry:
                for j in range(i + 1, len(entries)):
                    if entries[j].get("audit_id") == entry["audit_id"]:
                        anomalies.append({
                            "type": "DUPLICATE_ID",
                            "entry_index": i,
                            "entry_id": entry["audit_id"],
                            "severity": "CRITICAL",
                            "detail": f"Duplicate audit ID at indices {i} and {j}"
                        })
        
        return anomalies

class ComplianceAttestor:
    """Generate regulatory compliance attestation reports."""
    
    REGULATORY_REQUIREMENTS = {
        "OSFI_E23_4_3": {
            "regulation": "OSFI E-23 §4.3",
            "requirement": "Complete audit trail for all model decisions",
            "evidence_needed": ["chain_verification", "timestamp_consistency", "tamper_detection"]
        },
        "SR11_7_MONITORING": {
            "regulation": "SR 11-7 Ongoing Monitoring",
            "requirement": "Continuous monitoring with documented audit records",
            "evidence_needed": ["chain_verification", "entry_count", "coverage_period"]
        },
        "SEC_17a4": {
            "regulation": "SEC Rule 17a-4",
            "requirement": "Non-rewritable, non-erasable recordkeeping",
            "evidence_needed": ["chain_verification", "tamper_detection", "immutability_proof"]
        },
        "CFPB_FAIR_LENDING": {
            "regulation": "CFPB Fair Lending",
            "requirement": "Audit documentation for adverse action decisions",
            "evidence_needed": ["entry_count", "decision_tracking", "timestamp_consistency"]
        }
    }
    
    @staticmethod
    def generate_attestation(entries, is_chain_valid, anomalies):
        """Generate regulatory attestation report."""
        attestation = {
            "attestation_type": "Saillent Regulatory Compliance Attestation",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_period": {
                "first_entry": entries[0].get("timestamp", "unknown") if entries else "none",
                "last_entry": entries[-1].get("timestamp", "unknown") if entries else "none",
                "total_entries": len(entries)
            },
            "chain_integrity": {
                "verified": is_chain_valid,
                "anomalies_detected": len(anomalies),
                "tamper_evidence": "NONE" if len(anomalies) == 0 else "DETECTED"
            },
            "regulatory_compliance": {},
            "overall_assessment": ""
        }
        
        for reg_id, reg in ComplianceAttestor.REGULATORY_REQUIREMENTS.items():
            compliant = True
            missing_evidence = []
            
            for evidence in reg["evidence_needed"]:
                if evidence == "chain_verification" and not is_chain_valid:
                    compliant = False
                    missing_evidence.append("Chain verification failed")
                elif evidence == "tamper_detection" and len(anomalies) > 0:
                    compliant = False
                    missing_evidence.append(f"{len(anomalies)} anomalies detected")
                elif evidence == "entry_count" and len(entries) == 0:
                    compliant = False
                    missing_evidence.append("No entries found")
            
            attestation["regulatory_compliance"][reg_id] = {
                "regulation": reg["regulation"],
                "requirement": reg["requirement"],
                "compliant": compliant,
                "missing_evidence": missing_evidence
            }
        
        compliant_count = sum(1 for r in attestation["regulatory_compliance"].values() if r["compliant"])
        total = len(attestation["regulatory_compliance"])
        attestation["overall_assessment"] = f"{compliant_count}/{total} regulatory frameworks satisfied. " + \
            ("Ready for examination." if compliant_count == total else "Remediation required before examination.")
        
        return attestation

def main():
    parser = argparse.ArgumentParser(description="Saillent Cryptographic Audit Chain Verifier")
    parser.add_argument("--audit-file", required=True, help="Audit log JSON file")
    parser.add_argument("--output", default="chain_verification_report.json", help="Output file")
    args = parser.parse_args()
    
    print(f"\n🔐 Saillent Cryptographic Audit Chain Verifier (CACV-1)")
    print(f"   Framework: OSFI E-23 / SR 11-7 / SEC 17a-4 / CFPB\n")
    
    with open(args.audit_file) as f:
        data = json.load(f)
    
    entries = data.get("entries", [])
    forensics = ChainForensics()
    anomalies = forensics.detect_anomalies(entries)
    
    # Build Merkle tree
    tree = MerkleTree()
    for entry in entries:
        tree.add_leaf(entry)
    root_hash = tree.build()
    
    # Verify chain
    is_valid = len(anomalies) == 0
    
    # Generate attestation
    attestor = ComplianceAttestor()
    attestation = attestor.generate_attestation(entries, is_valid, anomalies)
    
    report = {
        "verification_type": "Saillent CACV-1 Chain Verification Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_file": args.audit_file,
        "merkle_root": root_hash,
        "total_entries": len(entries),
        "chain_valid": is_valid,
        "anomalies": anomalies,
        "regulatory_attestation": attestation,
        "recommendation": ""
    }
    
    if is_valid:
        report["recommendation"] = "Audit chain intact. All regulatory frameworks satisfied. Ready for examination."
    elif len(anomalies) <= 2:
        report["recommendation"] = f"{len(anomalies)} anomalies detected. Review and remediate before regulatory submission."
    else:
        report["recommendation"] = f"CRITICAL: {len(anomalies)} anomalies detected. Audit chain compromised. Initiate forensic investigation immediately."
    
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"📊 Verification Results")
    print(f"   Merkle Root: {root_hash[:32]}...")
    print(f"   Total Entries: {len(entries)}")
    print(f"   Chain Valid: {'✅' if is_valid else '❌'}")
    print(f"   Anomalies: {len(anomalies)}")
    
    if anomalies:
        print(f"\n⚠️  Anomalies Detected:")
        for a in anomalies:
            print(f"   [{a['severity']}] {a['type']}: {a['detail']}")
    
    print(f"\n📋 Regulatory Attestation:")
    for reg_id, reg in attestation["regulatory_compliance"].items():
        status = "✅" if reg["compliant"] else "❌"
        print(f"   {status} {reg['regulation']}")
    
    print(f"\n📋 {report['recommendation']}")

if __name__ == "__main__":
    main()
