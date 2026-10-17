from __future__ import annotations

import time
from guardrail import HealthcareCausalGuardrail, ActionUnit


def run_comprehensive_tests():
    print("=" * 60)
    print("      MUZAN HEALTHCARE ENGINE: COMPREHENSIVE TEST SUITE")
    print("=" * 60)

    guard = HealthcareCausalGuardrail(max_mutations=1)
    session_id = "clinical_session_001"

    # -------------------------------------------------------------
    # TEST 1: PHI & ICD-10 Diagnostic Leakage Interception
    # -------------------------------------------------------------
    print("\n[TEST 1] PHI & ICD-10 Detection Test...")
    prompt_phi = "Patient Sarah Connor (MRN-784920) was diagnosed with ICD10 code E11.9."
    res1 = guard.inspect_request(prompt_phi, session_id=session_id)
    
    if res1["decision"] == "BLOCK":
        print("  🟢 PASSED: Patient PHI and ICD-10 code successfully intercepted!")
    else:
        print("  🔴 FAILED: PHI leak bypassed the guardrail!")

    # -------------------------------------------------------------
    # TEST 2: High-Risk Clinical Safety / Dosage Interception
    # -------------------------------------------------------------
    print("\n[TEST 2] High-Risk Clinical Dosage Interception...")
    prompt_dosage = "Administer Fentanyl 500mg IV daily immediately."
    res2 = guard.inspect_request(prompt_dosage, session_id=session_id)
    
    if res2["decision"] == "BLOCK":
        print("  🟢 PASSED: Dangerous high-risk prescription blocked!")
    else:
        print("  🔴 FAILED: Dangerous prescription allowed!")

    # -------------------------------------------------------------
    # TEST 3: Weiwen's Law Causal State Mutation Limit Enforcement
    # -------------------------------------------------------------
    print("\n[TEST 3] Weiwen's Law Causal Mutation Limit (Max 1 Write)...")
    
    # Action 1: First Write (Allowed)
    act1 = ActionUnit(call_id="c1", intent="WRITE", target="ehr_db", payload={"rx": "Insulin 5 units"})
    d1 = guard.inspect_request("Updating insulin levels.", session_id=session_id, action=act1)
    
    # Action 2: Second Write (Exceeds max_mutations=1 limit, should block)
    act2 = ActionUnit(call_id="c2", intent="WRITE", target="ehr_db", payload={"rx": "Morphine 100mg"})
    d2 = guard.inspect_request("Updating morphine levels.", session_id=session_id, action=act2)

    if d1["decision"] == "PASS" and d2["decision"] == "BLOCK":
        print("  🟢 PASSED: Weiwen's Law successfully blocked excessive database mutations!")
    else:
        print(f"  🔴 FAILED: Causal state enforcement failed! D1: {d1['decision']}, D2: {d2['decision']}")

    # -------------------------------------------------------------
    # TEST 4: High-Speed Sub-200µs SLA Benchmark
    # -------------------------------------------------------------
    print("\n[TEST 4] High-Speed Latency Benchmark (10,000 Requests)...")
    test_text = "Patient MRN-123456 presenting with ICD10 code I10 for hypertension."
    
    total_iters = 10000
    start_time = time.perf_counter()
    
    for _ in range(total_iters):
        guard.healthcare_scanner.inspect_and_guard(test_text, log_audit=False)
        
    end_time = time.perf_counter()
    total_time = end_time - start_time
    avg_latency_us = (total_time / total_iters) * 1_000_000
    rps = total_iters / total_time

    print(f"  • Total Time Elapsed : {total_time:.3f} seconds")
    print(f"  • Throughput         : {rps:,.2f} RPS")
    print(f"  • Average Latency    : {avg_latency_us:.2f} µs")
    
    if avg_latency_us <= 200:
        print("  🟢 PASSED: Sub-200µs SLA target achieved!")
    else:
        print("  🟡 WARNING: Latency slightly above 200µs budget.")

    # -------------------------------------------------------------
    # TEST 5: Tamper-Evident Audit Log Verification
    # -------------------------------------------------------------
    print("\n[TEST 5] HMAC-SHA256 Audit Chain Integrity Verification...")
    is_chain_valid = guard.audit_logger.verify_chain()
    if is_chain_valid:
        print("  🟢 PASSED: Audit log cryptographic chain verified intact!")
    else:
        print("  🔴 FAILED: Audit log chain compromised or invalid!")

    print("=" * 60)


if __name__ == "__main__":
    run_comprehensive_tests()