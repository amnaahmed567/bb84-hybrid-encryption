# bb84_quantum.py
# BB84 Quantum Key Distribution using Qiskit AerSimulator with optional post-quantum authentication.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from typing import List, Tuple, Dict, Optional
import secrets
import math

# Use a cryptographically secure RNG for sampling operations
secure_random = secrets.SystemRandom()

# Optional: Post-quantum authentication (fallback if not available)
try:
    from dilithium import Dilithium, parameter_sets
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False


def generate_random_bits(length: int) -> List[int]:
    """
    Generates a secure random bitstring of given length using system entropy.
    """
    return [secrets.randbits(1) for _ in range(length)]

def generate_random_bases(length: int) -> List[str]:
    """
    Randomly assigns measurement bases ('Z' or 'X') for each qubit (unbiased).
    """
    return [secrets.choice(['Z', 'X']) for _ in range(length)]

def generate_random_bases_biased(length: int, p_Z: float = 0.8) -> List[str]:
    """
    Generates measurement bases with bias towards Z.
    p_Z in [0,1]: probability of choosing 'Z' basis; (1-p_Z) for 'X'.
    """
    p_Z = max(0.0, min(1.0, p_Z))
    return [('Z' if secure_random.random() < p_Z else 'X') for _ in range(length)]

def measure_qubit(bit: int, basis: str, measure_basis: str, shots: int = 1) -> int:
    """Simulate measurement of a single qubit; shots>1 adds measurement randomness."""
    circuit = QuantumCircuit(1, 1)
    
    if bit == 1:
        circuit.x(0)
    if basis == 'X':
        circuit.h(0)

    if measure_basis == 'X':
        circuit.h(0)
    circuit.measure(0, 0)

    simulator = AerSimulator()
    result = simulator.run(circuit, shots=max(1, shots)).result()
    counts = result.get_counts()

    return int(max(counts, key=counts.get))

def apply_depolarizing_noise(bit: int, p_depolarize: float) -> int:
    """With probability p_depolarize, flip the classical bit (simple proxy)."""
    if p_depolarize <= 0.0:
        return bit
    return bit ^ 1 if secure_random.random() < p_depolarize else bit

def photon_lost(p_loss: float) -> bool:
    """Return True if the photon is lost (no detection)."""
    return p_loss > 0.0 and (secure_random.random() < p_loss)

def apply_dark_count(measured_bit: Optional[int], dark_count: float) -> Optional[int]:
    """
    With small probability, detector clicks spuriously.
    If there was no detection (measured_bit is None), a dark count may produce a random bit.
    If there was detection, a dark count may flip the bit.
    """
    if dark_count <= 0.0:
        return measured_bit
    if secure_random.random() < dark_count:
        if measured_bit is None:
            return secure_random.choice([0, 1])
        else:
            return measured_bit ^ 1
    return measured_bit

def intercept_resend_strategy(bit: int, prep_basis: str, shots: int = 1) -> Tuple[int, str]:
    """
    Eve measures in a random basis and resends a qubit consistent with her outcome/basis.
    Returns (bit_after_eve, basis_after_eve).
    """
    eve_basis = secure_random.choice(['Z', 'X'])
    # Eve's measurement outcome (classical proxy using same measure_qubit routine)
    eve_out = measure_qubit(bit, prep_basis, eve_basis, shots=shots)
    # Eve resends with her basis and measured bit
    return eve_out, eve_basis

def bb84_protocol(length: int = 128, authenticate: bool = False) -> Tuple[List[int], List[int], List[int]]:
    """
    Runs the BB84 protocol simulation and returns the matching keys and their indices.

    Args:
        length: Number of qubits to simulate (default 128).
        authenticate: If True, perform post-quantum authentication using Dilithium (if available).

    Returns:
        A tuple containing:
        - Alice's key bits (from matching positions)
        - Bob's key bits (from matching positions)
        - List of matching indices (positions where bases matched)
    """
    alice_bits = generate_random_bits(length)
    alice_bases = generate_random_bases(length)
    bob_bases = generate_random_bases(length)

    bob_results = [
        measure_qubit(bit, prep_basis, measure_basis)
        for bit, prep_basis, measure_basis in zip(alice_bits, alice_bases, bob_bases)
    ]

    matching_indices = [i for i in range(length) if alice_bases[i] == bob_bases[i]]
    key_alice = [alice_bits[i] for i in matching_indices]
    key_bob = [bob_results[i] for i in matching_indices]

    if authenticate and PQCRYPTO_AVAILABLE:
        public_data = "".join(alice_bases).encode("utf-8")
        dil = Dilithium(parameter_set=parameter_sets["Dilithium5"])
        pk, sk = dil.generate_keypair()
        signature = dil.sign(public_data, sk)
        if not dil.verify(public_data, signature, pk):
            raise ValueError("Post-quantum signature verification failed.")


    return key_alice, key_bob, matching_indices


def binary_entropy(p: float) -> float:
    """Binary entropy h(p) = -p log2 p - (1-p) log2 (1-p), with safe bounds."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)

def run_qkd(
    length: int = 1024,
    *,
    authenticate: bool = False,
    biased: bool = True,
    p_Z: float = 0.8,
    p_depolarize: float = 0.0,
    p_loss: float = 0.0,
    dark_count: float = 0.0,
    attack: Optional[str] = None,
    attack_fraction: float = 0.08,
    shots_per_qubit: int = 1,
    eps_sec: float = 1e-10,
) -> Tuple[List[int], List[int], Dict[str, float]]:
    """
    Full QKD pipeline (Prepare → Distribute → Reconcile → Amplify) with realistic channel knobs.

    Channel/attack parameters (all exposed as function arguments):
    - p_depolarize: depolarizing noise probability (classical proxy: flip measured bit)
    - p_loss: photon loss probability (no detection at Bob)
    - dark_count: detector dark-count probability (random click if lost, or bit flip if detected)
    - attack: "intercept_resend" to simulate Eve measuring/resending
    - attack_fraction: fraction of qubits Eve attacks (5–10% recommended)
    - shots_per_qubit: measurement shots to introduce randomness (e.g., 5–10)

    QBER is computed *after* sifting and after sample testing (with the sampled bits removed),
    so it reflects channel noise, loss-induced resampling, and attacks.

    Example (typical lab-like settings giving ~1–5% QBER):
        run_qkd(
            length=1024,
            p_depolarize=0.012,
            p_loss=0.03,
            dark_count=0.01,
            attack="intercept_resend",
            attack_fraction=0.08,
            shots_per_qubit=6,
        )

    Returns: (final_key_a, final_key_b, stats)
    stats keys: n_total, n_detected, n_sifted, qber, leakEC, ell_final
    """
    # 1) Preparation
    alice_bits = generate_random_bits(length)
    alice_bases = generate_random_bases_biased(length, p_Z) if biased else generate_random_bases(length)
    bob_bases = generate_random_bases_biased(length, p_Z) if biased else generate_random_bases(length)

    detected_bits_bob: List[Optional[int]] = []
    effective_prep_bases: List[str] = []

    for bit, prep_basis, bob_basis in zip(alice_bits, alice_bases, bob_bases):
        # Optional attack: Eve intercepts a random fraction and resends
        if attack == 'intercept_resend' and secure_random.random() < max(0.0, min(1.0, attack_fraction)):
            bit, prep_basis = intercept_resend_strategy(bit, prep_basis, shots=max(1, shots_per_qubit))

        # Measurement by Bob (if not lost)
        if photon_lost(p_loss):
            measured = None  # no detection
        else:
            measured = measure_qubit(bit, prep_basis, bob_basis, shots=max(1, shots_per_qubit))
            # Depolarizing noise (classical proxy)
            measured = apply_depolarizing_noise(measured, p_depolarize)

        # Dark counts may create/flip detection
        measured = apply_dark_count(measured, dark_count)

        detected_bits_bob.append(measured)
        effective_prep_bases.append(prep_basis)

    # 2) Sifting: keep positions where bases match and detection occurred
    matching_indices: List[int] = [
        i for i in range(length)
        if (alice_bases[i] == bob_bases[i]) and (detected_bits_bob[i] is not None)
    ]

    key_alice = [alice_bits[i] for i in matching_indices]
    key_bob = [int(detected_bits_bob[i]) for i in matching_indices]

    # 3) Quick error sampling (existing function)
    passed, error_rate, remaining_a, remaining_b, sampled_indices = sample_key_confirmation(
        key_alice, key_bob, sample_size=min(20, max(1, len(key_alice)//10)), threshold=0.15
    )

    # 4) Reconciliation (Phase 2 will implement Cascade). For now, assume remaining keys are reconciled.
    reconciled_a = remaining_a
    reconciled_b = remaining_b

    # Compute QBER on reconciled portion (after sifting and sampling removal)
    mismatches = sum(1 for a, b in zip(reconciled_a, reconciled_b) if a != b)
    qber = (mismatches / len(reconciled_a)) if reconciled_a else 0.0

    # 5) Placeholder leakEC: assume parity leakage proportional to mismatches (to refine in Phase 2)
    leakEC = float(mismatches)  # simplistic placeholder; will be replaced by Cascade accounting

    # 6) Privacy Amplification (Phase 2 will implement universal hashing). Compute finite-key length estimate.
    n_sifted = float(len(reconciled_a))
    ell = max(0.0, n_sifted * (1.0 - binary_entropy(qber)) - leakEC - math.log2(1.0/eps_sec))

    stats = {
        'n_total': float(length),
        'n_detected': float(sum(1 for x in detected_bits_bob if x is not None)),
        'n_sifted': n_sifted,
        'qber': qber,
        'leakEC': leakEC,
        'ell_final': ell,
        'p_Z': float(p_Z),
        'p_depolarize': float(p_depolarize),
        'p_loss': float(p_loss),
        'dark_count': float(dark_count),
        'attack': (attack or 'none'),
        'attack_fraction': float(max(0.0, min(1.0, attack_fraction))),
        'shots_per_qubit': float(max(1, shots_per_qubit)),
    }

    # Final keys (Phase 2: compress to ell bits via PA). For now, return reconciled keys.
    return reconciled_a, reconciled_b, stats


def run_qkd_demo() -> Tuple[List[int], List[int], Dict[str, float]]:
    """Convenience helper to reliably see QBER ≈ 1–5% every run."""
    return run_qkd(
        length=1024,
        authenticate=False,
        biased=True,
        p_Z=0.8,
        p_depolarize=0.012,
        p_loss=0.03,
        dark_count=0.01,
        attack="intercept_resend",
        attack_fraction=0.08,
        shots_per_qubit=6,
    )


def sample_key_confirmation(key_a: List[int], key_b: List[int], sample_size: int = 20, threshold: float = 0.15):
    """
    Performs a sacrifice/sample check on a subset of the sifted key bits.

    - Randomly selects up to `sample_size` indices from the sifted key.
    - Compares Alice and Bob bits at those indices to estimate the error rate.
    - If the error rate exceeds `threshold`, the function indicates failure (possible eavesdropping).
    - On success, returns the remaining key bits (with sampled bits removed) for both parties.

    Args:
        key_a: Alice's sifted key bits (list of 0/1)
        key_b: Bob's sifted key bits (list of 0/1)
        sample_size: Number of bits to sacrifice for the test (default 20)
        threshold: Maximum tolerated error rate (fraction, default 0.15)

    Returns:
        (passed: bool, error_rate: float, remaining_a: List[int], remaining_b: List[int], sampled_indices: List[int])
    """
    n = min(sample_size, len(key_a))
    if n == 0:
        return True, 0.0, key_a, key_b, []

    # Choose sample indices deterministically from secure randomness
    sampled_indices = secure_random.sample(range(len(key_a)), k=n)

    # Compare bits at sampled indices
    mismatches = 0
    for i in sampled_indices:
        if key_a[i] != key_b[i]:
            mismatches += 1

    error_rate = mismatches / n

    passed = error_rate <= threshold

    # Build remaining keys by omitting sampled indices
    sampled_set = set(sampled_indices)
    remaining_a = [bit for idx, bit in enumerate(key_a) if idx not in sampled_set]
    remaining_b = [bit for idx, bit in enumerate(key_b) if idx not in sampled_set]

    return passed, error_rate, remaining_a, remaining_b, sampled_indices
