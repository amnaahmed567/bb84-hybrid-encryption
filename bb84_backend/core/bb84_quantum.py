# bb84_quantum.py
# BB84 Quantum Key Distribution using Qiskit AerSimulator with optional post-quantum authentication.
# ----------------------------------------------------------------------------
# Copyright 2025 Hector Mozo
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# ----------------------------------------------------------------------------


from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from typing import List, Tuple
import secrets

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
    Randomly assigns measurement bases ('Z' or 'X') for each qubit.
    """
    return [secrets.choice(['Z', 'X']) for _ in range(length)]

def measure_qubit(bit: int, basis: str, measure_basis: str) -> int:
    """
    Simulates the quantum measurement of a single qubit using Qiskit AerSimulator.
    """
    circuit = QuantumCircuit(1, 1)
    
    if bit == 1:
        circuit.x(0)
    if basis == 'X':
        circuit.h(0)

    if measure_basis == 'X':
        circuit.h(0)
    circuit.measure(0, 0)

    simulator = AerSimulator()
    result = simulator.run(circuit, shots=1).result()
    counts = result.get_counts()

    return int(max(counts, key=counts.get))

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
