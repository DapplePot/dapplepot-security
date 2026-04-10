"""Attack chain detection for v3 scoring.

Detects when multiple signals from a known attack chain all fired
in the same session, warranting score amplification.
"""
from core.config import ATTACK_CHAINS


def detect_attack_chains(fired_signal_ids: set[str]) -> tuple[list[str], float]:
    """
    Check fired_signal_ids against ATTACK_CHAINS.

    Returns:
        (chains_detected, amplification_factor)
        amplification_factor = max(matching chain amplifications), not product.
    """
    chains_detected: list[str] = []
    amplification = 1.0

    for chain_name, chain_def in ATTACK_CHAINS.items():
        if chain_def["signals"].issubset(fired_signal_ids):
            chains_detected.append(chain_name)
            amplification = max(amplification, chain_def["amplification"])

    return chains_detected, amplification
