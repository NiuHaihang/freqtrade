"""
Pickle / model file integrity verification module.

Provides HMAC-SHA256 based integrity checks for serialized model files
(cloudpickle, torch, etc.) to mitigate deserialization attacks (CWE-502).

The HMAC key is machine-local, generated once and stored alongside
the FreqAI data directory.
"""

import hashlib
import hmac
import logging
from pathlib import Path


logger = logging.getLogger(__name__)

# Suffix appended to create the HMAC sidecar file
_HMAC_SUFFIX = ".hmac"
_HMAC_KEY_FILENAME = ".freqai_hmac_key"


def _get_or_create_hmac_key(data_dir: Path) -> bytes:
    """
    Retrieve or generate a machine-local HMAC key.

    The key is stored in the FreqAI data directory as a hidden file.
    On first run, a random 32-byte key is generated and persisted.

    :param data_dir: Root directory of the FreqAI data (e.g., user_data/models/)
    :return: HMAC key bytes
    """
    key_path = data_dir / _HMAC_KEY_FILENAME
    if key_path.is_file():
        return key_path.read_bytes()

    import secrets

    key = secrets.token_bytes(32)
    # Ensure parent directory exists
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key)
    logger.info(f"Generated new HMAC key at {key_path}")
    return key


def compute_file_hmac(file_path: Path, key: bytes) -> str:
    """
    Compute HMAC-SHA256 digest for a file.

    :param file_path: Path to the file to hash
    :param key: HMAC key bytes
    :return: Hex-encoded HMAC digest
    """
    h = hmac.new(key, digestmod=hashlib.sha256)
    with file_path.open("rb") as fp:
        while chunk := fp.read(8192):
            h.update(chunk)
    return h.hexdigest()


def save_hmac_signature(file_path: Path, key: bytes) -> None:
    """
    Compute and save an HMAC signature sidecar file for the given file.

    The signature is stored at ``<file_path>.hmac``.

    :param file_path: Path to the file to sign
    :param key: HMAC key bytes
    """
    digest = compute_file_hmac(file_path, key)
    hmac_path = Path(str(file_path) + _HMAC_SUFFIX)
    hmac_path.write_text(digest, encoding="utf-8")


def verify_hmac_signature(file_path: Path, key: bytes) -> bool:
    """
    Verify the HMAC signature of a file.

    If the sidecar ``.hmac`` file does not exist (legacy data), a warning is
    logged and the file is treated as unverified but still allowed to load
    for backward compatibility.

    :param file_path: Path to the file to verify
    :param key: HMAC key bytes
    :return: True if signature is valid or missing (legacy), False if tampered
    """
    hmac_path = Path(str(file_path) + _HMAC_SUFFIX)

    if not hmac_path.is_file():
        logger.warning(
            f"SECURITY WARNING - No HMAC signature found for '{file_path}'. "
            "This file may be from a previous version. "
            "Re-saving will create a signature for future verification."
        )
        # Allow loading for backward compatibility
        return True

    expected_digest = hmac_path.read_text(encoding="utf-8").strip()
    actual_digest = compute_file_hmac(file_path, key)

    if not hmac.compare_digest(expected_digest, actual_digest):
        logger.error(
            f"SECURITY ERROR - HMAC verification FAILED for '{file_path}'. "
            "The file may have been tampered with. Refusing to load."
        )
        return False

    return True
