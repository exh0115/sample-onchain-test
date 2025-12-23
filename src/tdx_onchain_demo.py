#!/usr/bin/env python3
"""
TDX Onchain Demo Script

A sequential demo that:
1. Gets and displays the golden measurement & CVM identity hash
2. Registers with Solidity verification
3. Registers with SP1 ZK verification
4. Signs a message and verifies CVM signature on-chain (if AUTH_CONTRACT_ADDR is set)
5. Sleeps forever (keeps container alive)

Environment variables:
  PRIVATE_KEY            - Private key for signing transactions (required)
  SP1_PRIVATE_KEY        - SP1 prover private key with funds (optional, skips SP1 demo if not set)
  SEPOLIA_RPC            - Sepolia RPC URL (optional, default: https://1rpc.io/sepolia)
  AUTH_CONTRACT_ADDR     - Application auth contract address (optional, skips CVM verification and signature check demo if not set)
"""

import base64
import json
import os
import sys
import time
import traceback

import requests
from web3 import Web3

# Configuration
AGENT_URL = "http://localhost:7999"  # CVM agent endpoint (inside VM)
AGENT_URL_TLS = "https://localhost:8000"  # CVM agent TLS endpoint (self-signed)
SEPOLIA_RPC = os.environ.get("SEPOLIA_RPC", "https://1rpc.io/sepolia")
SEPOLIA_CHAIN_ID = 11155111
CVM_REGISTRY_CONTRACT = "0xE626f5503B455F775AA9845843B46033a26A635d"  # Sepolia

# SP1 ZK config for TDX
TDX_SP1_IMAGE_ID = "4114543f15a8197e675a4e046aef08ac64beb9692250e7a33561aa772aea9f26"
TDX_SP1_VERSION = "v5.0.0"

STEP_DELAY = 5  # seconds between steps


def log(msg: str) -> None:
    print(f"[DEMO] {msg}", flush=True)


def sleep_forever() -> None:
    """Sleep forever to keep container alive."""
    while True:
        time.sleep(3600)


def die(msg: str) -> None:
    """Print error and sleep forever (keeps container alive for debugging)."""
    print(f"[ERROR] {msg}", file=sys.stderr, flush=True)
    print("[ERROR] Sleeping forever to keep container alive for debugging...", flush=True)
    sleep_forever()


def get_golden_measurement() -> str:
    """Fetch golden measurement from CVM agent (TLS endpoint, self-signed cert)."""
    resp = requests.get(f"{AGENT_URL_TLS}/onchain/golden-measurement", timeout=30, verify=False)
    resp.raise_for_status()
    data = resp.json()
    return data.get("golden_measurement", "")


def get_cvm_identity_hash() -> str:
    """Fetch current CVM identity hash from CVM agent (returns hex string)."""
    resp = requests.get(f"{AGENT_URL}/current-cvm-identity-hash", timeout=30)
    resp.raise_for_status()
    data = resp.json()
    hash_b64 = data.get("cvm_identity_hash", "")
    hash_bytes = base64.b64decode(hash_b64)
    return "0x" + hash_bytes.hex()


def sign_message(message: str) -> tuple[bytes, bytes]:
    """
    Request the CVM agent to sign a message.

    Args:
        message: The message string to sign

    Returns:
        Tuple of (cvm_identity_hash, signature) as raw bytes
    """
    payload = {"message": message}

    resp = requests.post(
        f"{AGENT_URL}/sign-message",
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    cvm_identity_hash_b64 = data.get("cvm_identity_hash", "")
    signature_b64 = data.get("signature", "")

    if not cvm_identity_hash_b64 or not signature_b64:
        raise ValueError("Missing cvm_identity_hash or signature in response")

    cvm_identity_hash = base64.b64decode(cvm_identity_hash_b64)
    signature = base64.b64decode(signature_b64)

    return cvm_identity_hash, signature


def get_registration_collaterals(mode: str, sp1_pk: str = None) -> bytes:
    """
    Fetch registration collaterals from CVM agent.

    Args:
        mode: "solidity" (report_type=1) or "sp1" (report_type=2)
        sp1_pk: SP1 prover private key (required for sp1 mode)

    Returns:
        Raw calldata bytes
    """
    if mode == "solidity":
        params = {"report_type": 1}
    elif mode == "sp1":
        params = {
            "report_type": 2,
            "zk_config": {
                "image_id": TDX_SP1_IMAGE_ID,
                "url": "",
                "api_key": sp1_pk,
                "version": TDX_SP1_VERSION,
            }
        }
    else:
        raise ValueError(f"Unknown mode: {mode}")

    log(f"Request params: {json.dumps(params, indent=2)}")

    resp = requests.post(
        f"{AGENT_URL}/onchain/registration-collaterals",
        json=params,
        timeout=300,  # ZK proof can take a while
    )
    resp.raise_for_status()
    data = resp.json()

    calldata_b64 = data.get("calldata", "")
    if not calldata_b64:
        raise ValueError("No calldata in response")

    return base64.b64decode(calldata_b64)


def send_tx(w3: Web3, private_key: str, contract_address: str, calldata: bytes) -> str:
    """Send transaction to smart contract."""
    acct = w3.eth.account.from_key(private_key)
    from_addr = acct.address
    to_addr = Web3.to_checksum_address(contract_address)

    log(f"Sender: {from_addr}")
    log(f"Contract: {to_addr}")
    log(f"Calldata size: {len(calldata)} bytes")

    nonce = w3.eth.get_transaction_count(from_addr)

    try:
        gas_limit = w3.eth.estimate_gas({
            "from": from_addr,
            "to": to_addr,
            "data": calldata,
        })
    except Exception as e:
        log(f"Gas estimation failed ({e}), using default 10M")
        gas_limit = 10_000_000

    block = w3.eth.get_block("pending")
    base_fee = block.get("baseFeePerGas", w3.to_wei(10, "gwei"))
    priority_fee = w3.to_wei(2, "gwei")
    max_fee = base_fee * 2 + priority_fee

    tx = {
        "from": from_addr,
        "to": to_addr,
        "data": calldata,
        "nonce": nonce,
        "gas": gas_limit,
        "chainId": SEPOLIA_CHAIN_ID,
        "maxFeePerGas": int(max_fee),
        "maxPriorityFeePerGas": int(priority_fee),
    }

    log(f"Gas limit: {gas_limit}")
    log("Signing and sending transaction...")

    signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

    log(f"Transaction sent: 0x{tx_hash.hex()}")
    log("Waiting for confirmation...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt["status"] == 1:
        log("Transaction confirmed successfully!")
    else:
        log("Transaction failed!")

    return tx_hash.hex()


def step_golden_measurement_and_identity(w3: Web3, pk: str, auth_contract: str = None) -> None:
    """Step 1: Get and display golden measurement and VM identity."""
    print()
    print("=" * 70)
    print("STEP 1: Golden Measurement & VM Identity")
    print("=" * 70)

    log("Fetching golden measurement...")
    gm = get_golden_measurement()

    log("Fetching CVM identity hash...")
    identity_hash = get_cvm_identity_hash()

    print()
    print("*" * 70)
    print("Golden Measurement:")
    print()
    print(f"  {gm}")
    print()
    print("Current CVM Identity Hash:")
    print()
    print(f"  {identity_hash}")
    print("*" * 70)
    print()

    # Register golden measurement with auth contract if provided
    # Note that this is just an example to show how golden measurements can be registered
    # It does not need to be registered from within the CVM.
    if auth_contract:
        log(f"Registering golden measurement with auth contract: {auth_contract}")

        # Convert golden measurement hex string to bytes32
        gm_bytes = bytes.fromhex(gm.replace("0x", ""))

        # ABI encode addGoldenMeasurement(bytes32)
        func_selector = Web3.keccak(text="addGoldenMeasurement(bytes32)")[:4]
        from eth_abi import encode
        encoded_params = encode(["bytes32"], [gm_bytes])
        calldata = func_selector + encoded_params

        try:
            tx_hash = send_tx(w3, pk, auth_contract, calldata)
            print()
            print(f"Golden measurement registered! TX: 0x{tx_hash}")
            print(f"Explorer: https://sepolia.etherscan.io/tx/0x{tx_hash}")
            print()
        except Exception as e:
            # May fail if already registered, which is fine
            log(f"Note: addGoldenMeasurement failed (may already be registered): {e}")
    else:
        print("Please register this Golden Measurement with your")
        print("Application Auth Contract!")


def step_register_solidity(w3: Web3, contract: str, pk: str) -> None:
    """Step 2: Register with Solidity verification."""
    print()
    print("=" * 70)
    print("STEP 2: Registration with Solidity Verification")
    print("=" * 70)

    log("Fetching registration collaterals (Solidity mode)...")
    calldata = get_registration_collaterals("solidity")
    log(f"Got calldata: {len(calldata)} bytes")

    log("Sending registration transaction...")
    tx_hash = send_tx(w3, pk, contract, calldata)

    print()
    print(f"Transaction hash: 0x{tx_hash}")
    print(f"Explorer: https://sepolia.etherscan.io/tx/0x{tx_hash}")
    print()


def step_register_sp1(w3: Web3, contract: str, pk: str, sp1_pk: str) -> None:
    """Step 3: Register with SP1 ZK verification."""
    print()
    print("=" * 70)
    print("STEP 3: Registration with SP1 ZK Verification")
    print("=" * 70)

    log("Fetching registration collaterals (SP1 mode)...")
    log("This may take a few minutes for ZK proof generation...")
    calldata = get_registration_collaterals("sp1", sp1_pk)
    log(f"Got calldata: {len(calldata)} bytes")

    log("Sending registration transaction...")
    tx_hash = send_tx(w3, pk, contract, calldata)

    print()
    print(f"Transaction hash: 0x{tx_hash}")
    print(f"Explorer: https://sepolia.etherscan.io/tx/0x{tx_hash}")
    print()


def step_cvm_signature(w3: Web3, auth_contract: str = None) -> None:
    """Step 4: CVM Signature - sign message and optionally verify on-chain."""
    print()
    print("=" * 70)
    print("STEP 4: CVM Signature")
    print("=" * 70)

    message = "EXAMPLE_MESSAGE"
    message_bytes = message.encode("utf-8")

    log(f"Message to sign: {message}")
    log("Requesting signature from CVM agent...")

    cvm_identity_hash, signature = sign_message(message)

    # Build ABI-encoded calldata for checkCVMSignature
    func_selector = Web3.keccak(text="checkCVMSignature(bytes32,bytes,bytes)")[:4]
    from eth_abi import encode
    encoded_params = encode(
        ["bytes32", "bytes", "bytes"],
        [cvm_identity_hash, message_bytes, signature]
    )
    calldata = func_selector + encoded_params

    # Display signing results
    print()
    print("*" * 70)
    print("CVM Signature Results:")
    print()
    print(f"  Message: {message}")
    print(f"  CVM Identity Hash: 0x{cvm_identity_hash.hex()}")
    print(f"  Signature: 0x{signature.hex()}")
    print()
    print("ABI-encoded calldata for checkCVMSignature:")
    print(f"  0x{calldata.hex()}")
    print("*" * 70)
    print()

    # Only verify on-chain if auth contract is provided
    if auth_contract:
        log(f"Verifying signature on auth contract: {auth_contract}")

        auth_contract_addr = Web3.to_checksum_address(auth_contract)

        result = w3.eth.call({
            "to": auth_contract_addr,
            "data": calldata,
        })

        verified = bool(int.from_bytes(result, "big"))

        print()
        print(f"On-chain verification result: {'PASSED' if verified else 'FAILED'}")
        print()
    else:
        log("No AUTH_CONTRACT_ADDR provided, skipping on-chain verification")


def main() -> None:
    print()
    print("#" * 70)
    print("#  TDX Onchain Demo")
    print("#" * 70)
    print()

    try:
        # Load config from environment
        pk = os.environ.get("PRIVATE_KEY")
        sp1_pk = os.environ.get("SP1_PRIVATE_KEY")
        auth_contract = os.environ.get("AUTH_CONTRACT_ADDR")

        if not pk:
            die("PRIVATE_KEY environment variable is required")

        log(f"CVM Registry contract: {CVM_REGISTRY_CONTRACT}")
        log(f"Sepolia RPC: {SEPOLIA_RPC}")
        if sp1_pk:
            log("SP1 prover key: provided (will run SP1 demo)")
        else:
            log("SP1 prover key: not provided (skipping SP1 demo)")
        if auth_contract:
            log(f"Auth contract: {auth_contract} (will verify signature on-chain)")
        else:
            log("Auth contract: not provided (will skip on-chain verification)")
        print()

        # Connect to Sepolia
        log("Connecting to Sepolia...")
        w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC))
        if not w3.is_connected():
            die("Failed to connect to Sepolia RPC")
        log(f"Connected! Chain ID: {w3.eth.chain_id}")

        # Step 1: Golden measurement & VM identity
        step_golden_measurement_and_identity(w3, pk, auth_contract)

        log(f"Waiting {STEP_DELAY}s before next step...")
        time.sleep(STEP_DELAY)

        # Step 2: Solidity registration
        step_register_solidity(w3, CVM_REGISTRY_CONTRACT, pk)

        # Step 3: SP1 registration (only if SP1_PRIVATE_KEY is provided)
        if sp1_pk:
            log(f"Waiting {STEP_DELAY}s before next step...")
            time.sleep(STEP_DELAY)

            step_register_sp1(w3, CVM_REGISTRY_CONTRACT, pk, sp1_pk)
        else:
            print()
            log("Skipping SP1 registration (no SP1_PRIVATE_KEY provided)")

        # Step 4: CVM Signature (always signs, only verifies on-chain if auth contract provided)
        log(f"Waiting {STEP_DELAY}s before next step...")
        time.sleep(STEP_DELAY)

        step_cvm_signature(w3, auth_contract)

        # Done - sleep forever
        print()
        print("#" * 70)
        print("#  Demo Complete - Container staying alive")
        print("#" * 70)
        print()

    except Exception as e:
        print()
        print("#" * 70)
        print("#  ERROR OCCURRED")
        print("#" * 70)
        print(f"[ERROR] {type(e).__name__}: {e}", flush=True)
        print()
        traceback.print_exc()
        print()
        print("[ERROR] Sleeping forever to keep container alive for debugging...", flush=True)

    sleep_forever()


if __name__ == "__main__":
    main()
