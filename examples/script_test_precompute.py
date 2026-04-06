import argparse
import json
import sys
from pathlib import Path
import time
from typing import List, Union

import tomllib



sys.path.append(str(Path(__file__).resolve().parent.parent))

from elliptic_curves.data_structures.proof import Proof
from elliptic_curves.data_structures.vk import VerifyingKey
from elliptic_curves.instantiations.bls12_381.bls12_381 import BLS12_381, ProofBls12381, VerifyingKeyBls12381
from elliptic_curves.instantiations.mnt4_753.mnt4_753 import MNT4_753, ProofMnt4753, VerifyingKeyMnt4753
from elliptic_curves.models.bilinear_pairings import BilinearPairingCurve
from tx_engine import SIGHASH, Context, Script, Tx, TxIn, TxOut, Wallet, address_to_public_key_hash, p2pkh_script
from tx_engine.interface.interface_factory import InterfaceFactory
from tx_engine.interface.verify_script import ScriptFlags, verifyscript_params

from src.zkscript.groth16.bls12_381.bls12_381 import bls12_381 as bls12_381_groth
from src.zkscript.groth16.mnt4_753.mnt4_753 import mnt4_753 as mnt4_753_groth
from src.zkscript.groth16.model.groth16 import Groth16
from src.zkscript.script_types.locking_keys.groth16 import Groth16LockingKey
from src.zkscript.script_types.unlocking_keys.groth16 import Groth16UnlockingKey, Groth16UnlockingKeyWithPrecomputedMsm
from src.zkscript.util.utility_scripts import nums_to_script

verification_flags = 1
for f in ScriptFlags._member_names_[1:-2]:
    verification_flags |= ScriptFlags._member_map_[f]


def curve_setup(curve_arg: str) -> Union[BilinearPairingCurve, VerifyingKey, Proof, Groth16]:
    """Map command line curve argument to Python curve."""
    match curve_arg:
        case "bls12_381":
            curve = BLS12_381
            groth16_script = bls12_381_groth
            vk_type = VerifyingKeyBls12381
            proof_type = ProofBls12381
        case "mnt4_753":
            curve = MNT4_753
            groth16_script = mnt4_753_groth
            vk_type = VerifyingKeyMnt4753
            proof_type = ProofMnt4753
        case _:
            raise ValueError

    return curve, groth16_script, vk_type, proof_type


def load_public_inputs(public_inputs_serialized: bytes, curve: BilinearPairingCurve):
    n_public_inputs = int.from_bytes(public_inputs_serialized[:7], byteorder="little")
    field_length = (curve.get_order_scalar_field().bit_length() + 8) // 8

    index = 8
    public_inputs = []
    for _ in range(n_public_inputs):
        public_inputs.extend(
            curve.scalar_field.deserialise(public_inputs_serialized[index : index + field_length]).to_list()
        )
        index += field_length
    return [1, *public_inputs]


def proof_to_unlock(
    public_statements,
    proof,
    vk,
    groth16_script: Groth16,
) -> Script:
    prepared_proof = proof.prepare_for_zkscript(
        vk.prepare(),
        public_statements,
    )
    
    unlocking_key = Groth16UnlockingKeyWithPrecomputedMsm(
        A=prepared_proof.a,
        B=prepared_proof.b,
        C=prepared_proof.c,
        gradients_pairings=[
            prepared_proof.gradients_b,
            prepared_proof.gradients_minus_gamma,
            prepared_proof.gradients_minus_delta,
        ],
        inverse_miller_output=prepared_proof.inverse_miller_loop,
        precomputed_msm=[],
    )
    return unlocking_key.to_unlocking_script(groth16_script, True)


def vk_to_lock(vk: VerifyingKey, public_inputs: List,  groth16_script: Groth16) -> Script:
    assert len(public_inputs) + 1 == len(vk.gamma_abc)

    precomputed_msm = vk.gamma_abc[0]
    for base, scalar in zip(vk.gamma_abc[1:], public_inputs):
        precomputed_msm += base.multiply(scalar)
    
    prepared_vk = vk.prepare_for_zkscript()

    locking_key = Groth16LockingKey(
        alpha_beta=prepared_vk.alpha_beta,
        minus_gamma=prepared_vk.minus_gamma,
        minus_delta=prepared_vk.minus_delta,
        gamma_abc=prepared_vk.gamma_abc,
        gradients_pairings=[
            prepared_vk.gradients_minus_gamma,
            prepared_vk.gradients_minus_delta,
        ],
    )

    return \
        nums_to_script(precomputed_msm.to_list()) \
        + \
        groth16_script.groth16_verifier_with_precomputed_msm(
        locking_key=locking_key,
        modulo_threshold=200 * 8,
        check_constant=True,
        clean_constant=True,
    )


def save_data_to_file(data: list[str], key: list[str], filename: str):
    data_dir = Path(__file__).resolve().parent / "outputs"
    data_dir.mkdir(parents=True, exist_ok=True)
    data_to_write = []
    for k, d in zip(key, data):
        data_to_write.append({k: d})
    with Path.open(data_dir / f"{filename}.json", "w") as f:
        f.write(json.dumps(data_to_write))

def set_up_network_connection(network):
    """Set up network connection."""
    return InterfaceFactory().set_config({"interface_type": "woc", "network_type": network})


parser = argparse.ArgumentParser(
    description="Given a public statement, a Groth16 proof and verifying key, generate locking and unlocking script. \
        If funding UTXO (P2PKH) is supplied, create a couple of transactions:\
              one spending the UTXO and creating the ZKP verifier, \
                one spending the verifier and returning the amount to same PubKey"
)
parser.add_argument(
    "--dir",
    type=str,
    choices=["square_root", "sha256", "sha256Copy", "ai_inference"],
    help="Directory from which to get statement, proof and verifying key",
)
parser.add_argument(
    "--curve", type=str, choices=["bls12_381", "mnt4_753"], help="Curve over which Groth16 is instantiated"
)
parser.add_argument(
    "--config", type=str, help="JSON configuration file for transaction construction and broadcast", required=False
)
parser.add_argument("--regtest", type=bool, help="Test in regtest", default=False, required=False)

if __name__ == "__main__":
    # Fetch cli arguments
    args = parser.parse_args()
    data_dir = Path(args.dir)
    curve = args.curve
    config_path = Path(args.config) if args.config is not None else None
    test_in_regtest = args.regtest

    # Set up curve
    curve, groth16_script, vk_type, proof_type = curve_setup(args.curve)

    # Load proof, vk
    vk = vk_type.deserialise(json.load(Path.open(data_dir / "proof/verifying_key.json"))["verifying_key"])

    proof_hello = proof_type.deserialise(json.load(Path.open(data_dir / "proof/proof_hello.json"))["proof"])
    proof_world = proof_type.deserialise(json.load(Path.open(data_dir / "proof/proof_world.json"))["proof"])

    # Load public inputs
    public_inputs_hello = load_public_inputs(
        json.load(Path.open(data_dir / "proof/public_inputs_hello.json"))["public_inputs"], curve
    )
    public_inputs_world = load_public_inputs(
        json.load(Path.open(data_dir / "proof/public_inputs_world.json"))["public_inputs"], curve
    )

    # Construct locking and unlocking scripts
    time_start = time.perf_counter()
    lock_hello = vk_to_lock(vk, public_inputs_hello[1:], groth16_script)
    unlock_hello = proof_to_unlock(public_inputs_hello[1:], proof_hello, vk, groth16_script)
    time_scripts_built = time.perf_counter()
    print(f"Scripts built in {time_scripts_built - time_start:.6f} seconds")
    print(f"Locking script size: {len(lock_hello.serialize().hex()) / 2} bytes")
    print(f"Unlocking script size: {len(unlock_hello.serialize().hex()) / 2} bytes")

    context = Context(script=unlock_hello + lock_hello)
    assert context.evaluate(), "Evaluation hello failed"
    time_scripts_evaluated = time.perf_counter()
    print(f"Scripts evaluated in {time_scripts_evaluated - time_scripts_built:.6f} seconds")


    time_start = time.perf_counter()
    lock_world = vk_to_lock(vk, public_inputs_world[1:], groth16_script)
    unlock_world = proof_to_unlock(public_inputs_world[1:], proof_world, vk, groth16_script)
    time_scripts_built = time.perf_counter()
    print(f"Scripts built in {time_scripts_built - time_start:.6f} seconds")
    print(f"Locking script size: {len(lock_world.serialize().hex()) / 2} bytes")
    print(f"Unlocking script size: {len(unlock_world.serialize().hex()) / 2} bytes")

    context = Context(script=unlock_world + lock_world)
    assert context.evaluate(), "Evaluation world failed"
    time_scripts_evaluated = time.perf_counter()
    print(f"Scripts evaluated in {time_scripts_evaluated - time_scripts_built:.6f} seconds")


    contxt = Context(script=unlock_world + lock_hello)
    assert not context.evaluate(), "Evaluation world with lock hello should have failed"

    contxt = Context(script=unlock_hello + lock_world)
    assert not context.evaluate(), "Evaluation hello with lock world should have failed"

    print("Evaluation successful")

    save_data_to_file(
        [lock_hello.serialize().hex()],
        ["locking_script_hex"],
        f"locking_script_sha256_hello",
    )
    save_data_to_file(
        [unlock_hello.serialize().hex()],
        ["unlocking_script_hex"],
        f"unlocking_script_sha256_hello",
    )

    save_data_to_file(
        [unlock_world.serialize().hex()],
        ["unlocking_script_hex"],
        f"unlocking_script_sha256_world",
    )