import argparse
import json
import sys
from pathlib import Path
import time

sys.path.append(str(Path(__file__).resolve().parent.parent))

from elliptic_curves.instantiations.bls12_381.bls12_381 import (
    BLS12_381,
    ProofBls12381,
    VerifyingKeyBls12381,
)
from src.zkscript.groth16.bls12_381.bls12_381 import bls12_381 as bls12_381_groth
from src.zkscript.groth16.model.groth16 import Groth16
from src.zkscript.script_types.unlocking_keys.groth16 import Groth16UnlockingKey


def load_public_inputs(public_inputs_serialized, curve):
    """Deserialize public inputs from bytes serialized format to a list of integers.

    The file contains a byte-serialized format encoded as a JSON list of integers.
    We convert it to bytes, then parse according to the curve's scalar field size.
    Returns a list like [1, x1, x2, ...] where the leading 1 is the Groth16 convention.
    """
    # Ensure bytes
    if isinstance(public_inputs_serialized, list):
        public_inputs_serialized = bytes(public_inputs_serialized)

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


def proof_to_unlock(public_statements, proof, vk, groth16_script: Groth16):
    prepared_proof = proof.prepare_for_zkscript(
        vk.prepare(),
        public_statements,
    )

    unlocking_key = Groth16UnlockingKey.from_data(
        groth16_model=groth16_script,
        pub=prepared_proof.public_statements,
        A=prepared_proof.a,
        B=prepared_proof.b,
        C=prepared_proof.c,
        gradients_pairings=[
            prepared_proof.gradients_b,
            prepared_proof.gradients_minus_gamma,
            prepared_proof.gradients_minus_delta,
        ],
        gradients_multiplications=prepared_proof.gradients_multiplications,
        max_multipliers=None,
        gradients_additions=prepared_proof.gradients_additions,
        inverse_miller_output=prepared_proof.inverse_miller_loop,
        gradient_gamma_abc_zero=prepared_proof.gradient_gamma_abc_zero,
    )
    return unlocking_key.to_unlocking_script(groth16_script, True)


def save_data_to_file(data, key, filename: str):
    data_dir = Path(__file__).resolve().parent / "outputs"
    data_dir.mkdir(parents=True, exist_ok=True)
    data_to_write = [{k: d} for k, d in zip(key, data)]
    with Path.open(data_dir / f"{filename}.json", "w") as f:
        f.write(json.dumps(data_to_write))


parser = argparse.ArgumentParser(
    description="Read proof, verifying key and public inputs; generate the Groth16 unlocking script and save it to a file."
)
parser.add_argument("--proof", type=str, required=True, help="Path to proof.json")
parser.add_argument("--vk", type=str, required=True, help="Path to verifying_key.json")
parser.add_argument("--public-inputs", dest="public_inputs", type=str, required=True, help="Path to public_inputs.json")


if __name__ == "__main__":
    # Fetch CLI arguments
    args = parser.parse_args()

    # Set up curve-specific components
    pairing_curve, groth16_script, vk_type, proof_type = BLS12_381, bls12_381_groth, VerifyingKeyBls12381, ProofBls12381
    
    # Load proof, vk
    proof_json = json.load(Path.open(Path(args.proof)))
    vk_json = json.load(Path.open(Path(args.vk)))
    pub_json = json.load(Path.open(Path(args.public_inputs)))

    proof = proof_type.deserialise(proof_json["proof"])
    vk = vk_type.deserialise(vk_json["verifying_key"])

    # Load public inputs
    public_inputs = load_public_inputs(pub_json["public_inputs"], pairing_curve)

    # Construct unlocking script
    start = time.perf_counter()
    unlock = proof_to_unlock(public_inputs[1:], proof, vk, groth16_script)
    end = time.perf_counter()
    print(f"Elapsed: {end - start:.6f} seconds")

    print(f"Unlocking script size: {len(unlock.serialize().hex()) / 2} bytes")
    
    save_to_file = True
    if save_to_file:
        # Save unlocking script to file
        # Try to use the parent directory name of the proof file (e.g., the example name)
        case_dir = Path(args.proof).parent.name
        out_name = f"unlocking_script_{case_dir}"
        save_data_to_file(
            [unlock.serialize().hex()],
            ["unlocking_script_hex"],
            out_name,
        )
        print(f"Saved unlocking script to outputs/{out_name}.json")