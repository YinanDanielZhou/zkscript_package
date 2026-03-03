import argparse
import json
import sys
from pathlib import Path
import time

sys.path.append(str(Path(__file__).resolve().parent.parent))

from elliptic_curves.instantiations.bls12_381.bls12_381 import VerifyingKeyBls12381
from src.zkscript.groth16.bls12_381.bls12_381 import bls12_381 as bls12_381_groth
from src.zkscript.groth16.model.groth16 import Groth16
from src.zkscript.script_types.locking_keys.groth16 import Groth16LockingKey

def vk_to_lock(vk, groth16_script: Groth16):
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
    return groth16_script.groth16_verifier(
        locking_key,
        modulo_threshold=200 * 8,
        check_constant=True,
        clean_constant=True,
    )


def save_data_to_file(data, key, filename: str):
    data_dir = Path(__file__).resolve().parent / "outputs"
    data_dir.mkdir(parents=True, exist_ok=True)
    data_to_write = [{k: d} for k, d in zip(key, data)]
    with Path.open(data_dir / f"{filename}.json", "w") as f:
        f.write(json.dumps(data_to_write))


parser = argparse.ArgumentParser(
    description="Read a verifying key JSON and generate the Groth16 locking script, then save it to a file."
)
parser.add_argument(
    "--vk",
    type=str,
    required=True,
    help="Path to verifying_key.json",
)

if __name__ == "__main__":
    # Fetch CLI arguments
    args = parser.parse_args()
    vk_json_path = Path(args.vk)

    # Set up curve-specific components
    groth16_script, vk_type = bls12_381_groth, VerifyingKeyBls12381

    # Load verifying key
    vk = vk_type.deserialise(json.load(Path.open(vk_json_path))["verifying_key"])

    # Construct locking script
    start = time.perf_counter()
    lock = vk_to_lock(vk, groth16_script)
    end = time.perf_counter()
    print(f"Elapsed: {end - start:.6f} seconds")

    print(f"Locking script size: {len(lock.serialize().hex()) / 2} bytes")
    
    
    save_to_file = True
    if save_to_file:
        # Save locking script to file
        # Try to use the parent directory name of the VK file (e.g., the example name)
        case_dir = vk_json_path.parent.name
        out_name = f"locking_script_{case_dir}"

        save_data_to_file(
            [lock.serialize().hex()],
            ["locking_script_hex"],
            out_name,
        )
        print(f"Saved locking script to outputs/{out_name}.json")




# save_data_to_file(
    #     [lock.to_string(), lock.serialize().hex()],
    #     ["locking_script", "locking_script_hex"],
    #     out_name,
    # )