mod mmr_circuit_sum;
use mmr_circuit_sum::MmrTwoSumCircuit;
use mmr_circuit_sum::MAX_MERGE_COUNT;

use rand_chacha::ChaChaRng;
use rand::SeedableRng;

use ark_serialize::{CanonicalSerialize};
use ark_groth16::Groth16;

use ark_test_curves::bls12_381::{Bls12_381, Fr as ScalarFieldBls};
use ark_snark::SNARK;
use std::{fs::File};

// additional import for proving
#[allow(unused_imports)]
use ark_serialize::{Compress};
#[allow(unused_imports)]
use ark_groth16::{ProvingKey, VerifyingKey};
#[allow(unused_imports)]
use serde_json::{Value, json};
#[allow(unused_imports)]
use std::io::BufReader;
#[allow(unused_imports)]
use std::{io::Write};


fn proof_generate_and_verify(
    _pk: &ProvingKey<Bls12_381>, 
    _vk: &VerifyingKey<Bls12_381>
) -> Result<(), Box<dyn std::error::Error>>{
    // Randomness
    let mut _rng = ChaChaRng::from_entropy();

    let s = std::time::Instant::now();
    let proof_parameters= read_parameters("src/sum/proof_parameters.json")?;
    let t = s.elapsed();
    println!("Parameters loading time: {:?}", t);

    // Convert root bytes to field element (pack bytes into a single field element)
    let mut root = ScalarFieldBls::from(0u32);
    let base = ScalarFieldBls::from(256u32);
    for byte in proof_parameters.0.iter() {
        root = root * base + ScalarFieldBls::from(*byte);
    }

    let mut root_2 = ScalarFieldBls::from(0u32);
    for byte in proof_parameters.1.iter() {
        root_2 = root_2 * base + ScalarFieldBls::from(*byte);
    } 

    let path_config_field = pack_path_config(&proof_parameters.4, &proof_parameters.5);
    let path_config_field_2 = pack_path_config(&proof_parameters.8, &proof_parameters.9);

    let sum =proof_parameters.2 + proof_parameters.6;
    let result = if sum >= 0 {
        ScalarFieldBls::from(sum as u64)
    } else {
        -ScalarFieldBls::from(-sum as u64)
    };

    let circuit = MmrTwoSumCircuit {
        mmr_root: root,
        mmr_root_2: root_2,
        path_config_field: path_config_field,
        path_config_field_2: path_config_field_2,
        result: result,

        leaf_preimage: proof_parameters.2,
        path_hashes: proof_parameters.3,

        leaf_preimage_2: proof_parameters.6,
        path_hashes_2: proof_parameters.7
    };


    // Generate a new proof with the new inputs
    let s2 = std::time::Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&_pk, circuit.clone(), &mut _rng)
        .map_err(|e| format!("Proof generation failed: {}", e))?;
    let t2 = s2.elapsed();
    println!("Proving time: {:?}", t2);

    // Prepare public inputs - the mmr_root is already a field element
    let public_inputs: Vec<ScalarFieldBls> = vec![circuit.mmr_root, circuit.path_config_field, circuit.mmr_root_2, circuit.path_config_field_2, circuit.result];

    // Verify the new proof with the same vk
    let s3 = std::time::Instant::now();
    let t3 = s3.elapsed();
    let is_valid = Groth16::<Bls12_381>::verify(&_vk, &public_inputs, &proof)
        .map_err(|e| format!("Verification failed: {}", e))?;
    assert!(is_valid, "New proof is invalid");
    println!("Verification time: {:?}", t3);

    // Save proof, verification key, and public input to files
    save_to_file(&proof,"proof/MMRSUM/proof.json","proof")?;
    save_to_file(&public_inputs, "proof/MMRSUM/public_inputs.json","public_inputs")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    // std::env::set_var("RUST_BACKTRACE", "full");
    // Randomness
    let mut rng = ChaChaRng::from_entropy();

    // Example inputs (fill with real data):
    let root_bytes: [u8; 32] = hex::decode("54f90300d9722a43b1047ea5f8500a33d45f7f25996286823d9528c07cf10a61").unwrap().try_into().expect("Hex string must be exactly 32 bytes");

    // Convert root bytes to field element (pack bytes into a single field element)
    let mut root = ScalarFieldBls::from(0u32);
    let base = ScalarFieldBls::from(256u32);
    for byte in root_bytes.iter() {
        root = root * base + ScalarFieldBls::from(*byte);
    }

    let root_2_bytes: [u8; 32] = hex::decode("086203f877412ba963889983e41464efbb45fd03b4e54a602a653aa17ffdcaf0").unwrap().try_into().expect("Hex string must be exactly 32 bytes");
    let mut root_2 = ScalarFieldBls::from(0u32);
    for byte in root_2_bytes.iter() {
        root_2 = root_2 * base + ScalarFieldBls::from(*byte);
    }

    // First leaf
    let leaf_preimage: i64 = -2; // 0x0200000000000080   little endian signed magnitude
    let path_hashes: Vec<[u8; 32]> = vec![
        hex::decode("703d37e650ac5852ff1027382d58776810b88d1db959d667efa0df97ae156c6b").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("42dbeeb4eb5d41bbdc93732c6a87ab3241ee03f44a0780a52ddf831f5fd88b53").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("ccfea300216cc8686dacd619886ad89b3f0e6b2fe620c7b2c8806b284d4157b8").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("c15280932875422b745eb3e48601089e54e67add10afa8e17ccefa7baaf552fa").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("c693b27fb08051258f23366441be51cd2d6f846c8ad87dadc85bbe9f686a3bd1").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        // hex::decode("2d8377fac55a787272586ef23474b60ef75cd801072fb81c20923b81f590c99e").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        // hex::decode("db86a878b87f44fe7e34be40b83af3e91530afee8cbae138b00d932c17597a15").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
    ];  // siblings leaf→peak
    let path_dirs: Vec<bool>       = vec![true, true, false, false, true];  // same length as TREE_DEPTHS
    let skip_hashing: Vec<bool>    = vec![false, false, false, false, false]; // same length
    let path_config_field = pack_path_config(&path_dirs, &skip_hashing);

    // Second leaf
    let leaf_preimage_2: i64 = 3;
    let path_hashes_2: Vec<[u8; 32]> = vec![
        hex::decode("84961d14a797dc8ce78ba6eeeb860352c71433908e0ea80649af006106f84581").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("42dbeeb4eb5d41bbdc93732c6a87ab3241ee03f44a0780a52ddf831f5fd88b53").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("ccfea300216cc8686dacd619886ad89b3f0e6b2fe620c7b2c8806b284d4157b8").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("c15280932875422b745eb3e48601089e54e67add10afa8e17ccefa7baaf552fa").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        hex::decode("c693b27fb08051258f23366441be51cd2d6f846c8ad87dadc85bbe9f686a3bd1").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        // hex::decode("2d8377fac55a787272586ef23474b60ef75cd801072fb81c20923b81f590c99e").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
        // hex::decode("db86a878b87f44fe7e34be40b83af3e91530afee8cbae138b00d932c17597a15").unwrap().try_into().expect("Hex string must be exactly 32 bytes"),
    ];  // siblings leaf→peak
    let path_dirs_2: Vec<bool>       = vec![true, true, false, false, true];  // same length
    let skip_hashing_2: Vec<bool>    = vec![false, false, false, false, false]; // same length
    let path_config_field_2 = pack_path_config(&path_dirs_2, &skip_hashing_2);

    let sum =leaf_preimage + leaf_preimage_2;
    let result = if sum >= 0 {
        ScalarFieldBls::from(sum as u64)
    } else {
        -ScalarFieldBls::from(-sum as u64)
    };

    let circuit = MmrTwoSumCircuit {
        mmr_root: root,
        mmr_root_2: root_2,
        path_config_field: path_config_field,
        path_config_field_2: path_config_field_2,
        result: result,

        leaf_preimage: leaf_preimage,
        path_hashes: path_hashes,

        leaf_preimage_2: leaf_preimage_2,
        path_hashes_2: path_hashes_2,
    };

    // Setup
    let s0 = std::time::Instant::now();
    let setup_result = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng);
    
    let (pk, vk) = match setup_result {
        Ok((pk, vk)) => {
            println!("✓ Circuit setup successful!");
            (pk, vk)
        },
        Err(e) => {
            println!("✗ Circuit setup failed: {}", e);
            return Err(format!("Setup failed: {}", e).into());
        }
    };
    let t0 = s0.elapsed();
    println!("Setup time: {:?}", t0);


    save_to_file(&vk, "setup_results/MMRSUM/verifying_key.json", "verifying_key")?;
    let do_proving: bool = true;
    if !do_proving {
        let s1 = std::time::Instant::now();
        save_to_file_binary(&pk, "setup_results/MMRSUM/proving_key.bin")?;
        let t1 = s1.elapsed();
        println!("Saving time: {:?}", t1);
    } else {
        proof_generate_and_verify(&pk, &vk)?;
    }

    Ok(())
}

fn pack_path_config(path_dirs: &Vec<bool>, skip_hashing: &Vec<bool>) -> ScalarFieldBls {
    let mut packed = 0u32;
    for (i, &dir) in path_dirs.iter().enumerate() {
        if dir { packed |= 1 << i; }
    }
    for (i, &skip) in skip_hashing.iter().enumerate() {
        if skip { packed |= 1 << (i + MAX_MERGE_COUNT); }
    }
    return ScalarFieldBls::from(packed);
}


// Generic function to save serializable data
#[allow(dead_code)]
fn save_to_file<T>(
    item: &T,
    file_path: &str,
    key_name: &str
) -> Result<(), Box<dyn std::error::Error>>
where
    T: CanonicalSerialize,
{
    let mut serialized_data = vec![0; item.serialized_size(Compress::No)];
    item.serialize_uncompressed(&mut serialized_data[..])?;

    let json_data = json!({key_name: serialized_data});
    let json_string = serde_json::to_string_pretty(&json_data)?;

    File::create(file_path)?.write_all(json_string.as_bytes())?;
    Ok(())
}

fn save_to_file_binary<T>(item: &T, file_path: &str) -> Result<(), Box<dyn std::error::Error>>
where T: CanonicalSerialize,
{
    let mut file = File::create(file_path)?;
    item.serialize_compressed(&mut file)?;
    Ok(())
}


fn read_parameters(path: &str) -> Result<([u8; 32], [u8; 32], i64, Vec<[u8; 32]>, Vec<bool>, Vec<bool>, i64, Vec<[u8; 32]>, Vec<bool>, Vec<bool>, i64), Box<dyn std::error::Error>>{
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let json_data: Value = serde_json::from_reader(reader)?;

    let root_hex_str = json_data["root_hex"].as_str().ok_or("root must be hex string")?;
    let root: [u8; 32] = hex::decode(root_hex_str).unwrap().try_into().expect("root hex string must be exactly 32 bytes");

    let root_2_hex_str = json_data["root_2_hex"].as_str().ok_or("root_2 must be hex string")?;
    let root_2: [u8; 32] = hex::decode(root_2_hex_str).unwrap().try_into().expect("root_2 hex string must be exactly 32 bytes");

    // First leaf
    let leaf_preimage: i64 = json_data["leaf_preimage"].as_i64().ok_or("leaf_preimage must be i64")?;

    let path_hashes = json_data["path_hashes"]
        .as_array()
        .ok_or("encrypted_values must be an array")?
        .iter()
        .map(|v| {
            let path_hex_str = v.as_str().ok_or("encrypted_values must be hex strings")?;
            Ok(hex::decode(path_hex_str).unwrap().try_into().expect("path hex string must be exactly 32 bytes"))
        })
        .collect::<Result<Vec<[u8; 32]>, Box<dyn std::error::Error>>>()?;

    let path_dirs = json_data["path_dirs"]
        .as_array()
        .ok_or("encrypted_values must be an array")?
        .iter()
        .map(|v| {
            let path_dir = v.as_bool().ok_or("path_dirs must be bools")?;
            Ok(path_dir)
        })
        .collect::<Result<Vec<bool>, Box<dyn std::error::Error>>>()?;

    let skip_hashing = json_data["skip_hashing"]
        .as_array()
        .ok_or("encrypted_values must be an array")?
        .iter()
        .map(|v| {
            let skip = v.as_bool().ok_or("skip_hashing must be bools")?;
            Ok(skip)
        })
        .collect::<Result<Vec<bool>, Box<dyn std::error::Error>>>()?;

    
    // Second leaf
    let leaf_preimage_2: i64 = json_data["leaf_preimage_2"].as_i64().ok_or("leaf_preimage_2 must be i64")?;

    let path_hashes_2 = json_data["path_hashes_2"]
        .as_array()
        .ok_or("encrypted_values must be an array")?
        .iter()
        .map(|v| {
            let path_hex_str = v.as_str().ok_or("encrypted_values must be hex strings")?;
            Ok(hex::decode(path_hex_str).unwrap().try_into().expect("path hex string must be exactly 32 bytes"))
        })
        .collect::<Result<Vec<[u8; 32]>, Box<dyn std::error::Error>>>()?;

    let path_dirs_2 = json_data["path_dirs_2"]
        .as_array()
        .ok_or("encrypted_values must be an array")?
        .iter()
        .map(|v| {
            let path_dir = v.as_bool().ok_or("path_dirs must be bools")?;
            Ok(path_dir)
        })
        .collect::<Result<Vec<bool>, Box<dyn std::error::Error>>>()?;

    let skip_hashing_2 = json_data["skip_hashing_2"]
        .as_array()
        .ok_or("encrypted_values must be an array")?
        .iter()
        .map(|v| {
            let skip = v.as_bool().ok_or("skip_hashing must be bools")?;
            Ok(skip)
        })
        .collect::<Result<Vec<bool>, Box<dyn std::error::Error>>>()?;

    let result_preimage: i64 = leaf_preimage + leaf_preimage_2;

    Ok((root, root_2, leaf_preimage, path_hashes, path_dirs, skip_hashing, leaf_preimage_2, path_hashes_2, path_dirs_2, skip_hashing_2, result_preimage))
}


