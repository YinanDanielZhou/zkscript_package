use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_relations::r1cs::ConstraintSynthesizer;

use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    uint8::UInt8,
    fields::fp::FpVar,
    boolean::Boolean,
};
use ark_r1cs_std::bits::ToBitsGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;

use ark_test_curves::bls12_381::{Fr as ScalarFieldBls};


#[derive(Clone)]
pub struct MmrCompareCircuit{
    // public input
    pub mmr_root: ScalarFieldBls,
    pub mmr_root_2: ScalarFieldBls,
    // pub result_hash: ScalarFieldBls,

    pub path_config_field: ScalarFieldBls,
    pub path_config_field_2: ScalarFieldBls,

    pub operator: ScalarFieldBls,  // 0 : <, 1 : <=, 2 : >, 3 : >=, 4 : ==, 5 : !=

    // private witnesses
    pub leaf_preimage: i64,  // Signed 64-bit integer
    pub path_hashes: Vec<[u8; 32]>,

    // private witnesses 2
    pub leaf_preimage_2: i64,  // Signed 64-bit integer
    pub path_hashes_2: Vec<[u8; 32]>,
}

pub const MAX_MERGE_COUNT: usize = 5;   // 

impl ConstraintSynthesizer<ScalarFieldBls> for MmrCompareCircuit {
    fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<ScalarFieldBls>) -> ark_relations::r1cs::Result<()> {
        // ------------------------------------------------ the first leaf inclusion check -------------------------------------------------
        // ——— Allocate public inputs: root
        let root_var = FpVar::<ScalarFieldBls>::new_input(ark_relations::ns!(cs.clone(), "root"), || Ok(self.mmr_root))?;

        // Combined path_dirs and skip_hashing from single public input
        let path_config_field = FpVar::<ScalarFieldBls>::new_input(
            ark_relations::ns!(cs.clone(), "path_config"), 
            || Ok(self.path_config_field)
        )?;
        let path_config_bits = path_config_field.to_bits_le()?;
        
        // Extract path_dirs from bits 0-6 and skip_hashing from bits 7-13
        let dir_vars: Vec<Boolean<ScalarFieldBls>> = path_config_bits[0..MAX_MERGE_COUNT].to_vec();
        let skip_vars: Vec<Boolean<ScalarFieldBls>> = path_config_bits[MAX_MERGE_COUNT..(2 * MAX_MERGE_COUNT)].to_vec();

        // ——— Allocate private witnesses
        let is_negative = self.leaf_preimage < 0;
        let abs_value = self.leaf_preimage.abs() as u64;

        // Create field element for the absolute value
        let abs_field_value = ScalarFieldBls::from(abs_value);
        let abs_var = FpVar::<ScalarFieldBls>::new_witness(
            ark_relations::ns!(cs.clone(), "leaf_preimage_abs"),
            || Ok(abs_field_value)
        )?;
        let sign_var = Boolean::new_witness(cs.clone(), || Ok(is_negative))?;

        // Convert to signed magnitude little-endian format (8 bytes = 64 bits)
        // Format: [magnitude (63 bits)] [sign bit (1 bit)]
        // For -2: magnitude = 2 = 0x02, sign = 1 → 0x0200000000000080
        let abs_bits = abs_var.to_bits_le()?;
        let mut preimage_bytes: Vec<UInt8<ScalarFieldBls>> = abs_bits[..56]  // First 7 bytes (56 bits) of magnitude
            .chunks(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();
        // 8th byte: 7 bits from magnitude + 1 sign bit (MSB)
        let last_byte_bits = [
            abs_bits[56..63].to_vec(),  // bits 56-62 (7 bits of magnitude)
            vec![sign_var]              // bit 63 (sign bit: 0 = positive, 1 = negative)
        ].concat();
        preimage_bytes.push(UInt8::from_bits_le(&last_byte_bits));
        
        // Hash the preimage to get leaf
        let leaf_digest = Sha256Gadget::<ScalarFieldBls>::digest(&preimage_bytes)?;
        let leaf_witness = leaf_digest.0;

        // path siblings
        let mut path_vars: Vec<Vec<UInt8<ScalarFieldBls>>> = Vec::with_capacity(self.path_hashes.len());
        for (_i, h) in self.path_hashes.iter().enumerate() {
            path_vars.push(UInt8::<ScalarFieldBls>::new_witness_vec(cs.clone(), h)?);
        }

        let mut cur = leaf_witness.clone(); // 32 bytes

        for (_i, ((sib, dir), should_skip)) in path_vars.iter().zip(dir_vars.iter()).zip(skip_vars.iter()).enumerate() {
            // Conditionally select which vector goes left and which goes right
            // If dir is true: left = sib, right = cur
            // If dir is false: left = cur, right = sib
            let left: Vec<UInt8<ScalarFieldBls>> = sib.iter().zip(cur.iter())
                .map(|(s, c)| UInt8::conditionally_select(dir, s, c))
                .collect::<Result<_, _>>()?;
            let right: Vec<UInt8<ScalarFieldBls>> = cur.iter().zip(sib.iter())
                .map(|(c, s)| UInt8::conditionally_select(dir, c, s))
                .collect::<Result<_, _>>()?;

            let mut input = left;
            input.extend(right);

            let digest = Sha256Gadget::<ScalarFieldBls>::digest(&input)?;

            // Conditionally select: if should_hash is true, use digest; else keep cur
            let new_cur: Vec<UInt8<ScalarFieldBls>> = cur.iter().zip(digest.0.iter())
                .map(|(old, new)| UInt8::conditionally_select(should_skip, old, new))
                .collect::<Result<_, _>>()?;
            
            cur = new_cur;
        }

        // Convert bytes to field element by packing them
        // We'll manually reconstruct the field element from the bytes
        let mut acc = FpVar::<ScalarFieldBls>::zero();
        let base = FpVar::<ScalarFieldBls>::constant(ScalarFieldBls::from(256u32));

        for byte in cur.iter() {
            // Convert UInt8 to bits, then to field element
            let byte_bits = byte.to_bits_le()?;
            let mut byte_value = FpVar::<ScalarFieldBls>::zero();
            let mut power = FpVar::<ScalarFieldBls>::one();

            for bit in byte_bits.iter() {
                // If bit is true, add the power of 2
                let to_add = FpVar::conditionally_select(bit, &power, &FpVar::zero())?;
                byte_value = byte_value + to_add;
                power = power.double()?;
            }

            // acc = acc * 256 + byte_value
            acc = acc * &base + byte_value;
        }

        // ——— Enforce equality to the public MMR root
        acc.enforce_equal(&root_var)?;


        // ------------------------------------------------ the second leaf inclusion check -------------------------------------------------
        // ——— Allocate public inputs: root
        let root_var_2 = FpVar::<ScalarFieldBls>::new_input(ark_relations::ns!(cs.clone(), "root"), || Ok(self.mmr_root_2))?;

        // Combined path_dirs and skip_hashing from single public input
        let path_config_field_2 = FpVar::<ScalarFieldBls>::new_input(
            ark_relations::ns!(cs.clone(), "path_config"), 
            || Ok(self.path_config_field_2)
        )?;
        let path_config_bits_2 = path_config_field_2.to_bits_le()?;
        
        // Extract path_dirs from bits 0-6 and skip_hashing from bits 7-13
        let dir_vars_2: Vec<Boolean<ScalarFieldBls>> = path_config_bits_2[0..MAX_MERGE_COUNT].to_vec();
        let skip_vars_2: Vec<Boolean<ScalarFieldBls>> = path_config_bits_2[MAX_MERGE_COUNT..(2 * MAX_MERGE_COUNT)].to_vec();


        // ——— Allocate private witnesses
        let is_negative_2 = self.leaf_preimage_2 < 0;
        let abs_value_2 = self.leaf_preimage_2.abs() as u64;

        // Create field element for the absolute value
        let abs_field_value_2 = ScalarFieldBls::from(abs_value_2);
        let abs_var_2 = FpVar::<ScalarFieldBls>::new_witness(
            ark_relations::ns!(cs.clone(), "leaf_preimage_abs"),
            || Ok(abs_field_value_2)
        )?;
        let sign_var_2 = Boolean::new_witness(cs.clone(), || Ok(is_negative_2))?;

        // Convert to signed magnitude little-endian format (8 bytes = 64 bits)
        // Format: [magnitude (63 bits)] [sign bit (1 bit)]
        // For -2: magnitude = 2 = 0x02, sign = 1 → 0x0200000000000080
        let abs_bits_2 = abs_var_2.to_bits_le()?;
        let mut preimage_bytes_2: Vec<UInt8<ScalarFieldBls>> = abs_bits_2[..56]  // First 7 bytes (56 bits) of magnitude
            .chunks(8)
            .map(|chunk| UInt8::from_bits_le(chunk))
            .collect();
        // 8th byte: 7 bits from magnitude + 1 sign bit (MSB)
        let last_byte_bits_2 = [
            abs_bits_2[56..63].to_vec(),  // bits 56-62 (7 bits of magnitude)
            vec![sign_var_2]              // bit 63 (sign bit: 0 = positive, 1 = negative)
        ].concat();
        preimage_bytes_2.push(UInt8::from_bits_le(&last_byte_bits_2));
        
        // Hash the preimage to get leaf
        let leaf_digest_2 = Sha256Gadget::<ScalarFieldBls>::digest(&preimage_bytes_2)?;
        let leaf_witness_2 = leaf_digest_2.0;

        // path siblings
        let mut path_vars_2: Vec<Vec<UInt8<ScalarFieldBls>>> = Vec::with_capacity(self.path_hashes_2.len());
        for (_i, h) in self.path_hashes_2.iter().enumerate() {
            path_vars_2.push(UInt8::<ScalarFieldBls>::new_witness_vec(cs.clone(), h)?);
        }

        // ——— Start at the leaf, climb to the peak using path siblings
        let mut cur = leaf_witness_2.clone(); // 32 bytes

        for (_i, ((sib, dir), should_skip)) in path_vars_2.iter().zip(dir_vars_2.iter()).zip(skip_vars_2.iter()).enumerate() {
            // Conditionally select which vector goes left and which goes right
            // If dir is true: left = sib, right = cur
            // If dir is false: left = cur, right = sib
            let left: Vec<UInt8<ScalarFieldBls>> = sib.iter().zip(cur.iter())
                .map(|(s, c)| UInt8::conditionally_select(dir, s, c))
                .collect::<Result<_, _>>()?;
            let right: Vec<UInt8<ScalarFieldBls>> = cur.iter().zip(sib.iter())
                .map(|(c, s)| UInt8::conditionally_select(dir, c, s))
                .collect::<Result<_, _>>()?;

            let mut input = left;
            input.extend(right);

            let digest = Sha256Gadget::<ScalarFieldBls>::digest(&input)?;

            // Conditionally select: if should_hash is true, use digest; else keep cur
            let new_cur: Vec<UInt8<ScalarFieldBls>> = cur.iter().zip(digest.0.iter())
                .map(|(old, new)| UInt8::conditionally_select(should_skip, old, new))
                .collect::<Result<_, _>>()?;
            
            cur = new_cur;
        }

        // Convert bytes to field element by packing them
        // We'll manually reconstruct the field element from the bytes
        let mut acc = FpVar::<ScalarFieldBls>::zero();

        for byte in cur.iter() {
            // Convert UInt8 to bits, then to field element
            let byte_bits = byte.to_bits_le()?;
            let mut byte_value = FpVar::<ScalarFieldBls>::zero();
            let mut power = FpVar::<ScalarFieldBls>::one();

            for bit in byte_bits.iter() {
                // If bit is true, add the power of 2
                let to_add = FpVar::conditionally_select(bit, &power, &FpVar::zero())?;
                byte_value = byte_value + to_add;
                power = power.double()?;
            }

            // acc = acc * 256 + byte_value
            acc = acc * &base + byte_value;
        }

        // ——— Enforce equality to the public MMR root
        acc.enforce_equal(&root_var_2)?;


        // ———--------------------------------------- Compute the sum of the two leaves ---------------------------------------
        let shifted_value = (self.leaf_preimage as i128) - (i64::MIN as i128);
        let leaf_preimage_field = ScalarFieldBls::from(shifted_value as u64);

        let shifted_value_2 = (self.leaf_preimage_2 as i128) - (i64::MIN as i128);
        let leaf_preimage_2_field = ScalarFieldBls::from(shifted_value_2 as u64);

        // Create circuit variables for comparison
        let leaf_var = FpVar::<ScalarFieldBls>::new_witness(
            ark_relations::ns!(cs.clone(), "leaf_preimage_field"),
            || Ok(leaf_preimage_field)
        )?;
        
        let leaf_var_2 = FpVar::<ScalarFieldBls>::new_witness(
            ark_relations::ns!(cs.clone(), "leaf_preimage_2_field"),
            || Ok(leaf_preimage_2_field)
        )?;

        // Allocate operator as public input
        let operator_var = FpVar::<ScalarFieldBls>::new_input(
            ark_relations::ns!(cs.clone(), "operator"), 
            || Ok(self.operator)
        )?;

        // Perform all possible comparisons
        let is_less = leaf_var.is_cmp(&leaf_var_2, std::cmp::Ordering::Less, false)?;
        let is_greater = leaf_var.is_cmp(&leaf_var_2, std::cmp::Ordering::Greater, false)?;
        let is_equal = leaf_var.is_eq(&leaf_var_2)?;
        
        // Derive compound comparisons
        let is_less_equal = is_less.or(&is_equal)?;      // <=
        let is_greater_equal = is_greater.or(&is_equal)?; // >=
        let is_not_equal = is_equal.not();               // !=

        // Convert operator to bits for selection
        let op_bits = operator_var.to_bits_le()?;
        let op_bit_0 = &op_bits[0]; // LSB
        let op_bit_1 = &op_bits[1];
        let op_bit_2 = &op_bits[2]; // MSB for 3-bit encoding

        // Select comparison result based on operator (0:<, 1:<=, 2:>, 3:>=, 4:==, 5:!=)
        // Use nested conditional selects to implement 6-way selection
        let temp1 = Boolean::conditionally_select(op_bit_0, &is_less_equal, &is_less)?;           // bit0: 0->< 1-><=
        let temp2 = Boolean::conditionally_select(op_bit_0, &is_greater_equal, &is_greater)?;     // bit0: 0->> 1->>=
        let temp3 = Boolean::conditionally_select(op_bit_1, &temp2, &temp1)?;                     // bit1: 0->temp1 1->temp2
        let temp4 = Boolean::conditionally_select(op_bit_0, &is_not_equal, &is_equal)?;           // bit0: 0->== 1->!=
        let final_result = Boolean::conditionally_select(op_bit_2, &temp4, &temp3)?;              // bit2: 0->temp3 1->temp4

        // Convert result to field element (1 for true, 0 for false)
        let result_field = FpVar::conditionally_select(&final_result, &FpVar::one(), &FpVar::zero())?;
        result_field.enforce_equal(&FpVar::one())?;

        Ok(())
    }
}