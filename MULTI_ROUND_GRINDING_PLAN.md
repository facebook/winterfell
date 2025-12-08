# Multi-Round Grinding Implementation Plan

## Overview

Generalize the current single FRI query grinding to support grinding before any verifier challenge. This allows flexible distribution of proof-of-work across protocol rounds to optimize security vs. prover performance trade-offs.

## Current State (Commit 1)

**What we have:**
- ✅ `GrindingSchedule` struct in `air/src/proof/security.rs` with per-round fields (ali, deep, fri_batching, fri_first_intermediate, fri_query)
- ✅ `plan_grinding_schedule_ldr()` - Computes optimal schedule for list-decoding regime
- ✅ `plan_grinding_schedule_udr()` - Computes optimal schedule for unique-decoding regime
- ✅ `ProvenSecurity::compute_with_schedule()` - Security computation with per-round grinding
- ✅ Fixed DEEP epsilon calculation bug (uses `l` not `l²`)
- ✅ All security tests passing

**Commit message:**
```
Add multi-round grinding security estimator

- Add GrindingSchedule struct with per-round grinding fields
- Implement plan_grinding_schedule_ldr/udr for optimal schedule computation
- Add ProvenSecurity::compute_with_schedule for per-round security analysis
- Fix DEEP epsilon calculation in planner helpers (use l not l²)
- Remove deprecated greedy planner in favor of direct planner
- Separate LDR and UDR planning into distinct functions

This provides the security analysis foundation for multi-round grinding
but does not yet modify the prover/verifier protocol.

Based on improved proximity gap bounds from ePrint 2025/2055.
```

## Future State (Commit 2) - Protocol Implementation

### Current FRI Query Grinding Pattern

**Key Components:**
1. **Storage**: `pow_nonce: u64` in ProverChannel and Proof
2. **Grinding Method**: `grind_query_seed()` in `prover/src/channel.rs`
   - Searches for nonce where `check_leading_zeros(nonce) >= grinding_factor`
   - Parallelizable using Rayon's `find_any()`
3. **Algorithm**: `hash(seed || nonce).trailing_zeros() >= grinding_factor`
4. **Usage**: Nonce reseeds public coin before drawing query positions
5. **Verification**: Verifier checks `check_leading_zeros(pow_nonce) >= grinding_factor`

**Code Locations:**
- ProofOptions: `air/src/options.rs` (grinding_factor field)
- Prover grinding: `prover/src/channel.rs:169-184` (grind_query_seed)
- Verifier check: `verifier/src/lib.rs:273-279`
- Proof structure: `air/src/proof/mod.rs:52-72` (pow_nonce field)
- RandomCoin: `crypto/src/random/default.rs:139-146` (check_leading_zeros)

### Generalization Strategy

Every verifier challenge follows the same pattern:
1. Accumulate transcript (commitments from prover)
2. **[NEW]** Optionally grind to find valid nonce
3. Draw randomness from public coin (optionally reseeded with nonce)
4. Continue protocol

### Implementation Steps

#### Step 1: Data Structure Changes

**File: `air/src/proof/mod.rs`**

Add new struct for storing per-round nonces:
```rust
/// Proof-of-work nonces for multi-round grinding
#[derive(Clone, Debug, Default)]
pub struct GrindingNonces {
    pub ali: Option<u64>,
    pub deep: Option<u64>,
    pub fri_batching: Option<u64>,
    pub fri_first_intermediate: Option<u64>,
    pub fri_query: Option<u64>,
}

impl Serializable for GrindingNonces {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write each optional nonce
        // Format: bool (present?) followed by u64 if present
        write_option_u64(target, self.ali);
        write_option_u64(target, self.deep);
        write_option_u64(target, self.fri_batching);
        write_option_u64(target, self.fri_first_intermediate);
        write_option_u64(target, self.fri_query);
    }
}

impl Deserializable for GrindingNonces {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            ali: read_option_u64(source)?,
            deep: read_option_u64(source)?,
            fri_batching: read_option_u64(source)?,
            fri_first_intermediate: read_option_u64(source)?,
            fri_query: read_option_u64(source)?,
        })
    }
}
```

Update Proof structure:
```rust
pub struct Proof {
    pub context: Context,
    pub num_unique_queries: u8,
    pub commitments: Commitments,
    pub trace_queries: Vec<Queries>,
    pub constraint_queries: Queries,
    pub ood_frame: OodFrame,
    pub fri_proof: FriProof,

    // Replace: pub pow_nonce: u64,
    pub grinding_nonces: GrindingNonces,
}
```

**File: `air/src/options.rs`**

Update ProofOptions to use GrindingSchedule:
```rust
pub struct ProofOptions {
    num_queries: u8,
    blowup_factor: u8,
    // Remove: grinding_factor: u8,
    grinding_schedule: GrindingSchedule,
    field_extension: FieldExtension,
    fri_folding_factor: u8,
    fri_remainder_max_degree: u8,
    batching_constraints: BatchingMethod,
    batching_deep: BatchingMethod,
    partition_options: PartitionOptions,
}
```

Add builder methods to GrindingSchedule:
```rust
impl GrindingSchedule {
    /// No grinding at all
    pub fn none() -> Self {
        Self::default()
    }

    /// Only grind before FRI query sampling (most common optimization)
    pub fn query_only(bits: u32) -> Self {
        Self {
            fri_query: Some(bits),
            ..Default::default()
        }
    }

    /// Uniform grinding across all rounds
    pub fn uniform(bits: u32) -> Self {
        Self {
            ali: Some(bits),
            deep: Some(bits),
            fri_batching: Some(bits),
            fri_first_intermediate: Some(bits),
            fri_query: Some(bits),
        }
    }

    /// Compute schedule to reach target security level in LDR
    pub fn for_target_ldr(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        collision_resistance: u32,
        num_constraints: usize,
        num_committed_polys: usize,
        target_bits: u32,
    ) -> Self {
        let (schedule, _achieved, _m) = plan_grinding_schedule_ldr(
            options, base_field_bits, trace_domain_size,
            collision_resistance, num_constraints, num_committed_polys, target_bits
        );
        // Convert internal representation (0 = no grinding) to Option
        Self {
            ali: if schedule.ali > 0 { Some(schedule.ali) } else { None },
            deep: if schedule.deep > 0 { Some(schedule.deep) } else { None },
            fri_batching: if schedule.fri_batching > 0 { Some(schedule.fri_batching) } else { None },
            fri_first_intermediate: if schedule.fri_first_intermediate > 0 { Some(schedule.fri_first_intermediate) } else { None },
            fri_query: if schedule.fri_query > 0 { Some(schedule.fri_query) } else { None },
        }
    }

    /// Compute schedule to reach target security level in UDR
    pub fn for_target_udr(/* similar parameters */) -> Self {
        // Similar implementation using plan_grinding_schedule_udr
    }
}
```

#### Step 2: Prover Channel Changes

**File: `prover/src/channel.rs`**

Update ProverChannel:
```rust
pub struct ProverChannel {
    // Existing fields...

    // Replace: pow_nonce: u64,
    grinding_nonces: GrindingNonces,
}

impl ProverChannel {
    /// Generic grinding method that can be used for any round
    fn grind_for_challenge(&mut self, grinding_bits: u32) -> u64 {
        #[cfg(not(feature = "concurrent"))]
        let nonce = (1..u64::MAX)
            .find(|&nonce| self.public_coin.check_leading_zeros(nonce) >= grinding_bits)
            .expect("nonce not found");

        #[cfg(feature = "concurrent")]
        let nonce = (1..u64::MAX)
            .into_par_iter()
            .find_any(|&nonce| self.public_coin.check_leading_zeros(nonce) >= grinding_bits)
            .expect("nonce not found");

        nonce
    }

    /// Apply grinding before drawing ALI randomness
    pub fn grind_ali_seed(&mut self) {
        if let Some(bits) = self.context.options().grinding_schedule().ali {
            let nonce = self.grind_for_challenge(bits);
            self.grinding_nonces.ali = Some(nonce);
        }
    }

    /// Apply grinding before drawing DEEP randomness
    pub fn grind_deep_seed(&mut self) {
        if let Some(bits) = self.context.options().grinding_schedule().deep {
            let nonce = self.grind_for_challenge(bits);
            self.grinding_nonces.deep = Some(nonce);
        }
    }

    /// Apply grinding before drawing FRI batching randomness
    pub fn grind_fri_batching_seed(&mut self) {
        if let Some(bits) = self.context.options().grinding_schedule().fri_batching {
            let nonce = self.grind_for_challenge(bits);
            self.grinding_nonces.fri_batching = Some(nonce);
        }
    }

    /// Apply grinding before drawing FRI intermediate layer randomness
    pub fn grind_fri_intermediate_seed(&mut self) {
        if let Some(bits) = self.context.options().grinding_schedule().fri_first_intermediate {
            let nonce = self.grind_for_challenge(bits);
            self.grinding_nonces.fri_first_intermediate = Some(nonce);
        }
    }

    /// Apply grinding before drawing FRI query positions (existing method, modified)
    pub fn grind_query_seed(&mut self) {
        if let Some(bits) = self.context.options().grinding_schedule().fri_query {
            let nonce = self.grind_for_challenge(bits);
            self.grinding_nonces.fri_query = Some(nonce);
        }
    }

    /// Get all grinding nonces for inclusion in proof
    pub fn grinding_nonces(&self) -> GrindingNonces {
        self.grinding_nonces.clone()
    }
}
```

Update RandomCoin methods to accept optional nonce:
```rust
// In crypto/src/random/default.rs or mod.rs
pub trait RandomCoin {
    // Add new method that accepts optional nonce
    fn draw_with_nonce<E>(&mut self, nonce: Option<u64>) -> Result<E, RandomCoinError>
    where
        E: FieldElement;

    fn draw_integers_with_nonce(
        &mut self,
        num_values: usize,
        domain_size: usize,
        nonce: Option<u64>,
    ) -> Result<Vec<usize>, RandomCoinError>;
}

// Implementation would reseed if nonce present, otherwise use current seed
```

#### Step 3: Prover Integration

**File: `prover/src/lib.rs`**

Add grinding calls at appropriate protocol points:

```rust
// After constraint commitment, before ALI randomness draw
// Location: around line 300-350
channel.commit_constraints(/*...*/);
channel.grind_ali_seed();  // NEW
let constraint_coeffs = channel.draw_constraint_coefficients(/*...*/);

// After DEEP commitment, before DEEP randomness draw
// Location: around line 400-450
channel.commit_deep(/*...*/);
channel.grind_deep_seed();  // NEW
let z = channel.draw_deep_challenge();

// After FRI commitment, before FRI batching randomness draw
// Location: around line 450-500
channel.commit_fri_layer(/*...*/);
channel.grind_fri_batching_seed();  // NEW
let fri_alpha = channel.draw_fri_alpha();

// For FRI intermediate layers (may need loop modification)
// Location: FRI folding loop
channel.commit_fri_layer(/*...*/);
if is_first_intermediate {
    channel.grind_fri_intermediate_seed();  // NEW
}
let folding_challenge = channel.draw_fri_folding_challenge();

// Existing query grinding (now uses schedule)
// Location: around line 446-462
channel.grind_query_seed();  // MODIFIED to use schedule
let query_positions = channel.get_query_positions();
```

Update proof construction:
```rust
// Location: around line 500+
let proof = Proof::new(
    context,
    num_unique_queries,
    commitments,
    trace_queries,
    constraint_queries,
    ood_frame,
    fri_proof,
    channel.grinding_nonces(),  // CHANGED from pow_nonce
);
```

#### Step 4: Verifier Integration

**File: `verifier/src/lib.rs`**

Add verification checks after each commitment:

```rust
// After constraint commitment
let grinding_nonces = &proof.grinding_nonces;

// ALI grinding check
if let Some(bits) = air.options().grinding_schedule().ali {
    let nonce = grinding_nonces.ali
        .ok_or(VerifierError::MissingAliGrindingNonce)?;
    if public_coin.check_leading_zeros(nonce) < bits {
        return Err(VerifierError::AliGrindingVerificationFailed);
    }
    // Reseed public coin with verified nonce
    public_coin.reseed_with_int(nonce);
}

// DEEP grinding check (similar pattern)
if let Some(bits) = air.options().grinding_schedule().deep {
    let nonce = grinding_nonces.deep
        .ok_or(VerifierError::MissingDeepGrindingNonce)?;
    if public_coin.check_leading_zeros(nonce) < bits {
        return Err(VerifierError::DeepGrindingVerificationFailed);
    }
    public_coin.reseed_with_int(nonce);
}

// FRI batching grinding check
if let Some(bits) = air.options().grinding_schedule().fri_batching {
    let nonce = grinding_nonces.fri_batching
        .ok_or(VerifierError::MissingFriBatchingGrindingNonce)?;
    if public_coin.check_leading_zeros(nonce) < bits {
        return Err(VerifierError::FriBatchingGrindingVerificationFailed);
    }
    public_coin.reseed_with_int(nonce);
}

// FRI intermediate grinding check
if let Some(bits) = air.options().grinding_schedule().fri_first_intermediate {
    let nonce = grinding_nonces.fri_first_intermediate
        .ok_or(VerifierError::MissingFriIntermediateGrindingNonce)?;
    if public_coin.check_leading_zeros(nonce) < bits {
        return Err(VerifierError::FriIntermediateGrindingVerificationFailed);
    }
    public_coin.reseed_with_int(nonce);
}

// FRI query grinding check (replace existing check around line 273-279)
if let Some(bits) = air.options().grinding_schedule().fri_query {
    let nonce = grinding_nonces.fri_query
        .ok_or(VerifierError::MissingFriQueryGrindingNonce)?;
    if public_coin.check_leading_zeros(nonce) < bits {
        return Err(VerifierError::QuerySeedProofOfWorkVerificationFailed);
    }
    public_coin.reseed_with_int(nonce);
}
```

Update VerifierError enum:
```rust
pub enum VerifierError {
    // ... existing variants
    MissingAliGrindingNonce,
    AliGrindingVerificationFailed,
    MissingDeepGrindingNonce,
    DeepGrindingVerificationFailed,
    MissingFriBatchingGrindingNonce,
    FriBatchingGrindingVerificationFailed,
    MissingFriIntermediateGrindingNonce,
    FriIntermediateGrindingVerificationFailed,
    // QuerySeedProofOfWorkVerificationFailed already exists
}
```

#### Step 5: Testing

**File: `prover/src/tests.rs` or new test file**

Add comprehensive tests:

```rust
#[test]
fn test_no_grinding() {
    let schedule = GrindingSchedule::none();
    let proof = generate_test_proof_with_schedule(schedule);
    assert!(verify_proof(proof).is_ok());
}

#[test]
fn test_query_only_grinding() {
    let schedule = GrindingSchedule::query_only(20);
    let proof = generate_test_proof_with_schedule(schedule);
    assert!(proof.grinding_nonces.fri_query.is_some());
    assert!(proof.grinding_nonces.ali.is_none());
    assert!(verify_proof(proof).is_ok());
}

#[test]
fn test_uniform_grinding() {
    let schedule = GrindingSchedule::uniform(16);
    let proof = generate_test_proof_with_schedule(schedule);
    assert!(proof.grinding_nonces.ali.is_some());
    assert!(proof.grinding_nonces.deep.is_some());
    assert!(proof.grinding_nonces.fri_batching.is_some());
    assert!(verify_proof(proof).is_ok());
}

#[test]
fn test_custom_grinding_schedule() {
    let schedule = GrindingSchedule {
        ali: Some(5),
        deep: Some(10),
        fri_batching: Some(15),
        fri_first_intermediate: Some(20),
        fri_query: Some(25),
    };
    let proof = generate_test_proof_with_schedule(schedule);

    // Verify nonces are present
    assert_eq!(proof.grinding_nonces.ali.unwrap().trailing_zeros(), 5);
    assert_eq!(proof.grinding_nonces.deep.unwrap().trailing_zeros(), 10);

    assert!(verify_proof(proof).is_ok());
}

#[test]
fn test_optimal_ldr_schedule() {
    let schedule = GrindingSchedule::for_target_ldr(
        &options, 64, 1<<20, 128, 100, 200, 128
    );
    let proof = generate_test_proof_with_schedule(schedule);
    assert!(verify_proof(proof).is_ok());

    // Verify security level is achieved
    let security = ProvenSecurity::compute_with_schedule(
        &options, 64, 1<<20, 128, 100, 200, &schedule.to_internal()
    );
    assert!(security.ldr_bits() >= 128);
}

#[test]
fn test_verifier_rejects_missing_nonce() {
    let schedule = GrindingSchedule::query_only(20);
    let mut proof = generate_test_proof_with_schedule(schedule);

    // Remove the nonce
    proof.grinding_nonces.fri_query = None;

    let result = verify_proof(proof);
    assert!(matches!(result, Err(VerifierError::MissingFriQueryGrindingNonce)));
}

#[test]
fn test_verifier_rejects_invalid_nonce() {
    let schedule = GrindingSchedule::query_only(20);
    let mut proof = generate_test_proof_with_schedule(schedule);

    // Replace with invalid nonce (not enough zeros)
    proof.grinding_nonces.fri_query = Some(1);

    let result = verify_proof(proof);
    assert!(matches!(result, Err(VerifierError::QuerySeedProofOfWorkVerificationFailed)));
}

#[test]
fn test_serialization_roundtrip() {
    let schedule = GrindingSchedule::uniform(16);
    let proof = generate_test_proof_with_schedule(schedule);

    // Serialize
    let mut bytes = Vec::new();
    proof.write_into(&mut bytes);

    // Deserialize
    let deserialized = Proof::read_from(&mut &bytes[..]).unwrap();

    assert_eq!(proof.grinding_nonces.ali, deserialized.grinding_nonces.ali);
    assert_eq!(proof.grinding_nonces.deep, deserialized.grinding_nonces.deep);
    // ... check all fields
}
```

#### Step 6: Documentation

**File: `README.md` or new `docs/grinding.md`**

Add documentation explaining:
- What multi-round grinding is and why it's useful
- How to use the builder methods (none, query_only, uniform)
- How to use the scheduler (for_target_ldr, for_target_udr)
- Performance implications of different schedules
- Security trade-offs

Example usage patterns:
```rust
// Simple: no grinding
let options = ProofOptions::new(
    100, 8, GrindingSchedule::none(), /* ... */
);

// Common: only query grinding (backward compatible behavior)
let options = ProofOptions::new(
    100, 8, GrindingSchedule::query_only(20), /* ... */
);

// Advanced: optimal schedule for 128-bit security
let schedule = GrindingSchedule::for_target_ldr(
    &base_options, 64, 1<<20, 128, 100, 200, 128
);
let options = ProofOptions::new(
    100, 8, schedule, /* ... */
);
```

### Migration Checklist

- [ ] **Commit 1: Security Estimator**
  - [ ] Verify all tests pass
  - [ ] Review diff
  - [ ] Commit with detailed message

- [ ] **Commit 2: Protocol Implementation**
  - [ ] Update data structures (GrindingNonces, Proof, ProofOptions)
  - [ ] Add builder methods to GrindingSchedule
  - [ ] Update ProverChannel with generic grinding
  - [ ] Wire grinding into prover at each round
  - [ ] Add verifier checks for all rounds
  - [ ] Update serialization/deserialization
  - [ ] Add comprehensive tests
  - [ ] Update documentation
  - [ ] Verify all tests pass
  - [ ] Commit

### Notes and Considerations

1. **Nonce Reseeding**: Need to ensure public coin is reseeded with nonce (if present) before drawing randomness. This maintains the security proof that grinding adds entropy.

2. **FRI Intermediate Layers**: The `fri_first_intermediate` field applies to the first intermediate FRI layer. Subsequent layers may use the same grinding or none - this needs careful consideration based on the security analysis.

3. **Backward Compatibility**: Since we're not maintaining backward compatibility, all examples and tests in the codebase will need to be updated to use `GrindingSchedule`.

4. **Performance Testing**: Should benchmark the overhead of grinding at different rounds to validate the cost model used by the scheduler.

5. **Serialization Format**: The optional nonce serialization adds a bool per field. Consider if this overhead is acceptable or if we should use a more compact encoding (e.g., bitflags + variable-length nonce list).

6. **Error Messages**: Need clear error messages when grinding verification fails, indicating which round failed.

7. **Proof Size Impact**: Each `Option<u64>` adds 1 byte (flag) + up to 8 bytes (value) = 9 bytes max per round. With 5 rounds, that's 45 bytes maximum overhead compared to the current single nonce (8 bytes). This is acceptable but should be documented.

## Success Criteria

- [ ] All existing tests pass
- [ ] New multi-round grinding tests pass
- [ ] Proofs with different schedules verify correctly
- [ ] Verifier rejects invalid/missing nonces
- [ ] Serialization round-trips correctly
- [ ] Documentation is clear and complete
- [ ] Security estimator integration works correctly
- [ ] Performance is acceptable (grinding overhead measured)
