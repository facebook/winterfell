use math::{fields::f64::BaseElement, StarkField};

use crate::{proof::security::ProvenSecurity, BatchingMethod, FieldExtension, ProofOptions};

#[test]
fn get_100_bits_security() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 2;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 4;
    let num_queries = 119;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(unique_decoding, 100);
    assert_eq!(list_decoding, 94);

    // increasing the queries does not help the LDR case
    let num_queries = 150;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 94);

    // increasing the extension degree does help and we then need fewer queries by virtue
    // of being in LDR
    let field_extension = FieldExtension::Cubic;
    let num_queries = 81;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 100);
}

#[test]
fn unique_decoding_folding_factor_effect() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 2;
    let fri_remainder_max_degree = 7;
    let grinding_factor = 16;
    let blowup_factor = 8;
    let num_queries = 123;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(8);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(unique_decoding, 116);

    let fri_folding_factor = 4;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(unique_decoding, 115);
}

#[test]
fn unique_versus_list_decoding_rate_effect() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 2;
    let fri_remainder_max_degree = 7;
    let grinding_factor = 20;
    let blowup_factor = 2;
    let num_queries = 195;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(8);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(unique_decoding, 100);

    // when the rate is large, going to a larger extension field in order to make full use of
    // being in the LDR might not always be justified

    // we increase the extension degree
    let field_extension = FieldExtension::Cubic;
    // and we reduce the number of required queries to reach the target level, but this is
    // a relatively small, approximately 16%, reduction
    let num_queries = 163;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 100);

    // reducing the rate further changes things
    let field_extension = FieldExtension::Quadratic;
    let blowup_factor = 4;
    let num_queries = 119;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(unique_decoding, 100);

    // the improvement is now at approximately 32%
    let field_extension = FieldExtension::Cubic;
    let num_queries = 81;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 100);
}

#[test]
fn get_96_bits_security() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 4;
    let num_queries = 80;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(18);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 99);

    // increasing the blowup factor should increase the bits of security gained per query
    let blowup_factor = 8;
    let num_queries = 53;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 99);
}

#[test]
fn get_128_bits_security() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 80;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 128);

    // increasing the blowup factor should increase the bits of security gained per query
    let blowup_factor = 16;
    let num_queries = 65;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 128);
}

#[test]
fn grinding_schedule_quadratic_reaches_target() {
    // Show that the grinding schedule planner correctly reaches the target security level
    // in LDR for the quadratic extension case.
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let blowup_factor = 8;
    let num_queries = 70;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(18);
    let num_committed_polys = 128;
    let num_constraints = 4048;

    let options = ProofOptions::new(
        num_queries,
        blowup_factor,
        0, // baseline grinding factor is ignored by schedule variant
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );

    // Plan a schedule to reach 110 bits in LDR and verify it achieves the target.
    let target_bits = 110;
    let (schedule, _m) = super::plan_grinding_schedule_ldr(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        target_bits,
    );

    let list_decoding = ProvenSecurity::compute_with_schedule(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        &schedule,
    )
    .ldr_bits();

    assert_eq!(list_decoding, target_bits);
}

#[test]
fn grinding_schedule_quadratic_reaches_target_udr() {
    // Show that the grinding schedule planner correctly reaches the target security level
    // in UDR for the quadratic extension case.
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let blowup_factor = 8;
    let num_queries = 110;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 128;
    let num_constraints = 4048;

    let options = ProofOptions::new(
        num_queries,
        blowup_factor,
        0, // baseline grinding factor is ignored by schedule variant
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );

    // Plan a schedule to reach 110 bits in UDR and verify it achieves the target.
    let target_bits = 110;
    let schedule = super::plan_grinding_schedule_udr(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        target_bits,
    );

    let unique_decoding = ProvenSecurity::compute_with_schedule(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        &schedule,
    )
    .udr_bits();

    assert_eq!(unique_decoding, target_bits);
}

#[test]
fn security_summary_display_100bits_ldr() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let blowup_factor = 8;
    let num_queries = 60;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 128;
    let num_constraints = 4048;
    let target_bits = 100;

    let options = ProofOptions::new(
        num_queries,
        blowup_factor,
        0,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );

    let (schedule, m) = super::plan_grinding_schedule_ldr(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        target_bits,
    );

    let summary = super::summarize_ldr(
        &options,
        base_field_bits,
        trace_length,
        num_constraints,
        num_committed_polys,
        target_bits,
        &schedule,
        m,
    );

    std::println!("{summary}");
}

#[test]
fn security_summary_display_udr() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let blowup_factor = 8;
    let num_queries = 110;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 128;
    let num_constraints = 4048;
    let target_bits = 110;

    let options = ProofOptions::new(
        num_queries,
        blowup_factor,
        0,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );

    let schedule = super::plan_grinding_schedule_udr(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        target_bits,
    );

    let summary = super::summarize_udr(
        &options,
        base_field_bits,
        trace_length,
        num_constraints,
        num_committed_polys,
        target_bits,
        &schedule,
    );

    std::println!("{summary}");
}

#[test]
fn find_min_queries_ldr() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let blowup_factor = 8;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 128;
    let num_constraints = 4048;
    let target_bits = 100;

    let base_options = ProofOptions::new(
        1, // placeholder, will be varied
        blowup_factor,
        0,
        field_extension,
        fri_folding_factor,
        fri_remainder_max_degree,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );

    // Find minimum queries for 2^20 grinding budget
    let min_queries = super::find_min_queries_ldr(
        &base_options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        20.0,
        target_bits,
    );

    assert!(min_queries.is_some());
    let q = min_queries.unwrap();
    std::println!("Min queries for 2^20 grinding budget: {q}");

    // Verify the result: grinding cost should be <= 20
    let verify_options = ProofOptions::new(
        q,
        blowup_factor,
        0,
        field_extension,
        fri_folding_factor,
        fri_remainder_max_degree,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );
    let grinding = super::find_min_grinding_ldr(
        &verify_options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
        target_bits,
    );
    assert!(grinding.is_some());
    assert!(grinding.unwrap() <= 20.0);

    // Sanity check: one fewer query should exceed the budget
    if q > 1 {
        let fewer_options = ProofOptions::new(
            q - 1,
            blowup_factor,
            0,
            field_extension,
            fri_folding_factor,
            fri_remainder_max_degree,
            BatchingMethod::Horner,
            BatchingMethod::Horner,
        );
        let grinding_fewer = super::find_min_grinding_ldr(
            &fewer_options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
            target_bits,
        );
        if let Some(g) = grinding_fewer {
            assert!(g > 20.0);
        }
    }
}

#[test]
fn extension_degree() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 85;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(18);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 94);

    // increasing the extension degree improves the FRI commit phase soundness error and permits
    // reaching 128 bits security
    let field_extension = FieldExtension::Cubic;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(list_decoding, 128);
}

#[test]
fn trace_length() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 80;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_1,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    let trace_length = 2_usize.pow(16);

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_2,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert!(security_1 <= security_2);
}

#[test]
fn num_fri_queries() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 60;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_1,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    let num_queries = 80;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_2,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert!(security_1 < security_2);
}

#[test]
fn blowup_factor() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 127;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 30;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(20);
    let num_committed_polys = 2;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_1,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    let blowup_factor = 16;

    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_2,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert!(security_1 < security_2);
}

#[test]
fn deep_batching_method_udr() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 255;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 120;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(16);
    let num_committed_polys = 1 << 1;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Algebraic,
    );
    let ProvenSecurity {
        unique_decoding: security_1,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_1, 106);

    // when the FRI batching error is not largest when compared to the other soundness error
    // terms, increasing the number of committed polynomials might not lead to a degradation
    // in the round-by-round soundness of the protocol
    let num_committed_polys = 1 << 2;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Algebraic,
    );
    let ProvenSecurity {
        unique_decoding: security_2,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 106);

    // but after a certain point, there will be a degradation
    let num_committed_polys = 1 << 5;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Algebraic,
    );
    let ProvenSecurity {
        unique_decoding: security_2,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 104);

    // and this degradation is on the order of log2(N - 1) where N is the number of
    // committed polynomials
    let num_committed_polys = num_committed_polys << 3;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Algebraic,
    );
    let ProvenSecurity {
        unique_decoding: security_2,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 101);
}

#[test]
fn deep_batching_method_ldr() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 255;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 120;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(22);
    let num_committed_polys = 1 << 1;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Algebraic,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_1,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_1, 128);

    // increasing the number of committed polynomials might lead to a degradation
    // in the round-by-round soundness of the protocol on the order of log2(N - 1) where
    // N is the number of committed polynomials. This happens when the FRI batching error
    // is the largest among all errors
    let num_committed_polys = 1 << 8;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Algebraic,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_2,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    // with improved Johnson-regime bounds, degradation may occur only for very large N;
    // ensure non-increase when increasing the number of committed polynomials
    assert!(security_2 <= security_1);
}

#[test]
fn constraints_batching_method_udr() {
    let field_extension = FieldExtension::Quadratic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 2;
    let fri_remainder_max_degree = 255;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 120;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(16);
    let num_committed_polys = 1 << 1;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: security_1,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_1, 108);

    // when the total number of constraints is on the order of the size of the LDE domain size
    // there is no degradation in the soundness error when using algebraic/curve batching
    // to batch constraints
    let num_constraints = trace_length * blowup_factor;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Algebraic,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: security_2,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 108);

    // but after a certain point, there will be a degradation
    let num_constraints = (trace_length * blowup_factor) << 2;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Algebraic,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: security_2,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 107);

    // and this degradation is on the order of log2(C - 1) where C is the total number of
    // constraints
    let num_constraints = num_constraints << 2;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Algebraic,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: security_2,
        list_decoding: _,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 105);
}

#[test]
fn constraints_batching_method_ldr() {
    let field_extension = FieldExtension::Cubic;
    let base_field_bits = BaseElement::MODULUS_BITS;
    let fri_folding_factor = 8;
    let fri_remainder_max_degree = 255;
    let grinding_factor = 20;
    let blowup_factor = 8;
    let num_queries = 120;
    let collision_resistance = 128;
    let trace_length = 2_usize.pow(22);
    let num_committed_polys = 1 << 1;
    let num_constraints = 100;

    let mut options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_1,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_1, 128);

    // when the total number of constraints is on the order of the size of the LDE domain size
    // square there is no degradation in the soundness error when using algebraic/curve batching
    // to batch constraints
    let num_constraints = (trace_length * blowup_factor).pow(2);
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Algebraic,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_2,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_2, 128);

    // and we have a good margin until we see any degradation in the soundness error
    let num_constraints = num_constraints << 12;
    options = ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        field_extension,
        fri_folding_factor as usize,
        fri_remainder_max_degree as usize,
        BatchingMethod::Algebraic,
        BatchingMethod::Linear,
    );
    let ProvenSecurity {
        unique_decoding: _,
        list_decoding: security_3,
    } = ProvenSecurity::compute(
        &options,
        base_field_bits,
        trace_length,
        collision_resistance,
        num_constraints,
        num_committed_polys,
    );

    assert_eq!(security_3, 125);
}

#[test]
fn ldr_lower_order_term_negligible() {
    // Show the lower-order term (proportional to (m + 0.5) * γ * ρ) contributes negligibly
    // to the commit-phase bound in the Johnson regime, using γ ≤ J(δ) = 1 - sqrt(ρ).
    // The bit impact is Δ_bits = log2(1 + R) where R = (3/2) * (γ * ρ) / (m + 0.5)^4.

    // Conservative concrete example from the comment: m = 3, ρ = 1/2.
    let m = 3.0;
    let rho = 0.5;
    let gamma = 1.0 - super::sqrt(rho);
    let a = m + 0.5;
    let r = 1.5 * (gamma * rho) / super::powf(a, 4.0);
    let delta_bits = super::log2(1.0 + r);
    assert!(delta_bits < 0.005);

    // Typical ranges: blowup in {2,4,8,16} ⇒ ρ ∈ {1/2,1/4,1/8,1/16};
    // m in {3,6,12,20}. The bound should stay well below 0.005 bits.
    for blowup in [2_usize, 4, 8, 16] {
        let rho = 1.0 / (blowup as f64);
        let gamma = 1.0 - super::sqrt(rho);
        for m in [3.0_f64, 6.0, 12.0, 20.0] {
            let a = m + 0.5;
            let r = 1.5 * (gamma * rho) / super::powf(a, 4.0);
            let delta_bits = super::log2(1.0 + r);
            assert!(delta_bits < 0.005);
        }
    }
}
