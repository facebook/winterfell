use super::StarkProof;

#[test]
pub fn starkproof_new_dummy_doesnt_panic() {
    let _ = StarkProof::new_dummy();
}
