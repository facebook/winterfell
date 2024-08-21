#[derive(Debug, thiserror::Error)]
pub enum SumCheckProverError {
    #[error("number of rounds for sum-check must be greater than zero")]
    NumRoundsZero,
    #[error("the number of rounds is greater than the number of variables")]
    TooManyRounds,
    #[error("should provide at least one multi-linear polynomial as input")]
    NoMlsProvided,
    #[error("failed to generate round challenge")]
    FailedToGenerateChallenge,
    #[error("the provided multi-linears have different arities")]
    MlesDifferentArities,
    #[error("multi-linears should have at least one variable")]
    AtLeastOneVariable,
}
