pub mod delegable_dpc;
pub mod plain_dpc;

pub trait Assignment<T> {
    fn get(&self) -> Result<&T, ark_relations::r1cs::SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, ark_relations::r1cs::SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(ark_relations::r1cs::SynthesisError::AssignmentMissing),
        }
    }
}
