use crate::dpc::plain_dpc::PlainDPCComponents;
use ark_crypto_primitives::{CommitmentScheme, CRH, SNARK};

#[derive(Derivative)]
#[derivative(Clone(bound = "C: PlainDPCComponents"))]
pub struct CommAndCRHPublicParameters<C: PlainDPCComponents> {
    pub addr_comm_pp: <C::AddrC as CommitmentScheme>::Parameters,
    pub rec_comm_pp: <C::RecC as CommitmentScheme>::Parameters,
    pub pred_vk_comm_pp: <C::PredVkComm as CommitmentScheme>::Parameters,
    pub local_data_comm_pp: <C::LocalDataComm as CommitmentScheme>::Parameters,

    pub sn_nonce_crh_pp: <C::SnNonceH as CRH>::Parameters,
    pub pred_vk_crh_pp: <C::PredVkH as CRH>::Parameters,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: PlainDPCComponents"))]
pub struct PredNIZKParameters<C: PlainDPCComponents> {
    pub pk: <C::PredicateNIZK as SNARK>::ProvingKey,
    pub vk: <C::PredicateNIZK as SNARK>::VerifyingKey,
    pub proof: <C::PredicateNIZK as SNARK>::Proof,
}

pub struct PublicParameters<C: PlainDPCComponents> {
    pub comm_and_crh_pp: CommAndCRHPublicParameters<C>,
    pub pred_nizk_pp: PredNIZKParameters<C>,
    pub proof_check_nizk_pp: (
        <C::ProofCheckNIZK as SNARK>::ProvingKey,
        <C::ProofCheckNIZK as SNARK>::ProcessedVerifyingKey,
    ),
    pub core_nizk_pp: (
        <C::MainNIZK as SNARK>::ProvingKey,
        <C::MainNIZK as SNARK>::ProcessedVerifyingKey,
    ),
}

impl<C: PlainDPCComponents> PublicParameters<C> {
    pub fn core_check_nizk_pp(
        &self,
    ) -> &(
        <C::MainNIZK as SNARK>::ProvingKey,
        <C::MainNIZK as SNARK>::ProcessedVerifyingKey,
    ) {
        &self.core_nizk_pp
    }

    pub fn proof_check_nizk_pp(
        &self,
    ) -> &(
        <C::ProofCheckNIZK as SNARK>::ProvingKey,
        <C::ProofCheckNIZK as SNARK>::ProcessedVerifyingKey,
    ) {
        &self.proof_check_nizk_pp
    }

    pub fn pred_nizk_pp(&self) -> &PredNIZKParameters<C> {
        &self.pred_nizk_pp
    }

    pub fn sn_nonce_crh_pp(&self) -> &<C::SnNonceH as CRH>::Parameters {
        &self.comm_and_crh_pp.sn_nonce_crh_pp
    }

    pub fn pred_vk_crh_pp(&self) -> &<C::PredVkH as CRH>::Parameters {
        &self.comm_and_crh_pp.pred_vk_crh_pp
    }

    pub fn local_data_comm_pp(&self) -> &<C::LocalDataComm as CommitmentScheme>::Parameters {
        &self.comm_and_crh_pp.local_data_comm_pp
    }

    pub fn addr_comm_pp(&self) -> &<C::AddrC as CommitmentScheme>::Parameters {
        &self.comm_and_crh_pp.addr_comm_pp
    }

    pub fn rec_comm_pp(&self) -> &<C::RecC as CommitmentScheme>::Parameters {
        &self.comm_and_crh_pp.rec_comm_pp
    }

    pub fn pred_vk_comm_pp(&self) -> &<C::PredVkComm as CommitmentScheme>::Parameters {
        &self.comm_and_crh_pp.pred_vk_comm_pp
    }
}
