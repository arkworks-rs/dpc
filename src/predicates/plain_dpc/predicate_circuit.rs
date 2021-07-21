use crate::common::ToConstraintField;
use crate::constraints::Assignment;
use crate::ark_crypto_primitives::{CommitmentScheme, PRF};
use crate::dpc::plain_dpc::DPCRecord;
use crate::dpc::Record;
use crate::plain_dpc::*;
use algebra::bytes::ToBytes;
use r1cs_std::{uint8::UInt8, utils::AllocGadget};
use std::io::{Result as IoResult, Write};

use algebra::PairingEngine;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use crate::Error;

pub struct ConserveCircuit<C: PlainDPCComponents> {
    // Parameters
    comm_and_crh_parameters: Option<CommAndCRHPublicParameters<C>>,

    // Commitment to Predicate input.
    local_data_comm: Option<<C::LocalDataComm as CommitmentScheme>::Output>,
    position: u8,
}

impl<C: PlainDPCComponents> EmptyPredicateCircuit<C> {
    pub fn blank(comm_and_crh_parameters: &CommAndCRHPublicParameters<C>) -> Self {
        let local_data_comm = <C::LocalDataComm as CommitmentScheme>::Output::default();

        Self {
            comm_and_crh_parameters: Some(comm_and_crh_parameters.clone()),
            local_data_comm: Some(local_data_comm),
            position: 0u8,
        }
    }

    pub fn new(
        comm_amd_crh_parameters: &CommAndCRHPublicParameters<C>,
        local_data_comm: &<C::LocalDataComm as CommitmentScheme>::Output,
        position: u8,
    ) -> Self {
        Self {
            // Parameters
            comm_and_crh_parameters: Some(comm_amd_crh_parameters.clone()),

            // Other stuff
            local_data_comm: Some(local_data_comm.clone()),
            position,
        }
    }
}

impl<C: PlainDPCComponents> ConstraintSynthesizer<C::E> for EmptyPredicateCircuit<C> {
    fn generate_constraints<CS: ConstraintSystem<C::E>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let _position =
            UInt8::alloc_input_vec(ark_relations::ns!(cs, || "Alloc position"), &[self.position])?;

        {
            let mut cs = ark_relations::ns!(cs, || "Declare public parameters");
            let _local_data_comm_pp = <C::LocalDataCommGadget as CommitmentGadget<_, _>>::ParametersGadget::alloc_input_from_value(
                &mut ark_relations::ns!(cs, || "Declare Pred Input Comm parameters"),
                || self.comm_and_crh_parameters.get().map(|pp| &pp.local_data_comm_pp),
            )?;
        }

        let _local_data_comm =
            <C::LocalDataCommGadget as CommitmentGadget<_, _>>::OutputGadget::alloc_from_value(
                ark_relations::ns!(cs, || "Allocate predicate commitment"),
                || self.local_data_comm.get(),
            )?;

        {
            let mut cs = ark_relations::ns!(cs, || "Check that local data commitment is valid.");

            let mut local_data_bytes = Vec::new();
            for i in 0..C::NUM_INPUT_RECORDS {
                let mut cs =
                    ark_relations::ns!(cs, || format!("Construct local data with Input Record"));
                local_data_bytes.extend_from_slice(
                    &old_rec_comms[i].to_bytes(&mut ark_relations::ns!(cs, || "Record Comm"))?,
                );
                local_data_bytes
                    .extend_from_slice(&old_apks[i].to_bytes(&mut ark_relations::ns!(cs, || "Apk"))?);
                local_data_bytes.extend_from_slice(
                    &old_dummy_flags[i].to_bytes(&mut ark_relations::ns!(cs, || "IsDummy"))?,
                );
                local_data_bytes.extend_from_slice(&old_payloads[i]);
                local_data_bytes.extend_from_slice(&old_birth_pred_hashes[i]);
                local_data_bytes.extend_from_slice(&old_death_pred_hashes[i]);
                local_data_bytes
                    .extend_from_slice(&old_sns[i].to_bytes(&mut ark_relations::ns!(cs, || "Sn"))?);
            }

            for j in 0..C::NUM_OUTPUT_RECORDS {
                let mut cs =
                    ark_relations::ns!(cs, || format!("Construct local data with Output Record"));
                local_data_bytes.extend_from_slice(
                    &new_rec_comms[j].to_bytes(&mut ark_relations::ns!(cs, || "Record Comm"))?,
                );
                local_data_bytes
                    .extend_from_slice(&new_apks[j].to_bytes(&mut ark_relations::ns!(cs, || "Apk"))?);
                local_data_bytes.extend_from_slice(
                    &new_dummy_flags[j].to_bytes(&mut ark_relations::ns!(cs, || "IsDummy"))?,
                );
                local_data_bytes.extend_from_slice(&new_payloads[j]);
                local_data_bytes.extend_from_slice(&new_birth_pred_hashes[j]);
                local_data_bytes.extend_from_slice(&new_death_pred_hashes[j]);
            }
            let memo = UInt8::alloc_input_vec(ark_relations::ns!(cs, || "Allocate memorandum"), memo)?;
            local_data_bytes.extend_from_slice(&memo);

            let auxiliary =
                UInt8::alloc_vec(ark_relations::ns!(cs, || "Allocate auxiliary input"), auxiliary)?;
            local_data_bytes.extend_from_slice(&auxiliary);

            let local_data_comm_rand = <C::LocalDataCommGadget as CommitmentGadget<_, _>>::RandomnessGadget::alloc_from_value(
                ark_relations::ns!(cs, || "Allocate local data commitment randomness"),
                || Ok(local_data_rand)
            )?;

            let declared_local_data_comm = <C::LocalDataCommGadget as CommitmentGadget<_, _>>::OutputGadget::alloc_input_from_value(
                ark_relations::ns!(cs, || "Allocate local data commitment"),
                || self.local_data_comm.get()
            )?;

            let comm = C::LocalDataCommGadget::check_commitment_gadget(
                ark_relations::ns!(cs, || "Commit to local data"),
                &local_data_comm_pp,
                &local_data_bytes,
                &local_data_comm_rand,
            )?;

            comm.enforce_equal(
                &mut ark_relations::ns!(cs, || "Check that local data commitment is valid"),
                &declared_local_data_comm,
            )?;
        }

        Ok(())
    }
}
