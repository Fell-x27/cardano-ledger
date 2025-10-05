//! Rust representations of STS predicate failure types extracted from the
//! Cardano ledger `Rules` modules across eras.
//!
//! NOTE: These definitions focus on the structure and CBOR tags of the
//! predicate failure enums. Domain-specific payload types are represented by
//! lightweight stand-ins so the relationships between failures remain clear.
//! Any field marked with `TODO` should be replaced with the concrete type when
//! wiring these definitions into real code.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

// ---------------------------------------------------------------------------
// Helper stand-ins
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Coin(pub u64); // `coin = uint` in the CDDL specs.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DeltaCoin(pub i64); // `delta_coin = int` in the CDDL specs.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SlotNo(pub u64); // `slot_no = uint .size 8`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EpochNo(pub u64); // `epoch_no = uint .size 8`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NetworkId(pub u8); // `network_id = 0 / 1`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Addr(pub Vec<u8>); // Reward/payment addresses are CBOR byte strings.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RewardAccount(pub Vec<u8>); // `reward_account = bytes`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash28(pub [u8; 28]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash32(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ScriptHash(pub Hash28); // `script_hash = hash28`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DataHash(pub Hash32); // Various datum hashes use 32-byte hashes.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ScriptIntegrityHash(pub Hash32); // Matches the 32-byte hash usage.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxAuxDataHash(pub Hash32); // `auxiliary_data_hash = hash32`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxId(pub Hash32); // `transaction_id = hash32`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxIx(pub u16); // `transaction_input = [tx_id, index : uint .size 2]`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxIn {
    pub transaction_id: TxId,
    pub index: TxIx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProtVer {
    pub major: u16, // `major_protocol_version = 0 .. 12`.
    pub minor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ExUnits {
    pub mem: u64,
    pub steps: u64,
} // `ex_units = [mem : uint, steps : uint]`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ValidityInterval {
    pub invalid_before: Option<SlotNo>,
    pub invalid_hereafter: Option<SlotNo>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PoolCert; // TODO: expand using the certificates CDDL rules.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MIRPot; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UTxO<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxOut<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxCert<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Tx<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Value<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeyHash<Role>(pub PhantomData<Role>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VKey<Role>(pub PhantomData<Role>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VRFVerKeyHash<Role>(pub PhantomData<Role>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Credential<Role>(pub PhantomData<Role>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Withdrawals(pub BTreeMap<RewardAccount, Coin>); // `withdrawals = {+ reward_account => coin}`.

pub type StrictMaybe<T> = Option<T>;
pub type Natural = u64;
pub type Word32 = u32;
pub type ByteString = Vec<u8>;
pub type TagMismatchDescription = String;
pub type IsValid = bool;
pub type Text = String;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NonEmpty<T>(pub Vec<T>); // TODO: enforce the invariant.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct WitnessRole;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StakingRole;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StakePoolRole;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ColdCommitteeRole;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HotCommitteeRole;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DRepRole;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovActionIx(pub u16);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovActionId {
    pub tx_id: TxId,
    pub action_index: GovActionIx,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovAction<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProposalProcedure<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VotingProcedures<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Proposals<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovEnv<Era>(pub PhantomData<Era>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Voter(pub PhantomData<()>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovPurposeId<Purpose>(pub PhantomData<Purpose>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HardForkPurpose;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlutusPurpose<Tag, Era>(pub PhantomData<(Tag, Era)>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AsItem;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AsIx;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Mismatch<Relation, T> {
    pub supplied: T,
    pub expected: T,
    pub _relation: PhantomData<Relation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelEQ;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelLTEQ;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelGTEQ;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelLT;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelGT;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelSubset;

// ---------------------------------------------------------------------------
// Shelley era predicate failures
// ---------------------------------------------------------------------------

pub mod shelley {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum VotingPeriod {
        /// Tag: 0
        VoteForThisEpoch,
        /// Tag: 1
        VoteForNextEpoch,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PpupPredicateFailure {
        /// Tag: 0
        NonGenesisUpdatePPUP {
            offending_keys: Mismatch<RelSubset, BTreeSet<KeyHash<'static>>>,
        },
        /// Tag: 1
        PPUpdateWrongEpoch {
            current_epoch: EpochNo,
            declared_epoch: EpochNo,
            voting_period: VotingPeriod,
        },
        /// Tag: 2
        PVCannotFollowPPUP {
            proposed_version: ProtVer,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxoPredicateFailure<Era> {
        /// Tag: 0
        BadInputsUTxO {
            invalid_inputs: BTreeSet<TxIn>,
        },
        /// Tag: 1
        ExpiredUTxO {
            current_slot: SlotNo,
        },
        /// Tag: 2
        MaxTxSizeUTxO {
            size_mismatch: Mismatch<RelLTEQ, usize>,
        },
        /// Tag: 3
        InputSetEmptyUTxO,
        /// Tag: 4
        FeeTooSmallUTxO {
            fee_mismatch: Mismatch<RelGTEQ, Coin>,
        },
        /// Tag: 5
        ValueNotConservedUTxO {
            balance_mismatch: Mismatch<RelEQ, Value<Era>>,
        },
        /// Tag: 6
        OutputTooSmallUTxO {
            tiny_outputs: Vec<TxOut<Era>>,
        },
        /// Tag: 7
        UpdateFailure(super::shelley::PpupPredicateFailure),
        /// Tag: 8
        WrongNetwork {
            expected: NetworkId,
            offending: BTreeSet<Addr>,
        },
        /// Tag: 9
        WrongNetworkWithdrawal {
            expected: NetworkId,
            offending: BTreeSet<RewardAccount>,
        },
        /// Tag: 10
        OutputBootAddrAttrsTooBig {
            oversized_bootstrap_outputs: Vec<TxOut<Era>>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxowPredicateFailure<Era> {
        /// Tag: 0
        InvalidWitnessesUTXOW {
            invalid_witnesses: Vec<Credential<'static>>,
        },
        /// Tag: 1
        MissingVKeyWitnessesUTXOW {
            missing_signers: BTreeSet<KeyHash<'static>>,
        },
        /// Tag: 2
        MissingScriptWitnessesUTXOW {
            missing_scripts: BTreeSet<ScriptHash>,
        },
        /// Tag: 3
        ScriptWitnessNotValidatingUTXOW {
            failed_scripts: BTreeSet<ScriptHash>,
        },
        /// Tag: 4
        UtxoFailure(super::shelley::UtxoPredicateFailure<Era>),
        /// Tag: 5
        MIRInsufficientGenesisSigsUTXOW {
            missing_signatures: BTreeSet<KeyHash<'static>>,
        },
        /// Tag: 6
        MissingTxBodyMetadataHash {
            expected: TxAuxDataHash,
        },
        /// Tag: 7
        MissingTxMetadata {
            referenced: TxAuxDataHash,
        },
        /// Tag: 8
        ConflictingMetadataHash {
            mismatch: Mismatch<RelEQ, TxAuxDataHash>,
        },
        /// Tag: 9
        InvalidMetadata,
        /// Tag: 10
        ExtraneousScriptWitnessesUTXOW {
            extra_scripts: BTreeSet<ScriptHash>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DelegPredicateFailure {
        /// Tag: 0
        StakeKeyAlreadyRegistered {
            credential: Credential<'static>,
        },
        /// Tag: 1
        StakeKeyNotRegistered {
            credential: Credential<'static>,
        },
        /// Tag: 2
        StakeKeyNonZeroAccountBalance {
            remaining_balance: Coin,
        },
        /// Tag: 3
        StakeDelegationImpossible {
            credential: Credential<'static>,
        },
        /// Tag: 4
        WrongCertificateType,
        /// Tag: 5
        GenesisKeyNotInMapping {
            genesis_key: KeyHash<'static>,
        },
        /// Tag: 6
        DuplicateGenesisDelegate {
            delegate: KeyHash<'static>,
        },
        /// Tag: 7
        InsufficientForInstantaneousRewards {
            pot: MIRPot,
            bound: Mismatch<RelLTEQ, Coin>,
        },
        /// Tag: 8
        MIRCertificateTooLateInEpoch {
            cutoff: Mismatch<RelLT, SlotNo>,
        },
        /// Tag: 9
        DuplicateGenesisVRF {
            vrf: VRFVerKeyHash<'static>,
        },
        /// Tag: 11
        MIRTransferNotCurrentlyAllowed,
        /// Tag: 12
        MIRNegativesNotCurrentlyAllowed,
        /// Tag: 13
        InsufficientForTransfer {
            pot: MIRPot,
            bound: Mismatch<RelLTEQ, Coin>,
        },
        /// Tag: 14
        MIRProducesNegativeUpdate,
        /// Tag: 15
        MIRNegativeTransfer {
            pot: MIRPot,
            attempted: Coin,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PoolPredicateFailure {
        /// Tag: 0
        StakePoolNotRegisteredOnKey {
            pool_id: KeyHash<'static>,
        },
        /// Tag: 1
        StakePoolRetirementWrongEpoch {
            retirement_too_early: Mismatch<RelGT, EpochNo>,
            retirement_too_late: Mismatch<RelLTEQ, EpochNo>,
        },
        /// Tag: 3
        StakePoolCostTooLow {
            cost_bound: Mismatch<RelGTEQ, Coin>,
        },
        /// Tag: 4
        WrongNetwork {
            network_mismatch: Mismatch<RelEQ, NetworkId>,
            pool_id: KeyHash<'static>,
        },
        /// Tag: 5
        PoolMetadataHashTooBig {
            pool_id: KeyHash<'static>,
            hash_size: usize,
        },
        /// Tag: 6
        VRFKeyHashAlreadyRegistered {
            pool_id: KeyHash<'static>,
            vrf: VRFVerKeyHash<'static>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DelegsPredicateFailure<Era> {
        /// Tag: 0
        DelegateeNotRegistered {
            pool_id: KeyHash<'static>,
        },
        /// Tag: 1
        WithdrawalsNotInRewards {
            withdrawals: Withdrawals,
        },
        /// Tag: 2
        DelplFailure(DelplPredicateFailure<Era>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DelplPredicateFailure<Era> {
        /// Tag: 0
        PoolFailure(PoolPredicateFailure),
        /// Tag: 1
        DelegFailure(DelegPredicateFailure),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LedgerPredicateFailure<Era> {
        /// Tag: 0
        UtxowFailure(UtxowPredicateFailure<Era>),
        /// Tag: 1
        DelegsFailure(DelegsPredicateFailure<Era>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BbodyPredicateFailure<Era> {
        // No explicit CBOR instance in the source; tags unknown.
        WrongBlockBodySizeBBODY {
            mismatch: Mismatch<RelEQ, usize>,
        },
        InvalidBodyHashBBODY {
            mismatch: Mismatch<RelEQ, [u8; 32]>, // TODO: real hash type
        },
        LedgersFailure(LedgersPredicateFailure<Era>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LedgersPredicateFailure<Era> {
        /// Tag 0 relayed through `ShelleyBbodyPredFailure`
        LedgersFailure(LedgerPredicateFailure<Era>),
        /// TODO: capture other constructors when serialisation is required.
    }

    // TODO: Mirror the remaining Shelley-era failures (e.g. MIR, TICK) if
    // serialisation details become relevant.
}

// ---------------------------------------------------------------------------
// Allegra & Mary era predicate failures
// ---------------------------------------------------------------------------

pub mod allegra {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxoPredicateFailure<Era> {
        /// Tag: 0 (mirrors Shelley via translation layer)
        AlonzoWrapped(super::alonzo::UtxoPredicateFailure<Era>),
        /// Tag: 1
        ValidateOutsideValidityInterval {
            interval: ValidityInterval,
        },
        // TODO: complete once allegra-specific constructors are required.
    }

    // Mary reuses Allegra failures; see the `mary` module for explicit aliases.
}

pub mod mary {
    use super::*;

    pub type UtxoPredicateFailure<Era> = super::allegra::UtxoPredicateFailure<Era>;
}

// ---------------------------------------------------------------------------
// Alonzo era predicate failures
// ---------------------------------------------------------------------------

pub mod alonzo {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BbodyPredicateFailure<Era> {
        /// Tag: 0
        ShelleyInAlonzo(super::shelley::BbodyPredicateFailure<Era>),
        /// Tag: 1
        TooManyExUnits {
            bound: Mismatch<RelLTEQ, ExUnits>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxoPredicateFailure<Era> {
        /// Tag: 0
        BadInputsUTxO {
            invalid_inputs: BTreeSet<TxIn>,
        },
        /// Tag: 1
        OutsideValidityIntervalUTxO {
            interval: ValidityInterval,
            current_slot: SlotNo,
        },
        /// Tag: 2
        MaxTxSizeUTxO {
            bound: Mismatch<RelLTEQ, u32>,
        },
        /// Tag: 3
        InputSetEmptyUTxO,
        /// Tag: 4
        FeeTooSmallUTxO {
            bound: Mismatch<RelGTEQ, Coin>,
        },
        /// Tag: 5
        ValueNotConservedUTxO {
            mismatch: Mismatch<RelEQ, Value<Era>>,
        },
        /// Tag: 6
        OutputTooSmallUTxO {
            outputs: Vec<TxOut<Era>>,
        },
        /// Tag: 7
        UtxosFailure(UtxosPredicateFailure<Era>),
        /// Tag: 8
        WrongNetwork {
            expected: NetworkId,
            offending: BTreeSet<Addr>,
        },
        /// Tag: 9
        WrongNetworkWithdrawal {
            expected: NetworkId,
            offending: BTreeSet<RewardAccount>,
        },
        /// Tag: 10
        OutputBootAddrAttrsTooBig {
            outputs: Vec<TxOut<Era>>,
        },
        /// Tag: 12
        OutputTooBigUTxO {
            oversized_outputs: Vec<(i32, i32, TxOut<Era>)>,
        },
        /// Tag: 13
        InsufficientCollateral {
            computed: DeltaCoin,
            required: Coin,
        },
        /// Tag: 14
        ScriptsNotPaidUTxO {
            offending_utxo: UTxO<Era>,
        },
        /// Tag: 15
        ExUnitsTooBigUTxO {
            bound: Mismatch<RelLTEQ, ExUnits>,
        },
        /// Tag: 16
        CollateralContainsNonADA {
            value: Value<Era>,
        },
        /// Tag: 17
        WrongNetworkInTxBody {
            mismatch: Mismatch<RelEQ, NetworkId>,
        },
        /// Tag: 18
        OutsideForecast {
            slot: SlotNo,
        },
        /// Tag: 19
        TooManyCollateralInputs {
            bound: Mismatch<RelLTEQ, usize>,
        },
        /// Tag: 20
        NoCollateralInputs,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FailureDescription {
        /// Tag: 0
        PassedUnexpectedly,
        /// Tag: 1
        FailedUnexpectedly(Vec<FailureDescription>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxosPredicateFailure<Era> {
        /// Tag: 0
        ValidationTagMismatch {
            is_valid: bool,
            description: FailureDescription,
        },
        /// Tag: 1
        CollectErrors {
            errors: Vec<CollectError<Era>>,
        },
        /// Tag: 2
        UpdateFailure(super::shelley::PpupPredicateFailure),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CollectError<Era> {
        // Placeholder; see `collectTwoPhaseScriptInputs` for full shape.
        /// TODO: encode exact variants from `CollectError`.
        Placeholder(PhantomData<Era>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxowPredicateFailure<Era> {
        /// Tag: 0
        ShelleyInAlonzo(super::shelley::UtxowPredicateFailure<Era>),
        /// Tag: 1
        MissingRedeemers {
            missing: Vec<(PlutusPurpose<AsItem, Era>, ScriptHash)>,
        },
        /// Tag: 2
        MissingRequiredDatums {
            missing_hashes: BTreeSet<DataHash>,
            provided_hashes: BTreeSet<DataHash>,
        },
        /// Tag: 3
        NotAllowedSupplementalDatums {
            forbidden_hashes: BTreeSet<DataHash>,
            permitted: BTreeSet<DataHash>,
        },
        /// Tag: 4
        PPViewHashesDontMatch {
            mismatch: Mismatch<RelEQ, StrictMaybe<ScriptIntegrityHash>>,
        },
        /// Tag: 6
        UnspendableUTxONoDatumHash {
            inputs: BTreeSet<TxIn>,
        },
        /// Tag: 7
        ExtraRedeemers {
            extra: Vec<PlutusPurpose<AsIx, Era>>,
        },
        /// Tag: 8
        ScriptIntegrityHashMismatch {
            mismatch: Mismatch<RelEQ, StrictMaybe<ScriptIntegrityHash>>,
            provided: StrictMaybe<Vec<u8>>,
        },
    }

}

// ---------------------------------------------------------------------------
// Babbage era predicate failures
// ---------------------------------------------------------------------------

pub mod babbage {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxoPredicateFailure<Era> {
        /// Tag: 1
        AlonzoInBabbage(super::alonzo::UtxoPredicateFailure<Era>),
        /// Tag: 2
        IncorrectTotalCollateralField {
            provided: DeltaCoin,
            declared: Coin,
        },
        /// Tag: 3
        OutputTooSmall {
            outputs: Vec<(TxOut<Era>, Coin)>,
        },
        /// Tag: 4
        NonDisjointReferenceInputs {
            overlapping: Vec<TxIn>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxowPredicateFailure<Era> {
        /// Tag: 1
        AlonzoInBabbage(super::alonzo::UtxowPredicateFailure<Era>),
        /// Tag: 2
        UtxoFailure(UtxoPredicateFailure<Era>),
        /// Tag: 3
        MalformedScriptWitnesses {
            witnesses: BTreeSet<ScriptHash>,
        },
        /// Tag: 4
        MalformedReferenceScripts {
            scripts: BTreeSet<ScriptHash>,
        },
        /// Tag: 5
        ScriptIntegrityHashMismatch {
            mismatch: Mismatch<RelEQ, StrictMaybe<ScriptIntegrityHash>>,
            provided: StrictMaybe<Vec<u8>>,
        },
    }

    // TODO: Extend with Babbage-specific ledgers/bbody predicate failures when
    // serialisation hooks are required.
}

// ---------------------------------------------------------------------------
// Conway era predicate failures
// ---------------------------------------------------------------------------

pub mod conway {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxosPredicateFailure<Era> {
        /// Tag: 0
        ValidationTagMismatch {
            tag: IsValid,
            description: TagMismatchDescription,
        },
        /// Tag: 1
        CollectErrors {
            errors: Vec<super::alonzo::CollectError<Era>>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxoPredicateFailure<Era> {
        /// Tag: 0
        UtxosFailure(UtxosPredicateFailure<Era>),
        /// Tag: 1
        BadInputsUTxO {
            invalid_inputs: BTreeSet<TxIn>,
        },
        /// Tag: 2
        OutsideValidityIntervalUTxO {
            validity_interval: ValidityInterval,
            current_slot: SlotNo,
        },
        /// Tag: 3
        MaxTxSizeUTxO {
            size_mismatch: Mismatch<RelLTEQ, Word32>,
        },
        /// Tag: 4
        InputSetEmptyUTxO,
        /// Tag: 5
        FeeTooSmallUTxO {
            fee_mismatch: Mismatch<RelGTEQ, Coin>,
        },
        /// Tag: 6
        ValueNotConservedUTxO {
            balance_mismatch: Mismatch<RelEQ, Value<Era>>,
        },
        /// Tag: 7
        WrongNetwork {
            expected: NetworkId,
            offending: BTreeSet<Addr>,
        },
        /// Tag: 8
        WrongNetworkWithdrawal {
            expected: NetworkId,
            offending: BTreeSet<RewardAccount>,
        },
        /// Tag: 9
        OutputTooSmallUTxO {
            tiny_outputs: Vec<TxOut<Era>>,
        },
        /// Tag: 10
        OutputBootAddrAttrsTooBig {
            oversized_bootstrap_outputs: Vec<TxOut<Era>>,
        },
        /// Tag: 11
        OutputTooBigUTxO {
            // (actual_size, max_size, output)
            outputs: Vec<(i64, i64, TxOut<Era>)>,
        },
        /// Tag: 12
        InsufficientCollateral {
            provided: DeltaCoin,
            required: Coin,
        },
        /// Tag: 13
        ScriptsNotPaidUTxO {
            unpaid: UTxO<Era>,
        },
        /// Tag: 14
        ExUnitsTooBigUTxO {
            limit_mismatch: Mismatch<RelLTEQ, ExUnits>,
        },
        /// Tag: 15
        CollateralContainsNonADA {
            offending_value: Value<Era>,
        },
        /// Tag: 16
        WrongNetworkInTxBody {
            mismatch: Mismatch<RelEQ, NetworkId>,
        },
        /// Tag: 17
        OutsideForecast {
            slot: SlotNo,
        },
        /// Tag: 18
        TooManyCollateralInputs {
            bound: Mismatch<RelLTEQ, Natural>,
        },
        /// Tag: 19
        NoCollateralInputs,
        /// Tag: 20
        IncorrectTotalCollateralField {
            provided: DeltaCoin,
            declared: Coin,
        },
        /// Tag: 21
        BabbageOutputTooSmallUTxO {
            outputs: Vec<(TxOut<Era>, Coin)>,
        },
        /// Tag: 22
        BabbageNonDisjointRefInputs {
            overlapping: NonEmpty<TxIn>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum UtxowPredicateFailure<Era> {
        /// Tag: 0
        UtxoFailure(UtxoPredicateFailure<Era>),
        /// Tag: 1
        InvalidWitnessesUTXOW {
            witnesses: Vec<VKey<WitnessRole>>,
        },
        /// Tag: 2
        MissingVKeyWitnessesUTXOW {
            missing: BTreeSet<KeyHash<WitnessRole>>,
        },
        /// Tag: 3
        MissingScriptWitnessesUTXOW {
            missing: BTreeSet<ScriptHash>,
        },
        /// Tag: 4
        ScriptWitnessNotValidatingUTXOW {
            failing: BTreeSet<ScriptHash>,
        },
        /// Tag: 5
        MissingTxBodyMetadataHash {
            expected: TxAuxDataHash,
        },
        /// Tag: 6
        MissingTxMetadata {
            expected: TxAuxDataHash,
        },
        /// Tag: 7
        ConflictingMetadataHash {
            mismatch: Mismatch<RelEQ, TxAuxDataHash>,
        },
        /// Tag: 8
        InvalidMetadata,
        /// Tag: 9
        ExtraneousScriptWitnessesUTXOW {
            extraneous: BTreeSet<ScriptHash>,
        },
        /// Tag: 10
        MissingRedeemers {
            missing: Vec<(PlutusPurpose<AsItem, Era>, ScriptHash)>,
        },
        /// Tag: 11
        MissingRequiredDatums {
            missing_hashes: BTreeSet<DataHash>,
            provided_hashes: BTreeSet<DataHash>,
        },
        /// Tag: 12
        NotAllowedSupplementalDatums {
            disallowed_hashes: BTreeSet<DataHash>,
            allowed: BTreeSet<DataHash>,
        },
        /// Tag: 13
        PPViewHashesDontMatch {
            mismatch: Mismatch<RelEQ, StrictMaybe<ScriptIntegrityHash>>,
        },
        /// Tag: 14
        UnspendableUTxONoDatumHash {
            inputs: BTreeSet<TxIn>,
        },
        /// Tag: 15
        ExtraRedeemers {
            extra: Vec<PlutusPurpose<AsIx, Era>>,
        },
        /// Tag: 16
        MalformedScriptWitnesses {
            scripts: BTreeSet<ScriptHash>,
        },
        /// Tag: 17
        MalformedReferenceScripts {
            scripts: BTreeSet<ScriptHash>,
        },
        /// Tag: 18
        ScriptIntegrityHashMismatch {
            mismatch: Mismatch<RelEQ, StrictMaybe<ScriptIntegrityHash>>,
            provided: StrictMaybe<ByteString>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DelegPredicateFailure {
        /// Tag: 1
        IncorrectDepositDELEG {
            deposit: Coin,
        },
        /// Tag: 2
        StakeKeyRegisteredDELEG {
            stake_credential: Credential<StakingRole>,
        },
        /// Tag: 3
        StakeKeyNotRegisteredDELEG {
            stake_credential: Credential<StakingRole>,
        },
        /// Tag: 4
        StakeKeyHasNonZeroRewardAccountBalanceDELEG {
            balance: Coin,
        },
        /// Tag: 5
        DelegateeDRepNotRegisteredDELEG {
            delegatee: Credential<DRepRole>,
        },
        /// Tag: 6
        DelegateeStakePoolNotRegisteredDELEG {
            delegatee: KeyHash<StakePoolRole>,
        },
        /// Tag: 7
        DepositIncorrectDELEG {
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 8
        RefundIncorrectDELEG {
            mismatch: Mismatch<RelEQ, Coin>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum GovCertPredicateFailure {
        /// Tag: 0
        ConwayDRepAlreadyRegistered {
            credential: Credential<DRepRole>,
        },
        /// Tag: 1
        ConwayDRepNotRegistered {
            credential: Credential<DRepRole>,
        },
        /// Tag: 2
        ConwayDRepIncorrectDeposit {
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 3
        ConwayCommitteeHasPreviouslyResigned {
            cold_credential: Credential<ColdCommitteeRole>,
        },
        /// Tag: 4
        ConwayDRepIncorrectRefund {
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 5
        ConwayCommitteeIsUnknown {
            cold_credential: Credential<ColdCommitteeRole>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CertPredicateFailure<Era> {
        /// Tag: 1
        DelegFailure(DelegPredicateFailure),
        /// Tag: 2
        PoolFailure(super::shelley::PoolPredicateFailure),
        /// Tag: 3
        GovCertFailure(GovCertPredicateFailure),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CertsPredicateFailure<Era> {
        /// Tag: 0
        WithdrawalsNotInRewardsCERTS {
            withdrawals: Withdrawals,
        },
        /// Tag: 1
        CertFailure(CertPredicateFailure<Era>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum GovPredicateFailure<Era> {
        /// Tag: 0
        GovActionsDoNotExist {
            missing: NonEmpty<GovActionId>,
        },
        /// Tag: 1
        MalformedProposal {
            proposal: GovAction<Era>,
        },
        /// Tag: 2
        ProposalProcedureNetworkIdMismatch {
            reward_account: RewardAccount,
            expected_network: NetworkId,
        },
        /// Tag: 3
        TreasuryWithdrawalsNetworkIdMismatch {
            offending_accounts: BTreeSet<RewardAccount>,
            expected_network: NetworkId,
        },
        /// Tag: 4
        ProposalDepositIncorrect {
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 5
        DisallowedVoters {
            voters: NonEmpty<(Voter, GovActionId)>,
        },
        /// Tag: 6
        ConflictingCommitteeUpdate {
            members: BTreeSet<Credential<ColdCommitteeRole>>,
        },
        /// Tag: 7
        ExpirationEpochTooSmall {
            expired: BTreeMap<Credential<ColdCommitteeRole>, EpochNo>,
        },
        /// Tag: 8
        InvalidPrevGovActionId {
            proposal: ProposalProcedure<Era>,
        },
        /// Tag: 9
        VotingOnExpiredGovAction {
            votes: NonEmpty<(Voter, GovActionId)>,
        },
        /// Tag: 10
        ProposalCantFollow {
            previous: StrictMaybe<GovPurposeId<HardForkPurpose>>,
            version_mismatch: Mismatch<RelGT, ProtVer>,
        },
        /// Tag: 11
        InvalidPolicyHash {
            provided: StrictMaybe<ScriptHash>,
            expected: StrictMaybe<ScriptHash>,
        },
        /// Tag: 12
        DisallowedProposalDuringBootstrap {
            proposal: ProposalProcedure<Era>,
        },
        /// Tag: 13
        DisallowedVotesDuringBootstrap {
            votes: NonEmpty<(Voter, GovActionId)>,
        },
        /// Tag: 14
        VotersDoNotExist {
            voters: NonEmpty<Voter>,
        },
        /// Tag: 15
        ZeroTreasuryWithdrawals {
            action: GovAction<Era>,
        },
        /// Tag: 16
        ProposalReturnAccountDoesNotExist {
            reward_account: RewardAccount,
        },
        /// Tag: 17
        TreasuryWithdrawalReturnAccountsDoNotExist {
            reward_accounts: NonEmpty<RewardAccount>,
        },
        /// Tag: 18
        UnelectedCommitteeVoters {
            voters: NonEmpty<Credential<HotCommitteeRole>>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LedgerPredicateFailure<Era> {
        /// Tag: 1
        ConwayUtxowFailure(UtxowPredicateFailure<Era>),
        /// Tag: 2
        ConwayCertsFailure(CertsPredicateFailure<Era>),
        /// Tag: 3
        ConwayGovFailure(GovPredicateFailure<Era>),
        /// Tag: 4
        ConwayWdrlNotDelegatedToDRep {
            withdrawals: NonEmpty<KeyHash<StakingRole>>,
        },
        /// Tag: 5
        ConwayTreasuryValueMismatch {
            // Serialisation swaps supplied/expected relative to this struct.
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 6
        ConwayTxRefScriptsSizeTooBig {
            size_mismatch: Mismatch<RelLTEQ, i64>,
        },
        /// Tag: 7
        ConwayMempoolFailure {
            reason: Text,
        },
        /// Tag: 8
        ConwayWithdrawalsMissingAccounts {
            withdrawals: Withdrawals,
        },
        /// Tag: 9
        ConwayIncompleteWithdrawals {
            withdrawals: Withdrawals,
        },
    }
}
