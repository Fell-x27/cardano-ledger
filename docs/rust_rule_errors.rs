//! Rust representations of STS predicate failure types extracted from the
//! Cardano ledger `Rules` modules across eras.
//!
//! NOTE: These definitions focus on the structure and CBOR tags of the
//! predicate failure enums. Domain-specific payload types are represented by
//! lightweight stand-ins so the relationships between failures remain clear.
//! Any field marked with `TODO` should be replaced with the concrete type when
//! wiring these definitions into real code.

use std::collections::BTreeSet;
use std::marker::PhantomData;

// ---------------------------------------------------------------------------
// Helper stand-ins
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Coin; // TODO: use the real Coin type

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DeltaCoin; // TODO: use the real DeltaCoin type

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxIn; // TODO: use the real TxIn type

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxIx; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SlotNo; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EpochNo; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Network; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ScriptHash; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DataHash; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ScriptIntegrityHash; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Addr; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RewardAccount; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ExUnits; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TxAuxDataHash; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PoolCert; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MIRPot; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProtVer; // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ValidityInterval; // TODO

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
pub struct VRFVerKeyHash<Role>(pub PhantomData<Role>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Credential<Role>(pub PhantomData<Role>); // TODO

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Withdrawals; // TODO

pub type StrictMaybe<T> = Option<T>;

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
            expected: Network,
            offending: BTreeSet<Addr>,
        },
        /// Tag: 9
        WrongNetworkWithdrawal {
            expected: Network,
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
            network_mismatch: Mismatch<RelEQ, Network>,
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
            expected: Network,
            offending: BTreeSet<Addr>,
        },
        /// Tag: 9
        WrongNetworkWithdrawal {
            expected: Network,
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
            mismatch: Mismatch<RelEQ, Network>,
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
            missing: Vec<(PlutusPurpose<Era>, ScriptHash)>,
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
            extra: Vec<PlutusPurpose<Era>>,
        },
        /// Tag: 8
        ScriptIntegrityHashMismatch {
            mismatch: Mismatch<RelEQ, StrictMaybe<ScriptIntegrityHash>>,
            provided: StrictMaybe<Vec<u8>>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PlutusPurpose<Era>(pub PhantomData<Era>); // TODO
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
// Conway era predicate failures (skeleton)
// ---------------------------------------------------------------------------

pub mod conway {
    //! TODO: Translate Conway-era predicate failures. The encoding sections in
    //! `Cardano.Ledger.Conway.Rules.*` should be inspected and mirrored here.
}
