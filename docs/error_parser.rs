//! Utilities for decoding the ledger predicate failures that are
//! serialized as tagged CBOR sums.  The goal of this module is to keep the
//! low-level CBOR handling in one place so the types defined in
//! `rust_rule_errors.rs` can be connected to a real decoder without having to
//! manually pattern-match every constructor.
//!
//! The module exposes two views over an error message:
//!
//! * [`TaggedTree`] keeps the generic structure for tooling that wants to walk
//!   the CBOR representation without committing to any specific era.
//! * [`decode_conway_ledger_failures_bytes`] converts the Conway-era ledger
//!   predicate failures into enums keyed by their constructor tags so callers
//!   can pattern match on concrete error cases.

use ciborium::{de, value::Integer, value::Value};
use std::{convert::TryFrom, fmt, io};

/// Error returned while building a [`TaggedTree`].
#[derive(Debug)]
pub enum ParseError {
    /// The message could not be decoded from CBOR.
    Cbor(de::Error<std::io::Error>),
    /// The structure was not a tagged sum as expected.
    Malformed(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Cbor(err) => write!(f, "CBOR decoding error: {err}"),
            ParseError::Malformed(msg) => write!(f, "malformed predicate failure: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Cbor(err) => Some(err),
            ParseError::Malformed(_) => None,
        }
    }
}

impl From<de::Error<io::Error>> for ParseError {
    fn from(err: de::Error<io::Error>) -> Self {
        ParseError::Cbor(err)
    }
}

/// Minimal CBOR term representation that keeps ordering information for arrays
/// and key/value pairs for maps.  The intention is to resolve the term into the
/// helper structs defined in `rust_rule_errors.rs` in a later pass once we wire
/// up serde-based decoding.
#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Integer(Integer),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Float(f64),
    Null,
    Array(Vec<Term>),
    Map(Vec<(Term, Term)>),
    Tagged(u64, Box<Term>),
}

impl Term {
    fn from_value(value: Value) -> Term {
        match value {
            Value::Integer(int) => Term::Integer(int),
            Value::Bytes(bytes) => Term::Bytes(bytes),
            Value::Text(text) => Term::Text(text),
            Value::Bool(b) => Term::Bool(b),
            Value::Null => Term::Null,
            Value::Float(f) => Term::Float(f),
            Value::Array(items) => Term::Array(items.into_iter().map(Term::from_value).collect()),
            Value::Map(entries) => Term::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| (Term::from_value(k), Term::from_value(v)))
                    .collect(),
            ),
            Value::Tag(tag, boxed) => Term::Tagged(tag, Box::new(Term::from_value(*boxed))),
        }
    }

    fn as_unsigned(&self) -> Option<u64> {
        match self {
            Term::Integer(int) => u64::try_from(int.clone()).ok(),
            _ => None,
        }
    }
}

/// Representation of a CBOR-encoded sum value.
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedSum {
    pub tag: u64,
    pub fields: Vec<Term>,
}

impl TaggedSum {
    fn from_term(term: Term) -> Option<TaggedSum> {
        match term {
            Term::Array(mut elements) if !elements.is_empty() => {
                let tag_term = elements.remove(0);
                let tag = tag_term.as_unsigned()?;
                Some(TaggedSum {
                    tag,
                    fields: elements,
                })
            }
            Term::Tagged(tag, boxed) => {
                if let Term::Array(mut elements) = *boxed {
                    Some(TaggedSum {
                        tag,
                        fields: elements,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Tree structure that mirrors the nesting of predicate failures.  Each node
/// is either a tagged sum (which corresponds to one constructor of a predicate
/// failure) or a leaf containing an arbitrary CBOR term.
#[derive(Debug, Clone, PartialEq)]
pub enum TaggedTree {
    Sum(TaggedSum, Vec<TaggedTree>),
    Leaf(Term),
}

impl TaggedTree {
    fn from_term(term: Term) -> TaggedTree {
        if let Some(sum) = TaggedSum::from_term(term.clone()) {
            let children = sum
                .fields
                .iter()
                .cloned()
                .map(TaggedTree::from_term)
                .collect();
            TaggedTree::Sum(sum, children)
        } else {
            TaggedTree::Leaf(term)
        }
    }
}

/// Decode a CBOR message and build a [`TaggedTree`] describing its structure.
///
/// # Errors
///
/// Returns [`ParseError::Malformed`] if the input cannot be interpreted as a
/// tagged sum and [`ParseError::Cbor`] if the raw bytes are not valid CBOR.
pub fn decode_predicate_failure<R: io::Read>(reader: R) -> Result<TaggedTree, ParseError> {
    let value: Value = de::from_reader(reader)?;
    let root = Term::from_value(value);
    if TaggedSum::from_term(root.clone()).is_none() {
        return Err(ParseError::Malformed("expected a tagged sum"));
    }
    Ok(TaggedTree::from_term(root))
}

/// Convenience helper for decoding from an in-memory slice.
pub fn decode_predicate_failure_bytes(bytes: &[u8]) -> Result<TaggedTree, ParseError> {
    decode_predicate_failure(bytes)
}

/// Conway-specific view of the predicate failure hierarchy.  The helper enums
/// below capture the numeric tags so callers can match on constructors without
/// reimplementing the CBOR parsing logic.
#[derive(Debug, Clone, PartialEq)]
pub enum ConwayLedgerPredicateFailure {
    UtxowFailure(Box<ConwayUtxowPredicateFailure>),
    CertsFailure(Box<ConwayCertsPredicateFailure>),
    GovFailure(Box<ConwayGovPredicateFailure>),
    WdrlNotDelegatedToDRep { withdrawals: Term },
    TreasuryValueMismatch { mismatch: Term },
    TxRefScriptsSizeTooBig { size_mismatch: Term },
    MempoolFailure { reason: Term },
    WithdrawalsMissingAccounts { withdrawals: Term },
    IncompleteWithdrawals { withdrawals: Term },
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayUtxowPredicateFailure {
    UtxoFailure(Box<ConwayUtxoPredicateFailure>),
    InvalidWitnessesUTXOW {
        witnesses: Term,
    },
    MissingVKeyWitnessesUTXOW {
        missing: Term,
    },
    MissingScriptWitnessesUTXOW {
        missing: Term,
    },
    ScriptWitnessNotValidatingUTXOW {
        failing: Term,
    },
    MissingTxBodyMetadataHash {
        expected: Term,
    },
    MissingTxMetadata {
        expected: Term,
    },
    ConflictingMetadataHash {
        mismatch: Term,
    },
    InvalidMetadata,
    ExtraneousScriptWitnessesUTXOW {
        extraneous: Term,
    },
    MissingRedeemers {
        missing: Term,
    },
    MissingRequiredDatums {
        missing_hashes: Term,
        provided_hashes: Term,
    },
    NotAllowedSupplementalDatums {
        disallowed_hashes: Term,
        allowed: Term,
    },
    PPViewHashesDontMatch {
        mismatch: Term,
    },
    UnspendableUTxONoDatumHash {
        inputs: Term,
    },
    ExtraRedeemers {
        extra: Term,
    },
    MalformedScriptWitnesses {
        scripts: Term,
    },
    MalformedReferenceScripts {
        scripts: Term,
    },
    ScriptIntegrityHashMismatch {
        mismatch: Term,
        provided: Term,
    },
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayUtxoPredicateFailure {
    UtxosFailure(Box<ConwayUtxosPredicateFailure>),
    BadInputsUTxO {
        invalid_inputs: Term,
    },
    OutsideValidityIntervalUTxO {
        validity_interval: Term,
        current_slot: Term,
    },
    MaxTxSizeUTxO {
        size_mismatch: Term,
    },
    InputSetEmptyUTxO,
    FeeTooSmallUTxO {
        fee_mismatch: Term,
    },
    ValueNotConservedUTxO {
        balance_mismatch: Term,
    },
    WrongNetwork {
        expected: Term,
        offending: Term,
    },
    WrongNetworkWithdrawal {
        expected: Term,
        offending: Term,
    },
    OutputTooSmallUTxO {
        tiny_outputs: Term,
    },
    OutputBootAddrAttrsTooBig {
        oversized_bootstrap_outputs: Term,
    },
    OutputTooBigUTxO {
        outputs: Term,
    },
    InsufficientCollateral {
        provided: Term,
        required: Term,
    },
    ScriptsNotPaidUTxO {
        unpaid: Term,
    },
    ExUnitsTooBigUTxO {
        limit_mismatch: Term,
    },
    CollateralContainsNonADA {
        offending_value: Term,
    },
    WrongNetworkInTxBody {
        mismatch: Term,
    },
    OutsideForecast {
        slot: Term,
    },
    TooManyCollateralInputs {
        bound: Term,
    },
    NoCollateralInputs,
    IncorrectTotalCollateralField {
        provided: Term,
        declared: Term,
    },
    BabbageOutputTooSmallUTxO {
        outputs: Term,
    },
    BabbageNonDisjointRefInputs {
        overlapping: Term,
    },
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayUtxosPredicateFailure {
    ValidationTagMismatch { tag: Term, description: Term },
    CollectErrors { errors: Term },
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayCertsPredicateFailure {
    WithdrawalsNotInRewardsCERTS { withdrawals: Term },
    CertFailure(Box<ConwayCertPredicateFailure>),
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayCertPredicateFailure {
    DelegFailure(Box<ConwayDelegPredicateFailure>),
    PoolFailure { failure: Term },
    GovCertFailure(Box<ConwayGovCertPredicateFailure>),
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayDelegPredicateFailure {
    IncorrectDeposit { deposit: Term },
    StakeKeyRegistered { stake_credential: Term },
    StakeKeyNotRegistered { stake_credential: Term },
    StakeKeyHasNonZeroRewardAccountBalance { balance: Term },
    DelegateeDRepNotRegistered { delegatee: Term },
    DelegateeStakePoolNotRegistered { delegatee: Vec<u8> },
    DepositIncorrect { mismatch: Term },
    RefundIncorrect { mismatch: Term },
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayGovCertPredicateFailure {
    ConwayDRepAlreadyRegistered { credential: Term },
    ConwayDRepNotRegistered { credential: Term },
    ConwayDRepIncorrectDeposit { mismatch: Term },
    ConwayCommitteeHasPreviouslyResigned { cold_credential: Term },
    ConwayDRepIncorrectRefund { mismatch: Term },
    ConwayCommitteeIsUnknown { cold_credential: Term },
    Other(TaggedSum),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConwayGovPredicateFailure {
    GovActionsDoNotExist {
        missing: Term,
    },
    MalformedProposal {
        proposal: Term,
    },
    ProposalProcedureNetworkIdMismatch {
        reward_account: Term,
        expected_network: Term,
    },
    TreasuryWithdrawalsNetworkIdMismatch {
        offending_accounts: Term,
        expected_network: Term,
    },
    ProposalDepositIncorrect {
        mismatch: Term,
    },
    DisallowedVoters {
        voters: Term,
    },
    ConflictingCommitteeUpdate {
        members: Term,
    },
    ExpirationEpochTooSmall {
        expired: Term,
    },
    InvalidPrevGovActionId {
        proposal: Term,
    },
    VotingOnExpiredGovAction {
        votes: Term,
    },
    ProposalCantFollow {
        previous: Term,
        version_mismatch: Term,
    },
    InvalidPolicyHash {
        provided: Term,
        expected: Term,
    },
    DisallowedProposalDuringBootstrap {
        proposal: Term,
    },
    DisallowedVotesDuringBootstrap {
        votes: Term,
    },
    VotersDoNotExist {
        voters: Term,
    },
    ZeroTreasuryWithdrawals {
        action: Term,
    },
    ProposalReturnAccountDoesNotExist {
        reward_account: Term,
    },
    TreasuryWithdrawalReturnAccountsDoNotExist {
        reward_accounts: Term,
    },
    UnelectedCommitteeVoters {
        voters: Term,
    },
    Other(TaggedSum),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayLedgerPredicateFailureTag {
    ConwayUtxowFailure = 1,
    ConwayCertsFailure = 2,
    ConwayGovFailure = 3,
    ConwayWdrlNotDelegatedToDRep = 4,
    ConwayTreasuryValueMismatch = 5,
    ConwayTxRefScriptsSizeTooBig = 6,
    ConwayMempoolFailure = 7,
    ConwayWithdrawalsMissingAccounts = 8,
    ConwayIncompleteWithdrawals = 9,
}

impl TryFrom<u64> for ConwayLedgerPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ConwayUtxowFailure),
            2 => Ok(Self::ConwayCertsFailure),
            3 => Ok(Self::ConwayGovFailure),
            4 => Ok(Self::ConwayWdrlNotDelegatedToDRep),
            5 => Ok(Self::ConwayTreasuryValueMismatch),
            6 => Ok(Self::ConwayTxRefScriptsSizeTooBig),
            7 => Ok(Self::ConwayMempoolFailure),
            8 => Ok(Self::ConwayWithdrawalsMissingAccounts),
            9 => Ok(Self::ConwayIncompleteWithdrawals),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayUtxowPredicateFailureTag {
    UtxoFailure = 0,
    InvalidWitnessesUTXOW = 1,
    MissingVKeyWitnessesUTXOW = 2,
    MissingScriptWitnessesUTXOW = 3,
    ScriptWitnessNotValidatingUTXOW = 4,
    MissingTxBodyMetadataHash = 5,
    MissingTxMetadata = 6,
    ConflictingMetadataHash = 7,
    InvalidMetadata = 8,
    ExtraneousScriptWitnessesUTXOW = 9,
    MissingRedeemers = 10,
    MissingRequiredDatums = 11,
    NotAllowedSupplementalDatums = 12,
    PPViewHashesDontMatch = 13,
    UnspendableUTxONoDatumHash = 14,
    ExtraRedeemers = 15,
    MalformedScriptWitnesses = 16,
    MalformedReferenceScripts = 17,
    ScriptIntegrityHashMismatch = 18,
}

impl TryFrom<u64> for ConwayUtxowPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UtxoFailure),
            1 => Ok(Self::InvalidWitnessesUTXOW),
            2 => Ok(Self::MissingVKeyWitnessesUTXOW),
            3 => Ok(Self::MissingScriptWitnessesUTXOW),
            4 => Ok(Self::ScriptWitnessNotValidatingUTXOW),
            5 => Ok(Self::MissingTxBodyMetadataHash),
            6 => Ok(Self::MissingTxMetadata),
            7 => Ok(Self::ConflictingMetadataHash),
            8 => Ok(Self::InvalidMetadata),
            9 => Ok(Self::ExtraneousScriptWitnessesUTXOW),
            10 => Ok(Self::MissingRedeemers),
            11 => Ok(Self::MissingRequiredDatums),
            12 => Ok(Self::NotAllowedSupplementalDatums),
            13 => Ok(Self::PPViewHashesDontMatch),
            14 => Ok(Self::UnspendableUTxONoDatumHash),
            15 => Ok(Self::ExtraRedeemers),
            16 => Ok(Self::MalformedScriptWitnesses),
            17 => Ok(Self::MalformedReferenceScripts),
            18 => Ok(Self::ScriptIntegrityHashMismatch),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayUtxoPredicateFailureTag {
    UtxosFailure = 0,
    BadInputsUTxO = 1,
    OutsideValidityIntervalUTxO = 2,
    MaxTxSizeUTxO = 3,
    InputSetEmptyUTxO = 4,
    FeeTooSmallUTxO = 5,
    ValueNotConservedUTxO = 6,
    WrongNetwork = 7,
    WrongNetworkWithdrawal = 8,
    OutputTooSmallUTxO = 9,
    OutputBootAddrAttrsTooBig = 10,
    OutputTooBigUTxO = 11,
    InsufficientCollateral = 12,
    ScriptsNotPaidUTxO = 13,
    ExUnitsTooBigUTxO = 14,
    CollateralContainsNonADA = 15,
    WrongNetworkInTxBody = 16,
    OutsideForecast = 17,
    TooManyCollateralInputs = 18,
    NoCollateralInputs = 19,
    IncorrectTotalCollateralField = 20,
    BabbageOutputTooSmallUTxO = 21,
    BabbageNonDisjointRefInputs = 22,
}

impl TryFrom<u64> for ConwayUtxoPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UtxosFailure),
            1 => Ok(Self::BadInputsUTxO),
            2 => Ok(Self::OutsideValidityIntervalUTxO),
            3 => Ok(Self::MaxTxSizeUTxO),
            4 => Ok(Self::InputSetEmptyUTxO),
            5 => Ok(Self::FeeTooSmallUTxO),
            6 => Ok(Self::ValueNotConservedUTxO),
            7 => Ok(Self::WrongNetwork),
            8 => Ok(Self::WrongNetworkWithdrawal),
            9 => Ok(Self::OutputTooSmallUTxO),
            10 => Ok(Self::OutputBootAddrAttrsTooBig),
            11 => Ok(Self::OutputTooBigUTxO),
            12 => Ok(Self::InsufficientCollateral),
            13 => Ok(Self::ScriptsNotPaidUTxO),
            14 => Ok(Self::ExUnitsTooBigUTxO),
            15 => Ok(Self::CollateralContainsNonADA),
            16 => Ok(Self::WrongNetworkInTxBody),
            17 => Ok(Self::OutsideForecast),
            18 => Ok(Self::TooManyCollateralInputs),
            19 => Ok(Self::NoCollateralInputs),
            20 => Ok(Self::IncorrectTotalCollateralField),
            21 => Ok(Self::BabbageOutputTooSmallUTxO),
            22 => Ok(Self::BabbageNonDisjointRefInputs),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayUtxosPredicateFailureTag {
    ValidationTagMismatch = 0,
    CollectErrors = 1,
}

impl TryFrom<u64> for ConwayUtxosPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ValidationTagMismatch),
            1 => Ok(Self::CollectErrors),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayCertsPredicateFailureTag {
    WithdrawalsNotInRewardsCERTS = 0,
    CertFailure = 1,
}

impl TryFrom<u64> for ConwayCertsPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::WithdrawalsNotInRewardsCERTS),
            1 => Ok(Self::CertFailure),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayCertPredicateFailureTag {
    DelegFailure = 1,
    PoolFailure = 2,
    GovCertFailure = 3,
}

impl TryFrom<u64> for ConwayCertPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::DelegFailure),
            2 => Ok(Self::PoolFailure),
            3 => Ok(Self::GovCertFailure),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayDelegPredicateFailureTag {
    IncorrectDepositDELEG = 1,
    StakeKeyRegisteredDELEG = 2,
    StakeKeyNotRegisteredDELEG = 3,
    StakeKeyHasNonZeroRewardAccountBalanceDELEG = 4,
    DelegateeDRepNotRegisteredDELEG = 5,
    DelegateeStakePoolNotRegisteredDELEG = 6,
    DepositIncorrectDELEG = 7,
    RefundIncorrectDELEG = 8,
}

impl TryFrom<u64> for ConwayDelegPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IncorrectDepositDELEG),
            2 => Ok(Self::StakeKeyRegisteredDELEG),
            3 => Ok(Self::StakeKeyNotRegisteredDELEG),
            4 => Ok(Self::StakeKeyHasNonZeroRewardAccountBalanceDELEG),
            5 => Ok(Self::DelegateeDRepNotRegisteredDELEG),
            6 => Ok(Self::DelegateeStakePoolNotRegisteredDELEG),
            7 => Ok(Self::DepositIncorrectDELEG),
            8 => Ok(Self::RefundIncorrectDELEG),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayGovCertPredicateFailureTag {
    ConwayDRepAlreadyRegistered = 0,
    ConwayDRepNotRegistered = 1,
    ConwayDRepIncorrectDeposit = 2,
    ConwayCommitteeHasPreviouslyResigned = 3,
    ConwayDRepIncorrectRefund = 4,
    ConwayCommitteeIsUnknown = 5,
}

impl TryFrom<u64> for ConwayGovCertPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ConwayDRepAlreadyRegistered),
            1 => Ok(Self::ConwayDRepNotRegistered),
            2 => Ok(Self::ConwayDRepIncorrectDeposit),
            3 => Ok(Self::ConwayCommitteeHasPreviouslyResigned),
            4 => Ok(Self::ConwayDRepIncorrectRefund),
            5 => Ok(Self::ConwayCommitteeIsUnknown),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConwayGovPredicateFailureTag {
    GovActionsDoNotExist = 0,
    MalformedProposal = 1,
    ProposalProcedureNetworkIdMismatch = 2,
    TreasuryWithdrawalsNetworkIdMismatch = 3,
    ProposalDepositIncorrect = 4,
    DisallowedVoters = 5,
    ConflictingCommitteeUpdate = 6,
    ExpirationEpochTooSmall = 7,
    InvalidPrevGovActionId = 8,
    VotingOnExpiredGovAction = 9,
    ProposalCantFollow = 10,
    InvalidPolicyHash = 11,
    DisallowedProposalDuringBootstrap = 12,
    DisallowedVotesDuringBootstrap = 13,
    VotersDoNotExist = 14,
    ZeroTreasuryWithdrawals = 15,
    ProposalReturnAccountDoesNotExist = 16,
    TreasuryWithdrawalReturnAccountsDoNotExist = 17,
    UnelectedCommitteeVoters = 18,
}

impl TryFrom<u64> for ConwayGovPredicateFailureTag {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::GovActionsDoNotExist),
            1 => Ok(Self::MalformedProposal),
            2 => Ok(Self::ProposalProcedureNetworkIdMismatch),
            3 => Ok(Self::TreasuryWithdrawalsNetworkIdMismatch),
            4 => Ok(Self::ProposalDepositIncorrect),
            5 => Ok(Self::DisallowedVoters),
            6 => Ok(Self::ConflictingCommitteeUpdate),
            7 => Ok(Self::ExpirationEpochTooSmall),
            8 => Ok(Self::InvalidPrevGovActionId),
            9 => Ok(Self::VotingOnExpiredGovAction),
            10 => Ok(Self::ProposalCantFollow),
            11 => Ok(Self::InvalidPolicyHash),
            12 => Ok(Self::DisallowedProposalDuringBootstrap),
            13 => Ok(Self::DisallowedVotesDuringBootstrap),
            14 => Ok(Self::VotersDoNotExist),
            15 => Ok(Self::ZeroTreasuryWithdrawals),
            16 => Ok(Self::ProposalReturnAccountDoesNotExist),
            17 => Ok(Self::TreasuryWithdrawalReturnAccountsDoNotExist),
            18 => Ok(Self::UnelectedCommitteeVoters),
            _ => Err(()),
        }
    }
}

/// Decode the message into the Conway ledger predicate failures.  Any
/// constructors we do not recognise are returned as raw [`TaggedSum`] values so
/// future work can extend the match arms without re-parsing the CBOR.
pub fn decode_conway_ledger_failures<R: io::Read>(
    reader: R,
) -> Result<Vec<ConwayLedgerPredicateFailure>, ParseError> {
    let value: Value = de::from_reader(reader)?;
    let term = Term::from_value(value);
    let body = match term {
        Term::Array(mut elements) if elements.len() == 2 => {
            elements.remove(0);
            elements.remove(0)
        }
        _ => {
            return Err(ParseError::Malformed(
                "expected [tag, body] predicate failure message",
            ))
        }
    };

    let failures = match body {
        Term::Array(elements) => elements,
        _ => {
            return Err(ParseError::Malformed(
                "predicate failure body must be an array",
            ))
        }
    };

    failures
        .into_iter()
        .map(parse_conway_ledger_failure)
        .collect()
}

/// Convenience helper mirroring [`decode_conway_ledger_failures`] for an
/// in-memory message buffer.
pub fn decode_conway_ledger_failures_bytes(
    bytes: &[u8],
) -> Result<Vec<ConwayLedgerPredicateFailure>, ParseError> {
    decode_conway_ledger_failures(bytes)
}

fn parse_conway_ledger_failure(term: Term) -> Result<ConwayLedgerPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "ledger predicate failure node must be a tagged sum",
    ))?;

    match ConwayLedgerPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayLedgerPredicateFailureTag::ConwayUtxowFailure) => {
            let field =
                expect_single_field(sum.fields, "ConwayUtxowFailure expects a single payload")?;
            let utxow = parse_conway_utxow_failure(field)?;
            Ok(ConwayLedgerPredicateFailure::UtxowFailure(Box::new(utxow)))
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayCertsFailure) => {
            let child =
                expect_single_field(sum.fields, "ConwayCertsFailure expects a single payload")?;
            let certs = parse_conway_certs_failure(child)?;
            Ok(ConwayLedgerPredicateFailure::CertsFailure(Box::new(certs)))
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayGovFailure) => {
            let child =
                expect_single_field(sum.fields, "ConwayGovFailure expects a single payload")?;
            let gov = parse_conway_gov_failure(child)?;
            Ok(ConwayLedgerPredicateFailure::GovFailure(Box::new(gov)))
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayWdrlNotDelegatedToDRep) => {
            let withdrawals = expect_single_field(
                sum.fields,
                "ConwayWdrlNotDelegatedToDRep expects withdrawals",
            )?;
            Ok(ConwayLedgerPredicateFailure::WdrlNotDelegatedToDRep { withdrawals })
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayTreasuryValueMismatch) => {
            let mismatch = expect_single_field(
                sum.fields,
                "ConwayTreasuryValueMismatch expects mismatch payload",
            )?;
            Ok(ConwayLedgerPredicateFailure::TreasuryValueMismatch { mismatch })
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayTxRefScriptsSizeTooBig) => {
            let size_mismatch = expect_single_field(
                sum.fields,
                "ConwayTxRefScriptsSizeTooBig expects mismatch payload",
            )?;
            Ok(ConwayLedgerPredicateFailure::TxRefScriptsSizeTooBig { size_mismatch })
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayMempoolFailure) => {
            let reason =
                expect_single_field(sum.fields, "ConwayMempoolFailure expects reason payload")?;
            Ok(ConwayLedgerPredicateFailure::MempoolFailure { reason })
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayWithdrawalsMissingAccounts) => {
            let withdrawals = expect_single_field(
                sum.fields,
                "ConwayWithdrawalsMissingAccounts expects withdrawals",
            )?;
            Ok(ConwayLedgerPredicateFailure::WithdrawalsMissingAccounts { withdrawals })
        }
        Ok(ConwayLedgerPredicateFailureTag::ConwayIncompleteWithdrawals) => {
            let withdrawals = expect_single_field(
                sum.fields,
                "ConwayIncompleteWithdrawals expects withdrawals",
            )?;
            Ok(ConwayLedgerPredicateFailure::IncompleteWithdrawals { withdrawals })
        }
        _ => Ok(ConwayLedgerPredicateFailure::Other(sum)),
    }
}

fn parse_conway_utxow_failure(term: Term) -> Result<ConwayUtxowPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "utxow predicate failure must be a tagged sum",
    ))?;

    match ConwayUtxowPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayUtxowPredicateFailureTag::UtxoFailure) => {
            let child = expect_single_field(sum.fields, "UtxoFailure expects a single payload")?;
            let utxo = parse_conway_utxo_failure(child)?;
            Ok(ConwayUtxowPredicateFailure::UtxoFailure(Box::new(utxo)))
        }
        Ok(ConwayUtxowPredicateFailureTag::InvalidWitnessesUTXOW) => {
            let witnesses =
                expect_single_field(sum.fields, "InvalidWitnessesUTXOW expects witness payload")?;
            Ok(ConwayUtxowPredicateFailure::InvalidWitnessesUTXOW { witnesses })
        }
        Ok(ConwayUtxowPredicateFailureTag::MissingVKeyWitnessesUTXOW) => {
            let missing = expect_single_field(
                sum.fields,
                "MissingVKeyWitnessesUTXOW expects missing payload",
            )?;
            Ok(ConwayUtxowPredicateFailure::MissingVKeyWitnessesUTXOW { missing })
        }
        Ok(ConwayUtxowPredicateFailureTag::MissingScriptWitnessesUTXOW) => {
            let missing = expect_single_field(
                sum.fields,
                "MissingScriptWitnessesUTXOW expects missing payload",
            )?;
            Ok(ConwayUtxowPredicateFailure::MissingScriptWitnessesUTXOW { missing })
        }
        Ok(ConwayUtxowPredicateFailureTag::ScriptWitnessNotValidatingUTXOW) => {
            let failing = expect_single_field(
                sum.fields,
                "ScriptWitnessNotValidatingUTXOW expects failing payload",
            )?;
            Ok(ConwayUtxowPredicateFailure::ScriptWitnessNotValidatingUTXOW { failing })
        }
        Ok(ConwayUtxowPredicateFailureTag::MissingTxBodyMetadataHash) => {
            let expected = expect_single_field(
                sum.fields,
                "MissingTxBodyMetadataHash expects expected hash",
            )?;
            Ok(ConwayUtxowPredicateFailure::MissingTxBodyMetadataHash { expected })
        }
        Ok(ConwayUtxowPredicateFailureTag::MissingTxMetadata) => {
            let expected =
                expect_single_field(sum.fields, "MissingTxMetadata expects expected hash")?;
            Ok(ConwayUtxowPredicateFailure::MissingTxMetadata { expected })
        }
        Ok(ConwayUtxowPredicateFailureTag::ConflictingMetadataHash) => {
            let mismatch = expect_single_field(
                sum.fields,
                "ConflictingMetadataHash expects mismatch payload",
            )?;
            Ok(ConwayUtxowPredicateFailure::ConflictingMetadataHash { mismatch })
        }
        Ok(ConwayUtxowPredicateFailureTag::InvalidMetadata) => {
            expect_no_fields(sum.fields, "InvalidMetadata carries no payload")?;
            Ok(ConwayUtxowPredicateFailure::InvalidMetadata)
        }
        Ok(ConwayUtxowPredicateFailureTag::ExtraneousScriptWitnessesUTXOW) => {
            let extraneous =
                expect_single_field(sum.fields, "ExtraneousScriptWitnessesUTXOW expects payload")?;
            Ok(ConwayUtxowPredicateFailure::ExtraneousScriptWitnessesUTXOW { extraneous })
        }
        Ok(ConwayUtxowPredicateFailureTag::MissingRedeemers) => {
            let missing = expect_single_field(sum.fields, "MissingRedeemers expects payload")?;
            Ok(ConwayUtxowPredicateFailure::MissingRedeemers { missing })
        }
        Ok(ConwayUtxowPredicateFailureTag::MissingRequiredDatums) => {
            let (missing_hashes, provided_hashes) =
                expect_two_fields(sum.fields, "MissingRequiredDatums expects two payloads")?;
            Ok(ConwayUtxowPredicateFailure::MissingRequiredDatums {
                missing_hashes,
                provided_hashes,
            })
        }
        Ok(ConwayUtxowPredicateFailureTag::NotAllowedSupplementalDatums) => {
            let (disallowed_hashes, allowed) = expect_two_fields(
                sum.fields,
                "NotAllowedSupplementalDatums expects two payloads",
            )?;
            Ok(ConwayUtxowPredicateFailure::NotAllowedSupplementalDatums {
                disallowed_hashes,
                allowed,
            })
        }
        Ok(ConwayUtxowPredicateFailureTag::PPViewHashesDontMatch) => {
            let mismatch =
                expect_single_field(sum.fields, "PPViewHashesDontMatch expects mismatch payload")?;
            Ok(ConwayUtxowPredicateFailure::PPViewHashesDontMatch { mismatch })
        }
        Ok(ConwayUtxowPredicateFailureTag::UnspendableUTxONoDatumHash) => {
            let inputs =
                expect_single_field(sum.fields, "UnspendableUTxONoDatumHash expects input set")?;
            Ok(ConwayUtxowPredicateFailure::UnspendableUTxONoDatumHash { inputs })
        }
        Ok(ConwayUtxowPredicateFailureTag::ExtraRedeemers) => {
            let extra = expect_single_field(sum.fields, "ExtraRedeemers expects payload")?;
            Ok(ConwayUtxowPredicateFailure::ExtraRedeemers { extra })
        }
        Ok(ConwayUtxowPredicateFailureTag::MalformedScriptWitnesses) => {
            let scripts =
                expect_single_field(sum.fields, "MalformedScriptWitnesses expects payload")?;
            Ok(ConwayUtxowPredicateFailure::MalformedScriptWitnesses { scripts })
        }
        Ok(ConwayUtxowPredicateFailureTag::MalformedReferenceScripts) => {
            let scripts =
                expect_single_field(sum.fields, "MalformedReferenceScripts expects payload")?;
            Ok(ConwayUtxowPredicateFailure::MalformedReferenceScripts { scripts })
        }
        Ok(ConwayUtxowPredicateFailureTag::ScriptIntegrityHashMismatch) => {
            let (mismatch, provided) = expect_two_fields(
                sum.fields,
                "ScriptIntegrityHashMismatch expects two payloads",
            )?;
            Ok(ConwayUtxowPredicateFailure::ScriptIntegrityHashMismatch { mismatch, provided })
        }
        _ => Ok(ConwayUtxowPredicateFailure::Other(sum)),
    }
}

fn parse_conway_utxo_failure(term: Term) -> Result<ConwayUtxoPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "utxo predicate failure must be a tagged sum",
    ))?;

    match ConwayUtxoPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayUtxoPredicateFailureTag::UtxosFailure) => {
            let child = expect_single_field(sum.fields, "UtxosFailure expects a single payload")?;
            let utxos = parse_conway_utxos_failure(child)?;
            Ok(ConwayUtxoPredicateFailure::UtxosFailure(Box::new(utxos)))
        }
        Ok(ConwayUtxoPredicateFailureTag::BadInputsUTxO) => {
            let invalid_inputs =
                expect_single_field(sum.fields, "BadInputsUTxO expects invalid inputs payload")?;
            Ok(ConwayUtxoPredicateFailure::BadInputsUTxO { invalid_inputs })
        }
        Ok(ConwayUtxoPredicateFailureTag::OutsideValidityIntervalUTxO) => {
            let (validity_interval, current_slot) = expect_two_fields(
                sum.fields,
                "OutsideValidityIntervalUTxO expects interval and slot",
            )?;
            Ok(ConwayUtxoPredicateFailure::OutsideValidityIntervalUTxO {
                validity_interval,
                current_slot,
            })
        }
        Ok(ConwayUtxoPredicateFailureTag::MaxTxSizeUTxO) => {
            let size_mismatch =
                expect_single_field(sum.fields, "MaxTxSizeUTxO expects mismatch payload")?;
            Ok(ConwayUtxoPredicateFailure::MaxTxSizeUTxO { size_mismatch })
        }
        Ok(ConwayUtxoPredicateFailureTag::InputSetEmptyUTxO) => {
            expect_no_fields(sum.fields, "InputSetEmptyUTxO carries no payload")?;
            Ok(ConwayUtxoPredicateFailure::InputSetEmptyUTxO)
        }
        Ok(ConwayUtxoPredicateFailureTag::FeeTooSmallUTxO) => {
            let fee_mismatch =
                expect_single_field(sum.fields, "FeeTooSmallUTxO expects mismatch payload")?;
            Ok(ConwayUtxoPredicateFailure::FeeTooSmallUTxO { fee_mismatch })
        }
        Ok(ConwayUtxoPredicateFailureTag::ValueNotConservedUTxO) => {
            let balance_mismatch =
                expect_single_field(sum.fields, "ValueNotConservedUTxO expects mismatch payload")?;
            Ok(ConwayUtxoPredicateFailure::ValueNotConservedUTxO { balance_mismatch })
        }
        Ok(ConwayUtxoPredicateFailureTag::WrongNetwork) => {
            let (expected, offending) = expect_two_fields(
                sum.fields,
                "WrongNetwork expects expected/offending payloads",
            )?;
            Ok(ConwayUtxoPredicateFailure::WrongNetwork {
                expected,
                offending,
            })
        }
        Ok(ConwayUtxoPredicateFailureTag::WrongNetworkWithdrawal) => {
            let (expected, offending) = expect_two_fields(
                sum.fields,
                "WrongNetworkWithdrawal expects expected/offending payloads",
            )?;
            Ok(ConwayUtxoPredicateFailure::WrongNetworkWithdrawal {
                expected,
                offending,
            })
        }
        Ok(ConwayUtxoPredicateFailureTag::OutputTooSmallUTxO) => {
            let tiny_outputs =
                expect_single_field(sum.fields, "OutputTooSmallUTxO expects outputs payload")?;
            Ok(ConwayUtxoPredicateFailure::OutputTooSmallUTxO { tiny_outputs })
        }
        Ok(ConwayUtxoPredicateFailureTag::OutputBootAddrAttrsTooBig) => {
            let oversized_bootstrap_outputs = expect_single_field(
                sum.fields,
                "OutputBootAddrAttrsTooBig expects outputs payload",
            )?;
            Ok(ConwayUtxoPredicateFailure::OutputBootAddrAttrsTooBig {
                oversized_bootstrap_outputs,
            })
        }
        Ok(ConwayUtxoPredicateFailureTag::OutputTooBigUTxO) => {
            let outputs = expect_single_field(sum.fields, "OutputTooBigUTxO expects payload")?;
            Ok(ConwayUtxoPredicateFailure::OutputTooBigUTxO { outputs })
        }
        Ok(ConwayUtxoPredicateFailureTag::InsufficientCollateral) => {
            let (provided, required) = expect_two_fields(
                sum.fields,
                "InsufficientCollateral expects provided/required",
            )?;
            Ok(ConwayUtxoPredicateFailure::InsufficientCollateral { provided, required })
        }
        Ok(ConwayUtxoPredicateFailureTag::ScriptsNotPaidUTxO) => {
            let unpaid = expect_single_field(sum.fields, "ScriptsNotPaidUTxO expects payload")?;
            Ok(ConwayUtxoPredicateFailure::ScriptsNotPaidUTxO { unpaid })
        }
        Ok(ConwayUtxoPredicateFailureTag::ExUnitsTooBigUTxO) => {
            let limit_mismatch =
                expect_single_field(sum.fields, "ExUnitsTooBigUTxO expects mismatch payload")?;
            Ok(ConwayUtxoPredicateFailure::ExUnitsTooBigUTxO { limit_mismatch })
        }
        Ok(ConwayUtxoPredicateFailureTag::CollateralContainsNonADA) => {
            let offending_value =
                expect_single_field(sum.fields, "CollateralContainsNonADA expects payload")?;
            Ok(ConwayUtxoPredicateFailure::CollateralContainsNonADA { offending_value })
        }
        Ok(ConwayUtxoPredicateFailureTag::WrongNetworkInTxBody) => {
            let mismatch =
                expect_single_field(sum.fields, "WrongNetworkInTxBody expects mismatch payload")?;
            Ok(ConwayUtxoPredicateFailure::WrongNetworkInTxBody { mismatch })
        }
        Ok(ConwayUtxoPredicateFailureTag::OutsideForecast) => {
            let slot = expect_single_field(sum.fields, "OutsideForecast expects slot payload")?;
            Ok(ConwayUtxoPredicateFailure::OutsideForecast { slot })
        }
        Ok(ConwayUtxoPredicateFailureTag::TooManyCollateralInputs) => {
            let bound =
                expect_single_field(sum.fields, "TooManyCollateralInputs expects bound payload")?;
            Ok(ConwayUtxoPredicateFailure::TooManyCollateralInputs { bound })
        }
        Ok(ConwayUtxoPredicateFailureTag::NoCollateralInputs) => {
            expect_no_fields(sum.fields, "NoCollateralInputs carries no payload")?;
            Ok(ConwayUtxoPredicateFailure::NoCollateralInputs)
        }
        Ok(ConwayUtxoPredicateFailureTag::IncorrectTotalCollateralField) => {
            let (provided, declared) = expect_two_fields(
                sum.fields,
                "IncorrectTotalCollateralField expects provided/declared",
            )?;
            Ok(ConwayUtxoPredicateFailure::IncorrectTotalCollateralField { provided, declared })
        }
        Ok(ConwayUtxoPredicateFailureTag::BabbageOutputTooSmallUTxO) => {
            let outputs =
                expect_single_field(sum.fields, "BabbageOutputTooSmallUTxO expects payload")?;
            Ok(ConwayUtxoPredicateFailure::BabbageOutputTooSmallUTxO { outputs })
        }
        Ok(ConwayUtxoPredicateFailureTag::BabbageNonDisjointRefInputs) => {
            let overlapping =
                expect_single_field(sum.fields, "BabbageNonDisjointRefInputs expects payload")?;
            Ok(ConwayUtxoPredicateFailure::BabbageNonDisjointRefInputs { overlapping })
        }
        _ => Ok(ConwayUtxoPredicateFailure::Other(sum)),
    }
}

fn parse_conway_utxos_failure(term: Term) -> Result<ConwayUtxosPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "utxos predicate failure must be a tagged sum",
    ))?;

    match ConwayUtxosPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayUtxosPredicateFailureTag::ValidationTagMismatch) => {
            let (tag, description) =
                expect_two_fields(sum.fields, "ValidationTagMismatch expects tag/description")?;
            Ok(ConwayUtxosPredicateFailure::ValidationTagMismatch { tag, description })
        }
        Ok(ConwayUtxosPredicateFailureTag::CollectErrors) => {
            let errors = expect_single_field(sum.fields, "CollectErrors expects payload")?;
            Ok(ConwayUtxosPredicateFailure::CollectErrors { errors })
        }
        _ => Ok(ConwayUtxosPredicateFailure::Other(sum)),
    }
}

fn parse_conway_gov_cert_failure(term: Term) -> Result<ConwayGovCertPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "gov cert predicate failure must be a tagged sum",
    ))?;

    match ConwayGovCertPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayGovCertPredicateFailureTag::ConwayDRepAlreadyRegistered) => {
            let credential =
                expect_single_field(sum.fields, "ConwayDRepAlreadyRegistered expects credential")?;
            Ok(ConwayGovCertPredicateFailure::ConwayDRepAlreadyRegistered { credential })
        }
        Ok(ConwayGovCertPredicateFailureTag::ConwayDRepNotRegistered) => {
            let credential =
                expect_single_field(sum.fields, "ConwayDRepNotRegistered expects credential")?;
            Ok(ConwayGovCertPredicateFailure::ConwayDRepNotRegistered { credential })
        }
        Ok(ConwayGovCertPredicateFailureTag::ConwayDRepIncorrectDeposit) => {
            let mismatch =
                expect_single_field(sum.fields, "ConwayDRepIncorrectDeposit expects mismatch")?;
            Ok(ConwayGovCertPredicateFailure::ConwayDRepIncorrectDeposit { mismatch })
        }
        Ok(ConwayGovCertPredicateFailureTag::ConwayCommitteeHasPreviouslyResigned) => {
            let cold_credential = expect_single_field(
                sum.fields,
                "ConwayCommitteeHasPreviouslyResigned expects credential",
            )?;
            Ok(
                ConwayGovCertPredicateFailure::ConwayCommitteeHasPreviouslyResigned {
                    cold_credential,
                },
            )
        }
        Ok(ConwayGovCertPredicateFailureTag::ConwayDRepIncorrectRefund) => {
            let mismatch =
                expect_single_field(sum.fields, "ConwayDRepIncorrectRefund expects mismatch")?;
            Ok(ConwayGovCertPredicateFailure::ConwayDRepIncorrectRefund { mismatch })
        }
        Ok(ConwayGovCertPredicateFailureTag::ConwayCommitteeIsUnknown) => {
            let cold_credential =
                expect_single_field(sum.fields, "ConwayCommitteeIsUnknown expects credential")?;
            Ok(ConwayGovCertPredicateFailure::ConwayCommitteeIsUnknown { cold_credential })
        }
        _ => Ok(ConwayGovCertPredicateFailure::Other(sum)),
    }
}

fn parse_conway_gov_failure(term: Term) -> Result<ConwayGovPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "gov predicate failure must be a tagged sum",
    ))?;

    match ConwayGovPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayGovPredicateFailureTag::GovActionsDoNotExist) => {
            let missing =
                expect_single_field(sum.fields, "GovActionsDoNotExist expects missing payload")?;
            Ok(ConwayGovPredicateFailure::GovActionsDoNotExist { missing })
        }
        Ok(ConwayGovPredicateFailureTag::MalformedProposal) => {
            let proposal =
                expect_single_field(sum.fields, "MalformedProposal expects proposal payload")?;
            Ok(ConwayGovPredicateFailure::MalformedProposal { proposal })
        }
        Ok(ConwayGovPredicateFailureTag::ProposalProcedureNetworkIdMismatch) => {
            let (reward_account, expected_network) = expect_two_fields(
                sum.fields,
                "ProposalProcedureNetworkIdMismatch expects two payloads",
            )?;
            Ok(
                ConwayGovPredicateFailure::ProposalProcedureNetworkIdMismatch {
                    reward_account,
                    expected_network,
                },
            )
        }
        Ok(ConwayGovPredicateFailureTag::TreasuryWithdrawalsNetworkIdMismatch) => {
            let (offending_accounts, expected_network) = expect_two_fields(
                sum.fields,
                "TreasuryWithdrawalsNetworkIdMismatch expects two payloads",
            )?;
            Ok(
                ConwayGovPredicateFailure::TreasuryWithdrawalsNetworkIdMismatch {
                    offending_accounts,
                    expected_network,
                },
            )
        }
        Ok(ConwayGovPredicateFailureTag::ProposalDepositIncorrect) => {
            let mismatch = expect_single_field(
                sum.fields,
                "ProposalDepositIncorrect expects mismatch payload",
            )?;
            Ok(ConwayGovPredicateFailure::ProposalDepositIncorrect { mismatch })
        }
        Ok(ConwayGovPredicateFailureTag::DisallowedVoters) => {
            let voters = expect_single_field(sum.fields, "DisallowedVoters expects payload")?;
            Ok(ConwayGovPredicateFailure::DisallowedVoters { voters })
        }
        Ok(ConwayGovPredicateFailureTag::ConflictingCommitteeUpdate) => {
            let members =
                expect_single_field(sum.fields, "ConflictingCommitteeUpdate expects payload")?;
            Ok(ConwayGovPredicateFailure::ConflictingCommitteeUpdate { members })
        }
        Ok(ConwayGovPredicateFailureTag::ExpirationEpochTooSmall) => {
            let expired =
                expect_single_field(sum.fields, "ExpirationEpochTooSmall expects payload")?;
            Ok(ConwayGovPredicateFailure::ExpirationEpochTooSmall { expired })
        }
        Ok(ConwayGovPredicateFailureTag::InvalidPrevGovActionId) => {
            let proposal = expect_single_field(
                sum.fields,
                "InvalidPrevGovActionId expects proposal payload",
            )?;
            Ok(ConwayGovPredicateFailure::InvalidPrevGovActionId { proposal })
        }
        Ok(ConwayGovPredicateFailureTag::VotingOnExpiredGovAction) => {
            let votes =
                expect_single_field(sum.fields, "VotingOnExpiredGovAction expects payload")?;
            Ok(ConwayGovPredicateFailure::VotingOnExpiredGovAction { votes })
        }
        Ok(ConwayGovPredicateFailureTag::ProposalCantFollow) => {
            let (previous, version_mismatch) =
                expect_two_fields(sum.fields, "ProposalCantFollow expects two payloads")?;
            Ok(ConwayGovPredicateFailure::ProposalCantFollow {
                previous,
                version_mismatch,
            })
        }
        Ok(ConwayGovPredicateFailureTag::InvalidPolicyHash) => {
            let (provided, expected) =
                expect_two_fields(sum.fields, "InvalidPolicyHash expects two payloads")?;
            Ok(ConwayGovPredicateFailure::InvalidPolicyHash { provided, expected })
        }
        Ok(ConwayGovPredicateFailureTag::DisallowedProposalDuringBootstrap) => {
            let proposal = expect_single_field(
                sum.fields,
                "DisallowedProposalDuringBootstrap expects proposal",
            )?;
            Ok(ConwayGovPredicateFailure::DisallowedProposalDuringBootstrap { proposal })
        }
        Ok(ConwayGovPredicateFailureTag::DisallowedVotesDuringBootstrap) => {
            let votes =
                expect_single_field(sum.fields, "DisallowedVotesDuringBootstrap expects votes")?;
            Ok(ConwayGovPredicateFailure::DisallowedVotesDuringBootstrap { votes })
        }
        Ok(ConwayGovPredicateFailureTag::VotersDoNotExist) => {
            let voters = expect_single_field(sum.fields, "VotersDoNotExist expects payload")?;
            Ok(ConwayGovPredicateFailure::VotersDoNotExist { voters })
        }
        Ok(ConwayGovPredicateFailureTag::ZeroTreasuryWithdrawals) => {
            let action = expect_single_field(sum.fields, "ZeroTreasuryWithdrawals expects action")?;
            Ok(ConwayGovPredicateFailure::ZeroTreasuryWithdrawals { action })
        }
        Ok(ConwayGovPredicateFailureTag::ProposalReturnAccountDoesNotExist) => {
            let reward_account = expect_single_field(
                sum.fields,
                "ProposalReturnAccountDoesNotExist expects reward account",
            )?;
            Ok(ConwayGovPredicateFailure::ProposalReturnAccountDoesNotExist { reward_account })
        }
        Ok(ConwayGovPredicateFailureTag::TreasuryWithdrawalReturnAccountsDoNotExist) => {
            let reward_accounts = expect_single_field(
                sum.fields,
                "TreasuryWithdrawalReturnAccountsDoNotExist expects accounts",
            )?;
            Ok(
                ConwayGovPredicateFailure::TreasuryWithdrawalReturnAccountsDoNotExist {
                    reward_accounts,
                },
            )
        }
        Ok(ConwayGovPredicateFailureTag::UnelectedCommitteeVoters) => {
            let voters =
                expect_single_field(sum.fields, "UnelectedCommitteeVoters expects payload")?;
            Ok(ConwayGovPredicateFailure::UnelectedCommitteeVoters { voters })
        }
        _ => Ok(ConwayGovPredicateFailure::Other(sum)),
    }
}

fn parse_conway_certs_failure(term: Term) -> Result<ConwayCertsPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "certs predicate failure must be a tagged sum",
    ))?;

    match ConwayCertsPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayCertsPredicateFailureTag::WithdrawalsNotInRewardsCERTS) => {
            let withdrawals = expect_single_field(
                sum.fields,
                "WithdrawalsNotInRewardsCERTS expects withdrawals payload",
            )?;
            Ok(ConwayCertsPredicateFailure::WithdrawalsNotInRewardsCERTS { withdrawals })
        }
        Ok(ConwayCertsPredicateFailureTag::CertFailure) => {
            let child = expect_single_field(sum.fields, "CertFailure expects a single payload")?;
            let cert = parse_conway_cert_failure(child)?;
            Ok(ConwayCertsPredicateFailure::CertFailure(Box::new(cert)))
        }
        _ => Ok(ConwayCertsPredicateFailure::Other(sum)),
    }
}

fn parse_conway_cert_failure(term: Term) -> Result<ConwayCertPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "certificate predicate failure must be a tagged sum",
    ))?;

    match ConwayCertPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayCertPredicateFailureTag::DelegFailure) => {
            let child = expect_single_field(sum.fields, "DelegFailure expects a single payload")?;
            let deleg = parse_conway_deleg_failure(child)?;
            Ok(ConwayCertPredicateFailure::DelegFailure(Box::new(deleg)))
        }
        Ok(ConwayCertPredicateFailureTag::PoolFailure) => {
            let failure = expect_single_field(sum.fields, "PoolFailure expects a single payload")?;
            Ok(ConwayCertPredicateFailure::PoolFailure { failure })
        }
        Ok(ConwayCertPredicateFailureTag::GovCertFailure) => {
            let child = expect_single_field(sum.fields, "GovCertFailure expects a single payload")?;
            let gov = parse_conway_gov_cert_failure(child)?;
            Ok(ConwayCertPredicateFailure::GovCertFailure(Box::new(gov)))
        }
        _ => Ok(ConwayCertPredicateFailure::Other(sum)),
    }
}

fn parse_conway_deleg_failure(term: Term) -> Result<ConwayDelegPredicateFailure, ParseError> {
    let sum = TaggedSum::from_term(term).ok_or(ParseError::Malformed(
        "deleg predicate failure must be a tagged sum",
    ))?;

    match ConwayDelegPredicateFailureTag::try_from(sum.tag) {
        Ok(ConwayDelegPredicateFailureTag::IncorrectDepositDELEG) => {
            let deposit =
                expect_single_field(sum.fields, "IncorrectDeposit expects a deposit payload")?;
            Ok(ConwayDelegPredicateFailure::IncorrectDeposit { deposit })
        }
        Ok(ConwayDelegPredicateFailureTag::StakeKeyRegisteredDELEG) => {
            let stake_credential = expect_single_field(
                sum.fields,
                "StakeKeyRegistered expects a credential payload",
            )?;
            Ok(ConwayDelegPredicateFailure::StakeKeyRegistered { stake_credential })
        }
        Ok(ConwayDelegPredicateFailureTag::StakeKeyNotRegisteredDELEG) => {
            let stake_credential = expect_single_field(
                sum.fields,
                "StakeKeyNotRegistered expects a credential payload",
            )?;
            Ok(ConwayDelegPredicateFailure::StakeKeyNotRegistered { stake_credential })
        }
        Ok(ConwayDelegPredicateFailureTag::StakeKeyHasNonZeroRewardAccountBalanceDELEG) => {
            let balance = expect_single_field(
                sum.fields,
                "StakeKeyHasNonZeroRewardAccountBalance expects a balance",
            )?;
            Ok(ConwayDelegPredicateFailure::StakeKeyHasNonZeroRewardAccountBalance { balance })
        }
        Ok(ConwayDelegPredicateFailureTag::DelegateeDRepNotRegisteredDELEG) => {
            let delegatee = expect_single_field(
                sum.fields,
                "DelegateeDRepNotRegistered expects a credential",
            )?;
            Ok(ConwayDelegPredicateFailure::DelegateeDRepNotRegistered { delegatee })
        }
        Ok(ConwayDelegPredicateFailureTag::DelegateeStakePoolNotRegisteredDELEG) => {
            let delegatee_term = expect_single_field(
                sum.fields,
                "DelegateeStakePoolNotRegistered expects one argument",
            )?;
            let delegatee = extract_bytes(delegatee_term)?;
            Ok(ConwayDelegPredicateFailure::DelegateeStakePoolNotRegistered { delegatee })
        }
        Ok(ConwayDelegPredicateFailureTag::DepositIncorrectDELEG) => {
            let mismatch =
                expect_single_field(sum.fields, "DepositIncorrect expects mismatch payload")?;
            Ok(ConwayDelegPredicateFailure::DepositIncorrect { mismatch })
        }
        Ok(ConwayDelegPredicateFailureTag::RefundIncorrectDELEG) => {
            let mismatch =
                expect_single_field(sum.fields, "RefundIncorrect expects mismatch payload")?;
            Ok(ConwayDelegPredicateFailure::RefundIncorrect { mismatch })
        }
        _ => Ok(ConwayDelegPredicateFailure::Other(sum)),
    }
}

fn extract_bytes(mut term: Term) -> Result<Vec<u8>, ParseError> {
    loop {
        term = match term {
            Term::Bytes(bytes) => return Ok(bytes),
            Term::Array(mut items) if items.len() == 1 => items.remove(0),
            Term::Tagged(_, boxed) => *boxed,
            _ => return Err(ParseError::Malformed("expected byte string payload")),
        };
    }
}

fn expect_fields(
    mut fields: Vec<Term>,
    expected: usize,
    context: &'static str,
) -> Result<Vec<Term>, ParseError> {
    if fields.len() != expected {
        return Err(ParseError::Malformed(context));
    }
    Ok(fields)
}

fn expect_single_field(fields: Vec<Term>, context: &'static str) -> Result<Term, ParseError> {
    let mut fields = expect_fields(fields, 1, context)?;
    Ok(fields.remove(0))
}

fn expect_two_fields(fields: Vec<Term>, context: &'static str) -> Result<(Term, Term), ParseError> {
    let mut fields = expect_fields(fields, 2, context)?;
    let first = fields.remove(0);
    let second = fields.remove(0);
    Ok((first, second))
}

fn expect_no_fields(fields: Vec<Term>, context: &'static str) -> Result<(), ParseError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ParseError::Malformed(context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::ser::into_writer;
    use ciborium::value::Integer;

    #[test]
    fn round_trip_simple_sum() {
        let mut buffer = Vec::new();
        // Encode a dummy predicate failure represented as [5, [1], "payload"].
        let message = Value::Array(vec![
            Value::Integer(Integer::from(5u64)),
            Value::Array(vec![Value::Integer(Integer::from(1u64))]),
            Value::Text("payload".into()),
        ]);
        into_writer(&message, &mut buffer).expect("encode test value");

        let tree = decode_predicate_failure_bytes(&buffer).expect("parse tree");
        match tree {
            TaggedTree::Sum(sum, children) => {
                assert_eq!(sum.tag, 5);
                assert_eq!(children.len(), 2);
            }
            TaggedTree::Leaf(_) => panic!("expected a sum"),
        }
    }

    #[test]
    fn parse_conway_delegatee_stake_pool_not_registered() {
        let bytes = hex_to_bytes(
            "82028182068182018202d9010281581cda79a7527e856e5e1b1653c6c8e1255f79d8fe38b7e0a97bb5d0872c",
        );
        let failures =
            decode_conway_ledger_failures_bytes(&bytes).expect("decode Conway ledger failures");
        assert_eq!(failures.len(), 1);

        match &failures[0] {
            ConwayLedgerPredicateFailure::CertsFailure(certs) => match &**certs {
                ConwayCertsPredicateFailure::CertFailure(cert) => match &**cert {
                    ConwayCertPredicateFailure::DelegFailure(deleg) => match deleg {
                        ConwayDelegPredicateFailure::DelegateeStakePoolNotRegistered {
                            delegatee,
                        } => {
                            assert_eq!(
                                delegatee,
                                &hex_to_bytes(
                                    "da79a7527e856e5e1b1653c6c8e1255f79d8fe38b7e0a97bb5d0872c",
                                )
                            );
                        }
                        other => panic!("unexpected deleg predicate failure: {:?}", other),
                    },
                    other => panic!("unexpected certificate predicate failure: {:?}", other),
                },
                other => panic!("unexpected certs predicate failure: {:?}", other),
            },
            other => panic!("unexpected ledger predicate failure: {:?}", other),
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks(2) {
            let hi = (chunk[0] as char).to_digit(16).expect("upper nibble") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("lower nibble") as u8;
            out.push((hi << 4) | lo);
        }
        out
    }
}
