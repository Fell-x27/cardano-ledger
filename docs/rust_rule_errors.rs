//! Rust representations of STS predicate failure types extracted from the
//! Cardano ledger `Rules` modules across eras.
//!
//! NOTE: These definitions focus on the structure and CBOR tags of the
//! predicate failure enums. Domain-specific payload types are represented by
//! lightweight stand-ins so the relationships between failures remain clear.
//! Any field marked with `TODO` should be replaced with the concrete type when
//! wiring these definitions into real code.

use std::collections::{BTreeMap, BTreeSet};

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
pub struct Address(pub Vec<u8>); // `address = bytes` with format described in the CDDL.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RewardAccount(pub Vec<u8>); // `reward_account = bytes`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash28(pub [u8; 28]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash32(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ScriptHash(pub Hash28); // `script_hash = hash28`.

pub type PolicyId = ScriptHash; // `policy_id = script_hash`.

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
pub enum MIRPot {
    #[default]
    Reserves,
    Treasury,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnitInterval {
    pub numerator: u64,
    pub denominator: u64,
}

impl UnitInterval {
    pub const HALF: UnitInterval = UnitInterval {
        numerator: 1,
        denominator: 2,
    };
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NonNegativeInterval {
    pub numerator: u64,
    pub denominator: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EpochInterval(pub u32); // `epoch_interval = uint .size 4`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AddrKeyHash(pub Hash28);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeyHash(pub Hash28);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PoolKeyHash(pub Hash28);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VRFKeyHash(pub Hash32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VerificationKey(pub [u8; 32]); // `vkey = bytes .size 32`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Credential {
    KeyHash(AddrKeyHash),
    ScriptHash(ScriptHash),
}

impl Default for Credential {
    fn default() -> Self {
        Credential::KeyHash(AddrKeyHash(Hash28([0; 28])))
    }
}

pub type StakeCredential = Credential;
pub type CommitteeColdCredential = Credential;
pub type CommitteeHotCredential = Credential;
pub type DRepCredential = Credential;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DRep {
    KeyHash(AddrKeyHash),
    ScriptHash(ScriptHash),
    Abstain,
    NoConfidence,
}

impl Default for DRep {
    fn default() -> Self {
        DRep::Abstain
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Anchor {
    pub url: String,
    pub data_hash: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PoolMetadata {
    pub url: String,
    pub metadata_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Relay {
    SingleHostAddr {
        port: Option<u16>,
        ipv4: Option<[u8; 4]>,
        ipv6: Option<[u8; 16]>,
    },
    SingleHostName {
        port: Option<u16>,
        dns_name: String,
    },
    MultiHostName {
        dns_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PoolParams {
    pub operator: PoolKeyHash,
    pub vrf_keyhash: VRFKeyHash,
    pub pledge: Coin,
    pub cost: Coin,
    pub margin: UnitInterval,
    pub reward_account: RewardAccount,
    pub owners: BTreeSet<AddrKeyHash>,
    pub relays: Vec<Relay>,
    pub metadata: Option<PoolMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PoolCert {
    StakeRegistration { credential: StakeCredential },
    StakeDeregistration { credential: StakeCredential },
    StakeDelegation { credential: StakeCredential, pool: PoolKeyHash },
    PoolRegistration { params: PoolParams },
    PoolRetirement { pool: PoolKeyHash, epoch: EpochNo },
    RegCert { credential: StakeCredential, coin: Coin },
    UnregCert { credential: StakeCredential, coin: Coin },
    VoteDelegCert { credential: StakeCredential, drep: DRep },
    StakeVoteDelegCert { credential: StakeCredential, pool: PoolKeyHash, drep: DRep },
    StakeRegDelegCert { credential: StakeCredential, pool: PoolKeyHash, deposit: Coin },
    VoteRegDelegCert { credential: StakeCredential, drep: DRep, deposit: Coin },
    StakeVoteRegDelegCert {
        credential: StakeCredential,
        pool: PoolKeyHash,
        drep: DRep,
        deposit: Coin,
    },
    AuthCommitteeHotCert {
        cold: CommitteeColdCredential,
        hot: CommitteeHotCredential,
    },
    ResignCommitteeColdCert {
        cold: CommitteeColdCredential,
        anchor: Option<Anchor>,
    },
    RegDRepCert {
        credential: DRepCredential,
        deposit: Coin,
        anchor: Option<Anchor>,
    },
    UnregDRepCert {
        credential: DRepCredential,
        deposit: Coin,
    },
    UpdateDRepCert {
        credential: DRepCredential,
        anchor: Option<Anchor>,
    },
}

impl Default for PoolCert {
    fn default() -> Self {
        PoolCert::StakeRegistration {
            credential: StakeCredential::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Withdrawals(pub BTreeMap<RewardAccount, Coin>); // `withdrawals = {+ reward_account => coin}`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AssetName(pub Vec<u8>); // `asset_name = bytes .size (0 .. 32)`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MultiAsset(pub BTreeMap<PolicyId, BTreeMap<AssetName, u64>>);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueStruct {
    Coin(Coin),
    MultiAsset { coin: Coin, assets: MultiAsset },
}

impl Default for ValueStruct {
    fn default() -> Self {
        ValueStruct::Coin(Coin(0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BoundedBytes(pub Vec<u8>); // `bounded_bytes = bytes .size (0 .. 64)`.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BigInt {
    Int(i128),
    BigUInt(BoundedBytes),
    BigNInt(BoundedBytes),
}

impl Default for BigInt {
    fn default() -> Self {
        BigInt::Int(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlutusData {
    Constr { tag: u32, fields: Vec<PlutusData> },
    Map(BTreeMap<PlutusData, PlutusData>),
    List(Vec<PlutusData>),
    Integer(BigInt),
    Bytes(Vec<u8>),
}

impl Default for PlutusData {
    fn default() -> Self {
        PlutusData::Integer(BigInt::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatumOption {
    Hash(DataHash),
    Inline(PlutusData),
}

impl Default for DatumOption {
    fn default() -> Self {
        DatumOption::Hash(DataHash(Hash32([0; 32])))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NativeScript {
    ScriptPubkey(AddrKeyHash),
    ScriptAll(Vec<NativeScript>),
    ScriptAny(Vec<NativeScript>),
    ScriptNOfK { required: i64, scripts: Vec<NativeScript> },
    InvalidBefore(SlotNo),
    InvalidHereafter(SlotNo),
}

impl Default for NativeScript {
    fn default() -> Self {
        NativeScript::ScriptPubkey(AddrKeyHash(Hash28([0; 28])))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlutusScript {
    V1(Vec<u8>),
    V2(Vec<u8>),
    V3(Vec<u8>),
}

impl Default for PlutusScript {
    fn default() -> Self {
        PlutusScript::V1(vec![])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Script {
    Native(NativeScript),
    Plutus(PlutusScript),
}

impl Default for Script {
    fn default() -> Self {
        Script::Native(NativeScript::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ScriptRef(pub Script);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TxOutStruct {
    Shelley {
        address: Address,
        amount: ValueStruct,
        datum_hash: Option<DataHash>,
    },
    Babbage {
        address: Address,
        amount: ValueStruct,
        datum_option: Option<DatumOption>,
        script_ref: Option<ScriptRef>,
    },
}

impl Default for TxOutStruct {
    fn default() -> Self {
        TxOutStruct::Shelley {
            address: Address::default(),
            amount: ValueStruct::default(),
            datum_hash: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UTxOStruct(pub BTreeMap<TxIn, TxOutStruct>);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VotingProcedure {
    pub vote: u8, // `vote = 0 .. 2`
    pub anchor: Option<Anchor>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoterEnum {
    CommitteeKey(AddrKeyHash),
    CommitteeScript(ScriptHash),
    DRepKey(AddrKeyHash),
    DRepScript(ScriptHash),
    StakePool(PoolKeyHash),
}

impl Default for VoterEnum {
    fn default() -> Self {
        VoterEnum::DRepKey(AddrKeyHash(Hash28([0; 28])))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VotingProceduresStruct(
    pub BTreeMap<VoterEnum, BTreeMap<GovActionId, VotingProcedure>>,
);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProposalProcedureStruct {
    pub deposit: Coin,
    pub reward_account: RewardAccount,
    pub action: GovActionStruct,
    pub anchor: Anchor,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Constitution {
    pub anchor: Anchor,
    pub script_hash: Option<ScriptHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CostModels(pub BTreeMap<u8, Vec<i64>>);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ExUnitPrices {
    pub mem_price: NonNegativeInterval,
    pub step_price: NonNegativeInterval,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PoolVotingThresholds {
    pub motion_no_confidence: UnitInterval,
    pub committee_normal: UnitInterval,
    pub committee_no_confidence: UnitInterval,
    pub hard_fork_initiation: UnitInterval,
    pub security_parameter: UnitInterval,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DRepVotingThresholds {
    pub motion_no_confidence: UnitInterval,
    pub committee_normal: UnitInterval,
    pub committee_no_confidence: UnitInterval,
    pub update_constitution: UnitInterval,
    pub hard_fork_initiation: UnitInterval,
    pub pparam_network: UnitInterval,
    pub pparam_economic: UnitInterval,
    pub pparam_technical: UnitInterval,
    pub pparam_governance: UnitInterval,
    pub treasury_withdrawal: UnitInterval,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ProtocolParamUpdate {
    pub minfee_a: Option<Coin>,
    pub minfee_b: Option<Coin>,
    pub max_block_body_size: Option<u32>,
    pub max_tx_size: Option<u32>,
    pub max_block_header_size: Option<u16>,
    pub key_deposit: Option<Coin>,
    pub pool_deposit: Option<Coin>,
    pub max_epoch: Option<EpochInterval>,
    pub desired_number_of_pools: Option<u16>,
    pub pool_pledge_influence: Option<NonNegativeInterval>,
    pub expansion_rate: Option<UnitInterval>,
    pub treasury_growth_rate: Option<UnitInterval>,
    pub min_pool_cost: Option<Coin>,
    pub ada_per_utxo_byte: Option<Coin>,
    pub cost_models: Option<CostModels>,
    pub ex_unit_prices: Option<ExUnitPrices>,
    pub max_tx_ex_units: Option<ExUnits>,
    pub max_block_ex_units: Option<ExUnits>,
    pub max_value_size: Option<u32>,
    pub collateral_percentage: Option<u16>,
    pub max_collateral_inputs: Option<u16>,
    pub pool_voting_thresholds: Option<PoolVotingThresholds>,
    pub drep_voting_thresholds: Option<DRepVotingThresholds>,
    pub min_committee_size: Option<u16>,
    pub committee_term_limit: Option<EpochInterval>,
    pub governance_action_validity_period: Option<EpochInterval>,
    pub governance_action_deposit: Option<Coin>,
    pub drep_deposit: Option<Coin>,
    pub drep_inactivity_period: Option<EpochInterval>,
    pub ref_script_coins_per_byte: Option<NonNegativeInterval>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovActionId {
    pub tx_id: TxId,
    pub action_index: GovActionIx,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GovActionStruct {
    ParameterChange {
        previous: Option<GovPurposeIdStruct>,
        update: ProtocolParamUpdate,
        policy_hash: Option<ScriptHash>,
    },
    HardForkInitiation {
        previous: Option<GovPurposeIdStruct>,
        protocol_version: ProtVer,
    },
    TreasuryWithdrawals {
        withdrawals: BTreeMap<RewardAccount, Coin>,
        policy_hash: Option<ScriptHash>,
    },
    NoConfidence {
        previous: Option<GovPurposeIdStruct>,
    },
    UpdateCommittee {
        previous: Option<GovPurposeIdStruct>,
        removals: BTreeSet<CommitteeColdCredential>,
        additions: BTreeMap<CommitteeColdCredential, EpochNo>,
        new_quorum: UnitInterval,
    },
    NewConstitution {
        previous: Option<GovPurposeIdStruct>,
        constitution: Constitution,
    },
    InfoAction,
}

impl Default for GovActionStruct {
    fn default() -> Self {
        GovActionStruct::InfoAction
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum GovActionPurpose {
    ParameterChange,
    HardFork,
    Committee,
    Constitution,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovPurposeIdStruct {
    pub purpose: GovActionPurpose,
    pub id: GovActionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RedeemerTag {
    Spend,
    Mint,
    Cert,
    Reward,
    Voting,
    Proposing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PlutusPurposeStruct {
    pub tag: RedeemerTag,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GovEnvStruct;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationKind {
    Eq,
    Lteq,
    Gteq,
    Lt,
    Gt,
    Subset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationMismatch<T> {
    pub relation: RelationKind,
    pub supplied: T,
    pub expected: T,
}

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
pub struct GovActionIx(pub u16);

pub type TxOut<Era> = TxOutStruct;
pub type Value<Era> = ValueStruct;
pub type UTxO<Era> = UTxOStruct;
pub type GovAction<Era> = GovActionStruct;
pub type ProposalProcedure<Era> = ProposalProcedureStruct;
pub type VotingProcedures<Era> = VotingProceduresStruct;
pub type GovEnv<Era> = GovEnvStruct;
pub type Voter = VoterEnum;
pub type GovPurposeId<Purpose> = GovPurposeIdStruct;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HardForkPurpose;

pub type PlutusPurpose<Tag, Era> = PlutusPurposeStruct;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AsItem;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AsIx;

pub type Mismatch<Relation, T> = RelationMismatch<T>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelEQ;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelLTEQ;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelGTEQ;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelLT;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RelGT;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
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
            offending_keys: Mismatch<RelSubset, BTreeSet<KeyHash>>,
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
            offending: BTreeSet<Address>,
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
            invalid_witnesses: Vec<Credential>,
        },
        /// Tag: 1
        MissingVKeyWitnessesUTXOW {
            missing_signers: BTreeSet<KeyHash>,
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
            missing_signatures: BTreeSet<KeyHash>,
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
            credential: Credential,
        },
        /// Tag: 1
        StakeKeyNotRegistered {
            credential: Credential,
        },
        /// Tag: 2
        StakeKeyNonZeroAccountBalance {
            remaining_balance: Coin,
        },
        /// Tag: 3
        StakeDelegationImpossible {
            credential: Credential,
        },
        /// Tag: 4
        WrongCertificateType,
        /// Tag: 5
        GenesisKeyNotInMapping {
            genesis_key: KeyHash,
        },
        /// Tag: 6
        DuplicateGenesisDelegate {
            delegate: KeyHash,
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
            vrf: VRFKeyHash,
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
            pool_id: KeyHash,
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
            pool_id: KeyHash,
        },
        /// Tag: 5
        PoolMetadataHashTooBig {
            pool_id: KeyHash,
            hash_size: usize,
        },
        /// Tag: 6
        VRFKeyHashAlreadyRegistered {
            pool_id: KeyHash,
            vrf: VRFKeyHash,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DelegsPredicateFailure<Era> {
        /// Tag: 0
        DelegateeNotRegistered {
            pool_id: KeyHash,
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
            offending: BTreeSet<Address>,
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
        Placeholder, // TODO: encode exact variants from `CollectError`.
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
            offending: BTreeSet<Address>,
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
            witnesses: Vec<VerificationKey>,
        },
        /// Tag: 2
        MissingVKeyWitnessesUTXOW {
            missing: BTreeSet<KeyHash>,
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
            stake_credential: StakeCredential,
        },
        /// Tag: 3
        StakeKeyNotRegisteredDELEG {
            stake_credential: StakeCredential,
        },
        /// Tag: 4
        StakeKeyHasNonZeroRewardAccountBalanceDELEG {
            balance: Coin,
        },
        /// Tag: 5
        DelegateeDRepNotRegisteredDELEG {
            delegatee: DRepCredential,
        },
        /// Tag: 6
        DelegateeStakePoolNotRegisteredDELEG {
            delegatee: PoolKeyHash,
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
            credential: DRepCredential,
        },
        /// Tag: 1
        ConwayDRepNotRegistered {
            credential: DRepCredential,
        },
        /// Tag: 2
        ConwayDRepIncorrectDeposit {
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 3
        ConwayCommitteeHasPreviouslyResigned {
            cold_credential: CommitteeColdCredential,
        },
        /// Tag: 4
        ConwayDRepIncorrectRefund {
            mismatch: Mismatch<RelEQ, Coin>,
        },
        /// Tag: 5
        ConwayCommitteeIsUnknown {
            cold_credential: CommitteeColdCredential,
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
            members: BTreeSet<CommitteeColdCredential>,
        },
        /// Tag: 7
        ExpirationEpochTooSmall {
            expired: BTreeMap<CommitteeColdCredential, EpochNo>,
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
            voters: NonEmpty<CommitteeHotCredential>,
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
            withdrawals: NonEmpty<AddrKeyHash>,
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