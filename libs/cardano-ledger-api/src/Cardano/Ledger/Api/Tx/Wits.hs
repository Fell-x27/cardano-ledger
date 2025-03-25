module Cardano.Ledger.Api.Tx.Wits (
  -- * Shelley onwards
  EraTxWits (TxWits),
  mkBasicTxWits,

  -- ** Address witness
  addrTxWitsL,
  KeyRole (Witness),

  -- *** WitVKey
  WitVKey (WitVKey),
  witVKeyHash,

  -- ** Byron address witness
  bootAddrTxWitsL,
  BootstrapWitness,

  -- ** Script witness
  scriptTxWitsL,
  hashScriptTxWitsL,

  -- * Alonzo onwards
  AlonzoEraTxWits,
  datsTxWitsL,
  hashDataTxWitsL,
  TxDats (..),
  unTxDats,
  unTxDatsL,
  rdmrsTxWitsL,
  Redeemers (..),
  unRedeemers,
  unRedeemersL,
  PlutusPurpose,
  AlonzoPlutusPurpose (..),
  AsIx (..),
  AsItem (..),

  -- ** Conway
  ConwayPlutusPurpose (..),
)
where

import Cardano.Ledger.Alonzo.Scripts (
  AlonzoPlutusPurpose (..),
  AsItem (..),
  AsIx (..),
  PlutusPurpose,
 )
import Cardano.Ledger.Alonzo.TxWits (
  AlonzoEraTxWits,
  Redeemers (..),
  TxDats (..),
  datsTxWitsL,
  hashDataTxWitsL,
  rdmrsTxWitsL,
  unRedeemers,
  unRedeemersL,
  unTxDats,
  unTxDatsL,
 )
import Cardano.Ledger.Api.Era ()
import Cardano.Ledger.Conway.Scripts (ConwayPlutusPurpose (..))
import Cardano.Ledger.Core (EraTxWits (..), hashScriptTxWitsL)
import Cardano.Ledger.Keys (KeyRole (Witness))
import Cardano.Ledger.Keys.Bootstrap (BootstrapWitness)
import Cardano.Ledger.Keys.WitVKey (WitVKey (WitVKey), witVKeyHash)
