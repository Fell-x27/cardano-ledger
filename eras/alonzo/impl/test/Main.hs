{-# LANGUAGE TypeApplications #-}

module Main where

import Cardano.Ledger.Alonzo (Alonzo)
import qualified Test.Cardano.Ledger.Alonzo.Binary.CddlSpec as CddlSpec
import qualified Test.Cardano.Ledger.Alonzo.Binary.CostModelsSpec as CostModelsSpec
import qualified Test.Cardano.Ledger.Alonzo.Binary.TxWitsSpec as TxWitsSpec
import qualified Test.Cardano.Ledger.Alonzo.BinarySpec as BinarySpec
import qualified Test.Cardano.Ledger.Alonzo.GoldenTranslation as Golden
import qualified Test.Cardano.Ledger.Alonzo.Imp as Imp
import Test.Cardano.Ledger.Alonzo.ImpTest ()
import Test.Cardano.Ledger.Common
import Test.Cardano.Ledger.Core.JSON (roundTripJsonEraSpec)

main :: IO ()
main =
  ledgerTestMain $
    describe "Alonzo" $ do
      BinarySpec.spec
      CddlSpec.spec
      roundTripJsonEraSpec @Alonzo
      Golden.tests
      describe "Imp" $ do
        Imp.spec @Alonzo
      describe "CostModels" $ do
        CostModelsSpec.spec @Alonzo
      describe "TxWits" $ do
        TxWitsSpec.spec @Alonzo
