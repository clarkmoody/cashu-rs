use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ecash;
use crate::keyset::{self, KeySet};
use crate::mint::MintResponse;
use crate::secret::Secret;
use crate::Amount;

pub struct Wallet {
    _mint: String,
    active_keyset: KeySet,
    inactive_keysets: HashMap<keyset::Id, KeySet>,
    // TODO: Wallet Proof type that contains flag for pending and send ID
    pub proofs: ecash::Proofs,
}

impl Wallet {
    pub fn new(mint: impl Into<String>, active_keyset: KeySet) -> Self {
        Self {
            _mint: mint.into(),
            active_keyset,
            inactive_keysets: Default::default(),
            proofs: Vec::new(),
        }
    }

    pub fn process_mint_response(
        &mut self,
        pre_mint_secrets: PreMintSecrets,
        mint_response: MintResponse,
    ) {
        let secp = Secp256k1::new();

        for (pre_mint, promise) in pre_mint_secrets
            .into_iter()
            .zip(mint_response.promises.into_iter())
        {
            let PreMint {
                amount,
                blinding_factor,
                secret,
                ..
            } = pre_mint;
            let ecash::BlindedSignature {
                amount: promise_amount,
                c,
                id,
            } = promise;

            if amount != promise_amount {
                // Responses out of order or erroneous
                continue; // TODO
            }

            let keyset = id.as_ref().map_or_else(
                || &self.active_keyset,
                |id| {
                    if let Some(keyset) = self.inactive_keysets.get(&id) {
                        keyset
                    } else {
                        &self.active_keyset
                    }
                },
            );

            let Some(k) = keyset.get(amount) else {
                // Missing amount from keyset
                continue; // TODO
            };

            let rk = k
                .mul_tweak(&secp, &Scalar::from(blinding_factor))
                .expect("blinding factor tweak");
            // C = C_ - rK
            let c = c.combine(&rk.negate(&secp)).expect("combine pubkeys");

            let proof = ecash::Proof {
                amount,
                secret,
                c,
                id,
                script: None,
            };

            self.proofs.push(proof);
        }
    }

    pub fn pre_split_request(&self, target: Amount) -> Result<PreSplitRequest, Error> {
        let mut proofs = Vec::with_capacity(self.proofs.len());
        let mut running_total = Amount::ZERO;
        for proof in self.proofs.iter() {
            running_total += proof.amount;
            proofs.push(proof.clone());

            if running_total >= target {
                return PreSplitRequest::new(target, proofs);
            }
        }

        Err(Error::InsufficientFunds)
    }
}

pub struct PreMint {
    amount: Amount,
    blinded_key: PublicKey,
    blinding_factor: SecretKey,
    secret: Secret,
}

pub struct PreMintSecrets {
    secrets: Vec<PreMint>,
}

impl PreMintSecrets {
    pub fn new(total_amount: Amount) -> Self {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        let amounts = total_amount.split();
        let n = amounts.len();
        let mut output = Vec::with_capacity(n);

        for (amount, secret) in amounts.into_iter().zip(Secret::generate(n).into_iter()) {
            // Get a curve point from the hash of the secret (Y)
            let y = ecash::hash_to_curve(secret.as_bytes());
            // The blinding factor is a random secret key (r)
            let (blinding_factor, _) = secp.generate_keypair(&mut rng);
            // Compute the blinded key: B_ = Y + rG
            let blinded_key = y
                .add_exp_tweak(&secp, &Scalar::from(blinding_factor))
                .expect("EC math");

            output.push(PreMint {
                amount,
                blinded_key,
                blinding_factor,
                secret,
            });
        }

        Self { secrets: output }
    }

    fn iter(&self) -> impl Iterator<Item = &PreMint> {
        self.secrets.iter()
    }

    fn into_iter(self) -> impl Iterator<Item = PreMint> {
        self.secrets.into_iter()
    }

    fn len(&self) -> usize {
        self.secrets.len()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MintRequest {
    pub outputs: Vec<ecash::BlindedMessage>,
}

impl MintRequest {
    pub fn total_amount(&self) -> Amount {
        self.outputs
            .iter()
            .map(|ecash::BlindedMessage { amount, .. }| *amount)
            .sum()
    }
}

impl From<&PreMintSecrets> for MintRequest {
    fn from(secrets: &PreMintSecrets) -> Self {
        MintRequest {
            outputs: secrets
                .iter()
                .map(
                    |PreMint {
                         amount,
                         blinded_key,
                         ..
                     }| ecash::BlindedMessage {
                        amount: *amount,
                        b: *blinded_key,
                    },
                )
                .collect(),
        }
    }
}

pub struct PreSplitRequest {
    pub amount: Amount,
    pub target_secrets: PreMintSecrets,
    pub change_secrets: PreMintSecrets,
    pub proofs: ecash::Proofs,
}

impl PreSplitRequest {
    pub fn new(target: Amount, proofs: ecash::Proofs) -> Result<PreSplitRequest, Error> {
        let proof_total_amount = proofs
            .iter()
            .map(|ecash::Proof { amount, .. }| *amount)
            .sum();

        if target > proof_total_amount {
            return Err(Error::InsufficientFunds);
        }

        let change = proof_total_amount - target;
        let target_secrets = PreMintSecrets::new(target);
        let change_secrets = PreMintSecrets::new(change);

        Ok(PreSplitRequest {
            amount: target,
            target_secrets,
            change_secrets,
            proofs,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SplitRequest {
    /// Amount fo value to split out of the Proofs
    pub amount: Amount,
    /// Messages for the mint to sign
    pub outputs: Vec<ecash::BlindedMessage>,
    /// Tokens spent to the mint to be reissued as the `outputs`
    pub proofs: ecash::Proofs,
}

impl SplitRequest {
    pub fn proofs_amount(&self) -> Amount {
        self.proofs
            .iter()
            .map(|ecash::Proof { amount, .. }| *amount)
            .sum()
    }

    pub fn output_amount(&self) -> Amount {
        self.outputs
            .iter()
            .map(|ecash::BlindedMessage { amount, .. }| *amount)
            .sum()
    }
}

impl From<&PreSplitRequest> for SplitRequest {
    fn from(req: &PreSplitRequest) -> Self {
        let mut outputs = Vec::with_capacity(req.target_secrets.len() + req.change_secrets.len());
        outputs.extend(MintRequest::from(&req.target_secrets).outputs);
        outputs.extend(MintRequest::from(&req.change_secrets).outputs);

        SplitRequest {
            amount: req.amount,
            outputs,
            proofs: req.proofs.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InsufficientFunds,
}
