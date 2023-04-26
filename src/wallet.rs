use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ecash;
use crate::keyset::{self, KeySet};
use crate::mint::MintResponse;
use crate::secret::Secret;
use crate::Amount;

pub struct Wallet {
    mint: String,
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
        use base64::{engine::general_purpose::URL_SAFE, Engine as _};

        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        let mut random_bytes = [0u8; 32];

        let amounts = total_amount.split();
        let mut output = Vec::with_capacity(amounts.len());

        for amount in amounts {
            // Generate random bytes
            rng.fill_bytes(&mut random_bytes);
            // The secret string
            let secret = URL_SAFE.encode(random_bytes);
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
