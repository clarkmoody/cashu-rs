use std::collections::{HashMap, HashSet};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::ecash;
use crate::ecash::BlindedMessage;
use crate::ecash::BlindedSignature;
use crate::keyset;
use crate::keyset::mint::KeySet;
use crate::secret::Secret;
use crate::wallet;
use crate::Amount;

#[derive(Debug, Serialize, Deserialize)]
pub struct Invoice {
    /// BOLT-11 payment request
    #[serde(rename = "pr")]
    payment_request: String, // TODO: LN invoice
    /// Hash of the invoice
    hash: Sha256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MintResponse {
    pub promises: Vec<ecash::BlindedSignature>,
}

/// Response to the `CheckFeesRequest`
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckFeesResponse {
    /// Expected maximum fees
    fee: Amount,
}

/// Response to a melt request, indicating whether the invoice is paid
#[derive(Debug, Serialize, Deserialize)]
pub struct MeltResponse {
    /// Success status
    paid: bool,
    /// Preimage of the invoice
    preimage: String,
}

/// Response to a split request, containing blind signatures for the
/// amount requested and the change
#[derive(Debug, Serialize, Deserialize)]
pub struct SplitResponse {
    /// Outputs that sum to the remainder after reaching the
    /// requested amount (total - target)
    #[serde(rename = "fst")]
    change: Vec<ecash::BlindedSignature>,
    /// Outputs that sum to the target requested amount
    #[serde(rename = "snd")]
    target: Vec<ecash::BlindedSignature>,
}

pub struct Mint {
    active_keyset: KeySet,
    inactive_keysets: HashMap<keyset::Id, KeySet>,
    paid_invoices: HashMap<Sha256, (Amount, String)>,
    pending_invoices: HashMap<Sha256, (Amount, String)>,
    spent_secrets: HashSet<Secret>,
}

impl Mint {
    /// Create a new mint, generating a keyset
    pub fn new(
        secret: impl Into<String>,
        derivation_path: impl Into<String>,
        max_order: u8,
    ) -> Self {
        Self {
            active_keyset: KeySet::generate(secret, derivation_path, max_order),
            inactive_keysets: Default::default(),
            paid_invoices: Default::default(),
            pending_invoices: Default::default(),
            spent_secrets: Default::default(),
        }
    }

    pub fn from_keyset(keyset: KeySet) -> Self {
        Self {
            active_keyset: keyset,
            inactive_keysets: Default::default(),
            paid_invoices: Default::default(),
            pending_invoices: Default::default(),
            spent_secrets: Default::default(),
        }
    }

    /// Retrieve the public keys of the active keyset for distribution to
    /// wallet clients
    pub fn active_keyset_pubkeys(&self) -> keyset::KeySet {
        keyset::KeySet::from(self.active_keyset.clone())
    }

    /// Generate a new active keyset and move the current active keyset to the
    /// inactive list
    pub fn rotate_keyset(
        &mut self,
        secret: impl Into<String>,
        derivation_path: impl Into<String>,
        max_order: u8,
    ) {
        self.inactive_keysets
            .insert(self.active_keyset.id.clone(), self.active_keyset.clone());
        self.active_keyset = KeySet::generate(secret, derivation_path, max_order);
    }

    pub fn process_invoice_request(&mut self, amount: Amount) -> Invoice {
        let invoice = String::new(); // TODO: LN invoice
        let hash = Sha256::hash(invoice.as_bytes());
        self.pending_invoices
            .insert(hash, (amount, invoice.clone()));

        Invoice {
            payment_request: invoice,
            hash,
        }
    }

    pub fn pay_invoice(&mut self, hash: Sha256) {
        if let Some((amount, invoice)) = self.pending_invoices.remove(&hash) {
            self.paid_invoices.insert(hash, (amount, invoice));
        }
    }

    pub fn process_mint_request(
        &mut self,
        payment_hash: Sha256,
        mint_request: wallet::MintRequest,
    ) -> Result<MintResponse, Error> {
        let Some((amount, _invoice)) = self.paid_invoices.get(&payment_hash) else {
            return Err(Error::InvalidPaymentHash);
        };

        // Check for amount mismatch
        if mint_request.total_amount() != *amount {
            return Err(Error::InvalidAmount);
        }

        let mut blind_signatures = Vec::with_capacity(mint_request.outputs.len());

        for blinded_message in mint_request.outputs {
            blind_signatures.push(self.blind_sign(&blinded_message)?);
        }

        self.paid_invoices.remove(&payment_hash);

        Ok(MintResponse {
            promises: blind_signatures,
        })
    }

    fn blind_sign(&self, blinded_message: &BlindedMessage) -> Result<BlindedSignature, Error> {
        let secp = Secp256k1::new();

        let BlindedMessage { amount, b } = blinded_message;

        let Some(key_pair) = self.active_keyset.get(*amount) else {
            // No key for amount
            return Err(Error::InvalidAmount);
        };

        let scalar = secp256k1::Scalar::from(key_pair.secret_key());

        Ok(BlindedSignature {
            amount: *amount,
            c: b.mul_tweak(&secp, &scalar).expect("ec math"),
            id: Some(self.active_keyset.id.clone()),
        })
    }

    fn verify_proof(&self, proof: &ecash::Proof) -> Result<String, Error> {
        let secp = Secp256k1::new();

        let ecash::Proof {
            amount,
            secret,
            c,
            id,
            ..
        } = proof;

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

        let Some(keypair) = keyset.get(*amount) else {
            return Err(Error::InvalidAmount);
        };

        let k = keypair.secret_key();
        let y = ecash::hash_to_curve(secret.as_bytes());
        let ky = y.mul_tweak(&secp, &Scalar::from(k)).expect("ec math");

        if ky == *c {
            Ok(secret.clone())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAmount,
    InvalidProof,
    InvalidPaymentHash,
}

#[cfg(test)]
mod test {
    use super::Mint;
    use crate::{wallet, Amount};

    #[test]
    fn becdh() {
        let mut mint = Mint::new("the-secret", "0/0/0/0", 4);
        let invoice = mint.process_invoice_request(Amount::from(13));
        mint.pay_invoice(invoice.hash);

        let mut wallet = wallet::Wallet::new("mint", mint.active_keyset_pubkeys());
        let pre_secrets = wallet::PreMintSecrets::new(Amount::from(13));
        let mint_request = wallet::MintRequest::from(&pre_secrets);

        let mint_response = mint
            .process_mint_request(invoice.hash, mint_request)
            .expect("process mint request");
        wallet.process_mint_response(pre_secrets, mint_response);

        // TODO: Melt / Split requests here instead

        for proof in wallet.proofs {
            assert_eq!(mint.verify_proof(&proof), Ok(proof.secret));
        }
    }
}
