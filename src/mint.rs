use std::collections::{HashMap, HashSet};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use serde::{Deserialize, Serialize};

use crate::ecash::{self, BlindedMessage, BlindedSignature};
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
    /// Random hash. MUST NOT be the hash of the invoice.
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

impl SplitResponse {
    pub fn change_amount(&self) -> Amount {
        self.change
            .iter()
            .map(|ecash::BlindedSignature { amount, .. }| *amount)
            .sum()
    }

    pub fn target_amount(&self) -> Amount {
        self.target
            .iter()
            .map(|ecash::BlindedSignature { amount, .. }| *amount)
            .sum()
    }
}

/// API response for list of keysets
#[derive(Debug, Serialize, Deserialize)]
pub struct KeySetsResponse {
    keysets: Vec<keyset::Id>,
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

    /// Return a list of all supported keysets
    pub fn keysets(&self) -> KeySetsResponse {
        let mut keysets: Vec<_> = self.inactive_keysets.keys().cloned().collect();
        keysets.push(self.active_keyset.id.clone());
        KeySetsResponse { keysets }
    }

    pub fn keyset(&self, id: &keyset::Id) -> Option<keyset::KeySet> {
        if &self.active_keyset.id == id {
            return Some(self.active_keyset.clone().into());
        }

        self.inactive_keysets.get(id).map(|k| k.clone().into())
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
        use rand::RngCore;

        let invoice = String::new(); // TODO: LN invoice

        let mut rng = rand::thread_rng();
        let mut random_bytes = [0u8; Sha256::LEN];
        rng.fill_bytes(&mut random_bytes);
        let hash = Sha256::hash(&random_bytes);

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
        hash: Sha256,
        mint_request: wallet::MintRequest,
    ) -> Result<MintResponse, Error> {
        let Some((amount, _invoice)) = self.paid_invoices.get(&hash) else {
            return Err(Error::PaymentHash);
        };

        // Check for amount mismatch
        if mint_request.total_amount() != *amount {
            return Err(Error::Amount);
        }

        let mut blind_signatures = Vec::with_capacity(mint_request.outputs.len());

        for blinded_message in mint_request.outputs {
            blind_signatures.push(self.blind_sign(&blinded_message)?);
        }

        self.paid_invoices.remove(&hash);

        Ok(MintResponse {
            promises: blind_signatures,
        })
    }

    fn blind_sign(&self, blinded_message: &BlindedMessage) -> Result<BlindedSignature, Error> {
        use bitcoin::secp256k1::{Scalar, Secp256k1};

        let secp = Secp256k1::new();

        let BlindedMessage { amount, b } = blinded_message;

        let Some(key_pair) = self.active_keyset.get(*amount) else {
            // No key for amount
            return Err(Error::Amount);
        };

        let scalar = Scalar::from(key_pair.secret_key());

        Ok(BlindedSignature {
            amount: *amount,
            c: b.mul_tweak(&secp, &scalar).expect("ec math"),
            id: Some(self.active_keyset.id.clone()),
        })
    }

    pub fn process_split_request(
        &mut self,
        split_request: wallet::split::Request,
    ) -> Result<SplitResponse, Error> {
        let proofs_total = split_request.proofs_amount();
        if proofs_total < split_request.amount {
            return Err(Error::Amount);
        }

        let output_total = split_request.output_amount();
        if output_total < split_request.amount {
            return Err(Error::Amount);
        }

        if proofs_total != output_total {
            return Err(Error::Amount);
        }

        let mut secrets = Vec::with_capacity(split_request.proofs.len());
        for proof in split_request.proofs {
            secrets.push(self.verify_proof(&proof)?);
        }

        let mut target_total = Amount::ZERO;
        let mut change_total = Amount::ZERO;
        let mut target = Vec::with_capacity(split_request.outputs.len());
        let mut change = Vec::with_capacity(split_request.outputs.len());

        // Create sets of target and change amounts that we're looking for
        // in the outputs (blind messages). As we loop, take from those sets,
        // target amount first.
        for output in split_request.outputs {
            let signed = self.blind_sign(&output)?;

            // Accumulate outputs into the target (send) list
            if target_total + signed.amount <= split_request.amount {
                target_total += signed.amount;
                target.push(signed);
            } else {
                change_total += signed.amount;
                change.push(signed);
            }
        }

        if target_total != split_request.amount {
            return Err(Error::OutputOrdering);
        }

        for secret in secrets {
            self.spent_secrets.insert(secret);
        }

        Ok(SplitResponse { change, target })
    }

    fn verify_proof(&self, proof: &ecash::Proof) -> Result<Secret, Error> {
        use bitcoin::secp256k1::{Scalar, Secp256k1};

        let secp = Secp256k1::new();

        let ecash::Proof {
            amount,
            secret,
            c,
            id,
            ..
        } = proof;

        if self.spent_secrets.contains(&secret) {
            return Err(Error::Proof);
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

        let Some(keypair) = keyset.get(*amount) else {
            return Err(Error::Amount);
        };

        let k = keypair.secret_key();
        let y = ecash::hash_to_curve(secret.as_bytes());
        let ky = y.mul_tweak(&secp, &Scalar::from(k)).expect("ec math");

        if ky == *c {
            Ok(secret.clone())
        } else {
            Err(Error::Proof)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Amount,
    OutputOrdering,
    PaymentHash,
    Proof,
}

pub mod request {
    use super::{wallet, Amount, Sha256};
    use serde::Serialize;
    use url::Url;

    #[derive(Debug)]
    pub struct Request {
        pub method: Method,
        pub url: Url,
        pub body: Option<serde_json::Value>,
    }

    impl Request {
        fn get(url: Url) -> Self {
            Request {
                method: Method::Get,
                url,
                body: None,
            }
        }

        fn post_json<T: Serialize>(url: Url, body: T) -> Self {
            Request {
                method: Method::Post,
                url,
                body: serde_json::to_value(&body).ok(),
            }
        }
    }

    #[derive(Debug)]
    pub enum Method {
        Get,
        Post,
    }

    /// Valid requests to make to the mint
    #[derive(Debug)]
    pub enum Endpoint {
        Keys,
        InvoiceRequest {
            amount: Amount,
        },
        MintRequest {
            payment_hash: Sha256,
            mint_request: wallet::MintRequest,
        },
        Split {
            split_request: wallet::split::Request,
        },
    }

    impl Endpoint {
        pub fn request(&self, base: &Url) -> Request {
            match self {
                Endpoint::Keys => Request::get(base.join("/keys").unwrap()),
                Endpoint::InvoiceRequest { amount } => {
                    let mut url = base.join("/mint").unwrap();
                    url.query_pairs_mut()
                        .append_pair("amount", amount.to_string().as_str());
                    Request::get(url)
                }
                Endpoint::MintRequest {
                    payment_hash,
                    mint_request,
                } => {
                    let mut url = base.join("/mint").unwrap();
                    url.query_pairs_mut()
                        .append_pair("hash", payment_hash.to_string().as_str());
                    Request::post_json(url, mint_request)
                }
                Endpoint::Split { split_request } => {
                    let url = base.join("/split").unwrap();
                    Request::post_json(url, split_request)
                }
            }
        }
    }
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

        let url = url::Url::parse("http://localhost").unwrap();

        let mut wallet = wallet::Wallet::new(url, mint.active_keyset_pubkeys());
        let pre_secrets = wallet::PreMintSecrets::new(Amount::from(13));
        let mint_request = wallet::MintRequest::from(&pre_secrets);

        let mint_response = mint
            .process_mint_request(invoice.hash, mint_request)
            .expect("process mint request");
        wallet.process_mint_response(pre_secrets, mint_response);

        let pre_split_request = wallet
            .pre_split_request(Amount::from(7))
            .expect("pre split requst");
        let split_request = wallet::split::Request::from(&pre_split_request);
        let proof_amount = split_request.proofs_amount();

        let split_response = mint
            .process_split_request(split_request)
            .expect("process split request");

        assert_eq!(split_response.target_amount(), Amount::from(7));
        assert_eq!(
            split_response.change_amount(),
            proof_amount - Amount::from(7)
        );
    }
}
