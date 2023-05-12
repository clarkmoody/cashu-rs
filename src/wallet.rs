use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use url::Url;

use crate::ecash::{self, MintProofs, Token};
use crate::keyset::{self, KeySet};
use crate::mint::request::{Endpoint, Request};
use crate::mint::{MintResponse, SplitResponse};
use crate::secret::Secret;
use crate::Amount;

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    mint: String,
    active_keyset: KeySet,
    inactive_keysets: HashMap<keyset::Id, KeySet>,
    proofs: HashMap<proof::Id, proof::Proof>,
    split_proposals: HashMap<split::Id, split::Proposal>,
}

impl Wallet {
    pub fn new(mint: Url, active_keyset: KeySet) -> Self {
        Self {
            mint: mint.to_string(),
            active_keyset,
            inactive_keysets: Default::default(),
            proofs: Default::default(),
            split_proposals: Default::default(),
        }
    }

    pub fn balance(&self) -> Balance {
        let mut balance = Balance::default();
        for proof in self.proofs.values() {
            balance = balance.add(proof);
        }
        balance
    }

    pub fn active_keyset(&self) -> &KeySet {
        &self.active_keyset
    }

    pub fn mint(&self) -> &str {
        &self.mint
    }

    pub fn request(&self, endpoint: Endpoint) -> Request {
        let url = Url::parse(&self.mint).unwrap();
        endpoint.request(&url)
    }

    pub fn process_mint_response(
        &mut self,
        pre_mint_secrets: PreMintSecrets,
        mint_response: MintResponse,
    ) -> Vec<proof::Id> {
        let secp = Secp256k1::new();
        let mut proof_ids = Vec::new();

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

            let proof = proof::Proof::new(proof);
            proof_ids.push(proof.id());
            self.proofs.insert(proof.id(), proof);
        }

        proof_ids
    }

    /// Gather proofs and create mint requests for the target amount
    pub fn pre_split_request(&mut self, target: Amount) -> Result<split::Proposal, Error> {
        let mut proof_ids = HashSet::new();
        let mut running_total = Amount::ZERO;
        let mut total_reached = false;
        for proof in self.proofs.values().filter(|proof| proof.is_unspent()) {
            running_total += proof.amount();
            proof_ids.insert(proof.id());

            if running_total >= target {
                total_reached = true;
                break;
            }
        }

        if total_reached {
            let split_id = split::Id::new();
            let mut proofs = Vec::with_capacity(proof_ids.len());
            for id in proof_ids {
                if let Some(proof) = self.proofs.get_mut(&id) {
                    proof.spend_pending_split(split_id);
                    proofs.push(proof.clone());
                } else {
                    return Err(Error::InsufficientFunds);
                }
            }
            return split::Proposal::new(split_id, target, proofs);
        }

        Err(Error::InsufficientFunds)
    }

    /// If the split fails, mark the proofs as not spent
    pub fn cancel_pending_split(&mut self, split_proposal: &split::Proposal) {
        for proof in split_proposal.proofs.iter() {
            if let Some(p) = self.proofs.get_mut(&proof.id()) {
                p.set_unspent();
            }
        }
    }

    // TODO: Result
    /// Close the loop after receiving a response to a split request
    pub fn process_split(
        &mut self,
        split_proposal: &split::Proposal,
        split_response: SplitResponse,
    ) -> Option<Token> {
        for id in split_proposal.proofs.iter().map(|p| p.id()) {
            if let Some(proof) = self.proofs.get_mut(&id) {
                proof.spend_in_split(split_proposal.id);
            } else {
                // TODO: Error
                return None;
            }
        }

        let split::Proposal {
            change_secrets,
            target_secrets,
            ..
        } = split_proposal;
        let SplitResponse { change, target } = split_response;
        let change_mint_response = MintResponse { promises: change };
        let _receive_proofs =
            self.process_mint_response(change_secrets.clone(), change_mint_response);

        let target_mint_response = MintResponse { promises: target };
        let target_proofs =
            self.process_mint_response(target_secrets.clone(), target_mint_response);

        let mut token_proofs = Vec::with_capacity(target_proofs.len());
        for id in target_proofs {
            if let Some(proof) = self.proofs.get_mut(&id) {
                proof.set_spent();
                token_proofs.push(proof.inner().clone());
            }
            // TODO: Error for None
        }

        Some(Token {
            memo: None,
            token: vec![MintProofs {
                mint: self.mint.clone(),
                proofs: token_proofs,
            }],
        })
    }

    pub fn receive_proofs(&mut self, proofs: ecash::Proofs) -> Result<split::Proposal, Error> {
        let mut proposal_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let proof = proof::Proof::received(proof);
            proposal_proofs.push(proof.clone());
            self.proofs.insert(proof.id(), proof);
        }
        Ok(split::Proposal::new(
            split::Id::new(),
            Amount::ZERO,
            proposal_proofs,
        )?)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Balance {
    pub settled: Amount,
    pub receiving: Amount,
    pub sending: Amount,
    pub spent: Amount,
}

impl Balance {
    fn add(self, proof: &proof::Proof) -> Self {
        match proof.state() {
            proof::State::Minted => Self {
                settled: self.settled + proof.amount(),
                ..self
            },
            proof::State::Receiving => Self {
                receiving: self.receiving + proof.amount(),
                ..self
            },
            proof::State::PendingSplit { .. } | proof::State::Sent { .. } => Self {
                sending: self.sending + proof.amount(),
                ..self
            },
            proof::State::Split { .. } => Self {
                spent: self.spent + proof.amount(),
                ..self
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreMint {
    amount: Amount,
    blinded_key: PublicKey,
    blinding_factor: SecretKey,
    secret: Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn total_amount(&self) -> Amount {
        self.secrets
            .iter()
            .map(|PreMint { amount, .. }| *amount)
            .sum()
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

pub mod split {
    use serde::{Deserialize, Serialize};

    use super::{Error, MintRequest, PreMintSecrets};
    use crate::{ecash, Amount};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Id(u64);

    impl Id {
        pub fn new() -> Self {
            Self(rand::random())
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Proposal {
        pub id: Id,
        amount: Amount,
        pub target_secrets: PreMintSecrets,
        pub change_secrets: PreMintSecrets,
        pub proofs: Vec<super::proof::Proof>,
    }

    impl Proposal {
        pub fn new(
            id: Id,
            target: Amount,
            proofs: Vec<super::proof::Proof>,
        ) -> Result<Proposal, Error> {
            let proof_total_amount = proofs.iter().map(|proof| proof.amount()).sum();

            if target > proof_total_amount {
                return Err(Error::InsufficientFunds);
            }

            let change = proof_total_amount - target;
            let target_secrets = PreMintSecrets::new(target);
            let change_secrets = PreMintSecrets::new(change);

            Ok(Proposal {
                id,
                amount: target,
                target_secrets,
                change_secrets,
                proofs,
            })
        }

        fn inner_proofs(&self) -> Vec<ecash::Proof> {
            self.proofs.iter().map(|p| p.inner()).cloned().collect()
        }

        pub fn sending_amount(&self) -> Amount {
            self.target_secrets.total_amount()
        }

        pub fn receiving_amount(&self) -> Amount {
            self.change_secrets.total_amount()
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Request {
        /// Amount fo value to split out of the Proofs
        pub amount: Amount,
        /// Messages for the mint to sign
        pub outputs: Vec<ecash::BlindedMessage>,
        /// Tokens spent to the mint to be reissued as the `outputs`
        pub proofs: ecash::Proofs,
    }

    impl Request {
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

    impl From<&Proposal> for Request {
        fn from(req: &Proposal) -> Self {
            let mut outputs =
                Vec::with_capacity(req.target_secrets.len() + req.change_secrets.len());
            outputs.extend(MintRequest::from(&req.target_secrets).outputs);
            outputs.extend(MintRequest::from(&req.change_secrets).outputs);

            Request {
                amount: req.amount,
                outputs,
                proofs: req.inner_proofs(),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("insufficient funds")]
    InsufficientFunds,
}

mod proof {
    use super::split;
    use crate::{ecash, Amount};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Id(u64);

    impl Id {
        pub fn new() -> Self {
            Self(rand::random())
        }
    }

    /// Current spend state a Proof
    #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum State {
        /// Proof has been minted by this wallet via blind signing
        #[default]
        Minted,
        /// Proof is spent in a pending split
        PendingSplit { id: split::Id },
        /// Proof is being added to wallet
        Receiving,
        /// Sent to aother user
        Sent { timestamp: u64 },
        /// Proof has been spent in a split
        Split { id: split::Id },
    }

    impl State {
        fn _is_spent(&self) -> bool {
            use State::*;

            match self {
                Minted => false,
                PendingSplit { .. } => false,
                Receiving => false,
                Sent { .. } => false,
                Split { .. } => true,
            }
        }

        fn is_pending_or_spent(&self) -> bool {
            use State::*;

            match self {
                Minted => false,
                PendingSplit { .. } => true,
                Receiving => true,
                Sent { .. } => true,
                Split { .. } => true,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Proof {
        id: Id,
        inner: ecash::Proof,
        state: State,
    }

    impl Proof {
        pub fn new(proof: super::ecash::Proof) -> Self {
            Self {
                id: Id::new(),
                inner: proof,
                state: State::Minted,
            }
        }

        pub fn received(proof: super::ecash::Proof) -> Self {
            Self {
                id: Id::new(),
                inner: proof,
                state: State::Receiving,
            }
        }

        pub fn id(&self) -> Id {
            self.id
        }

        pub fn amount(&self) -> Amount {
            self.inner.amount
        }

        pub fn inner(&self) -> &ecash::Proof {
            &self.inner
        }

        pub fn state(&self) -> State {
            self.state
        }

        pub fn is_unspent(&self) -> bool {
            !self.state.is_pending_or_spent()
        }

        pub fn set_unspent(&mut self) {
            self.state = State::Minted;
        }

        pub fn spend_pending_split(&mut self, id: split::Id) {
            self.state = State::PendingSplit { id };
        }

        pub fn spend_in_split(&mut self, id: split::Id) {
            self.state = State::Split { id };
        }

        pub fn set_spent(&mut self) {
            // TODO: Proper timestamp
            self.state = State::Sent { timestamp: 0 };
        }
    }

    impl From<ecash::Proof> for Proof {
        fn from(proof: ecash::Proof) -> Self {
            Proof {
                id: Id::new(),
                inner: proof,
                state: Default::default(),
            }
        }
    }
}
