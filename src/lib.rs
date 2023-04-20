use serde::{Deserialize, Serialize};

pub mod keyset;

/// Number of satoshis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Amount(#[serde(with = "bitcoin::amount::serde::as_sat")] bitcoin::Amount);
