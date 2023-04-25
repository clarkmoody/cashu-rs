use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::keyset;
use crate::Amount;

/// An encrypted ("blinded") secret and an amount is sent from Alice to Bob
/// for minting tokens or for splitting tokens. A BlindedMessage is also
/// called an output.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlindedMessage {
    /// The value of the requested token
    amount: Amount,
    /// The encrypted secret message generated by Alice
    #[serde(rename = "B_")]
    b: PublicKey,
}

/// A signature on the [`BlindedMessage`] is sent from Bob to Alice after
/// minting tokens or after splitting tokens. A BlindedSignature is also
/// called a promise.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlindedSignature {
    /// The value of the blinded token
    amount: Amount,
    /// The blinded signature on the secret message `B_` sent in the
    /// previous step.
    #[serde(rename = "C_")]
    c: PublicKey,
    /// The keyset id of the mint public keys that signed the token.
    id: Option<keyset::Id>,
}

/// A Proof is sent to Bob for melting tokens. A Proof can also be sent from
/// Alice to Carol for which it is first can be serialized. Upon receiving the
/// token, Carol deserializes it and requests a split from Bob to receive new
/// tokens.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// The value of the Proof
    amount: Amount,
    /// The secret message
    secret: String,
    /// The unblinded signature on secret
    #[serde(rename = "C")]
    c: PublicKey,
    /// The keyset id of the mint public keys that signed the token
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<keyset::Id>,
    /// A P2SHScript that specifies the spending condition for this Proof
    #[serde(default, skip_serializing_if = "Option::is_none")]
    script: Option<String>, // TODO: P2SHScript
}

/// An list of Proofs. In general, this will be used for most
/// operations instead of a single Proof. Proofs must be serialized before
/// sending between wallets.
type Proofs = Vec<Proof>;

/// This token format has the `[version]` value A. Here, List[Proof] is identical to a V2 token.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Token {
    token: Vec<MintProofs>,
    memo: Option<String>,
}

/// Proofs associated with a mint
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct MintProofs {
    mint: String, // TODO: URI
    proofs: Proofs,
}

impl Token {
    const PREFIX: &str = "cashuA";

    pub fn encode(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE, Engine as _};

        // TODO: Error propagation
        let json = serde_json::to_string(&self).unwrap_or_else(|_| String::new());
        let b64 = URL_SAFE.encode(json);

        format!("cashuA{b64}")
    }

    // TODO: Result
    pub fn decode(encoded: &str) -> Option<Self> {
        use base64::{engine::general_purpose::URL_SAFE, Engine as _};

        if encoded.starts_with(Self::PREFIX) {
            let b64 = encoded.trim_start_matches("cashuA");
            let json = URL_SAFE.decode(&b64).ok()?;
            serde_json::from_slice(&json).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::Token;

    #[test]
    fn serialize_token() {
        // NUT-00 § 0.2.3
        let json = r#"
            {
              "token": [
                {
                  "mint": "https://8333.space:3338",
                  "proofs": [
                    {
                      "id": "DSAl9nvvyfva",
                      "amount": 2,
                      "secret": "EhpennC9qB3iFlW8FZ_pZw",
                      "C": "02c020067db727d586bc3183aecf97fcb800c3f4cc4759f69c626c9db5d8f5b5d4"
                    },
                    {
                      "id": "DSAl9nvvyfva",
                      "amount": 8,
                      "secret": "TmS6Cv0YT5PU_5ATVKnukw",
                      "C": "02ac910bef28cbe5d7325415d5c263026f15f9b967a079ca9779ab6e5c2db133a7"
                    }
                  ]
                }
              ],
              "memo": "Thankyou."
            }
        "#;
        let encoded = "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4IiwicHJvb2ZzIjpbeyJpZCI6IkRTQWw5bnZ2eWZ2YSIsImFtb3VudCI6Miwic2VjcmV0IjoiRWhwZW5uQzlxQjNpRmxXOEZaX3BadyIsIkMiOiIwMmMwMjAwNjdkYjcyN2Q1ODZiYzMxODNhZWNmOTdmY2I4MDBjM2Y0Y2M0NzU5ZjY5YzYyNmM5ZGI1ZDhmNWI1ZDQifSx7ImlkIjoiRFNBbDludnZ5ZnZhIiwiYW1vdW50Ijo4LCJzZWNyZXQiOiJUbVM2Q3YwWVQ1UFVfNUFUVktudWt3IiwiQyI6IjAyYWM5MTBiZWYyOGNiZTVkNzMyNTQxNWQ1YzI2MzAyNmYxNWY5Yjk2N2EwNzljYTk3NzlhYjZlNWMyZGIxMzNhNyJ9XX1dLCJtZW1vIjoiVGhhbmt5b3UuIn0=";

        // Decode JSON
        let token_from_json: Token = serde_json::from_str(json).expect("decode JSON");
        // Decode Base64
        let token_from_encoded = Token::decode(encoded).expect("decode Base64");
        // Check that decoded tokens are identical
        assert_eq!(token_from_json, token_from_encoded);

        // Check round-trip
        assert_eq!(
            Token::decode(&token_from_json.encode()).expect("re-decode"),
            token_from_encoded
        );
    }
}