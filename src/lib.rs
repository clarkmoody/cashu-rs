mod amount;
pub mod ecash;
pub mod keyset;
pub mod mint;
pub mod secret;
pub mod wallet;

pub use amount::Amount;

pub fn base64_url_safe_to_standard(s: &str) -> String {
    s.replace("_", "/").replace("-", "+")
}
