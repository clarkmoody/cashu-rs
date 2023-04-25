use serde::{Deserialize, Serialize};

/// Number of satoshis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Amount(#[serde(with = "bitcoin::amount::serde::as_sat")] bitcoin::Amount);

impl Amount {
    pub const ZERO: Amount = Amount(bitcoin::Amount::ZERO);

    /// Split into parts that are powers of two
    pub fn split(&self) -> Vec<Amount> {
        let sats = self.0.to_sat();
        (0_u64..64)
            .into_iter()
            .rev()
            .filter_map(|bit| {
                let part = 1 << bit;
                ((sats & part) == part).then_some(Amount::from(part))
            })
            .collect()
    }
}

impl From<bitcoin::Amount> for Amount {
    fn from(value: bitcoin::Amount) -> Self {
        Self(value)
    }
}

impl From<Amount> for bitcoin::Amount {
    fn from(value: Amount) -> Self {
        value.0
    }
}

impl From<u64> for Amount {
    fn from(value: u64) -> Self {
        Self(bitcoin::Amount::from_sat(value))
    }
}

impl std::ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Amount) -> Self::Output {
        Amount(self.0 + rhs.0)
    }
}

impl std::ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        Amount(self.0 - rhs.0)
    }
}

impl core::iter::Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sats: u64 = iter.map(|amt| amt.0.to_sat()).sum();
        Amount::from(sats)
    }
}

#[cfg(test)]
mod test {
    use super::Amount;

    #[test]
    fn split() {
        let amount = Amount::from(13);
        let expected = vec![Amount::from(8), Amount::from(4), Amount::from(1)];
        assert_eq!(amount.split(), expected);

        let amount = Amount::from(u64::MAX);
        let expected = vec![
            Amount::from(1 << 63),
            Amount::from(1 << 62),
            Amount::from(1 << 61),
            Amount::from(1 << 60),
            Amount::from(1 << 59),
            Amount::from(1 << 58),
            Amount::from(1 << 57),
            Amount::from(1 << 56),
            Amount::from(1 << 55),
            Amount::from(1 << 54),
            Amount::from(1 << 53),
            Amount::from(1 << 52),
            Amount::from(1 << 51),
            Amount::from(1 << 50),
            Amount::from(1 << 49),
            Amount::from(1 << 48),
            Amount::from(1 << 47),
            Amount::from(1 << 46),
            Amount::from(1 << 45),
            Amount::from(1 << 44),
            Amount::from(1 << 43),
            Amount::from(1 << 42),
            Amount::from(1 << 41),
            Amount::from(1 << 40),
            Amount::from(1 << 39),
            Amount::from(1 << 38),
            Amount::from(1 << 37),
            Amount::from(1 << 36),
            Amount::from(1 << 35),
            Amount::from(1 << 34),
            Amount::from(1 << 33),
            Amount::from(1 << 32),
            Amount::from(1 << 31),
            Amount::from(1 << 30),
            Amount::from(1 << 29),
            Amount::from(1 << 28),
            Amount::from(1 << 27),
            Amount::from(1 << 26),
            Amount::from(1 << 25),
            Amount::from(1 << 24),
            Amount::from(1 << 23),
            Amount::from(1 << 22),
            Amount::from(1 << 21),
            Amount::from(1 << 20),
            Amount::from(1 << 19),
            Amount::from(1 << 18),
            Amount::from(1 << 17),
            Amount::from(1 << 16),
            Amount::from(1 << 15),
            Amount::from(1 << 14),
            Amount::from(1 << 13),
            Amount::from(1 << 12),
            Amount::from(1 << 11),
            Amount::from(1 << 10),
            Amount::from(1 << 9),
            Amount::from(1 << 8),
            Amount::from(1 << 7),
            Amount::from(1 << 6),
            Amount::from(1 << 5),
            Amount::from(1 << 4),
            Amount::from(1 << 3),
            Amount::from(1 << 2),
            Amount::from(1 << 1),
            Amount::from(1 << 0),
        ];
        assert_eq!(amount.split(), expected);
    }
}
