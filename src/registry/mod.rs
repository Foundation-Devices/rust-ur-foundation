// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! UR registry.

pub mod passport;

use core::num::NonZeroU32;
use ur::registry::crypto_hdkey::{
    BaseHDKey, CoinType, CryptoCoinInfo, CryptoKeypath, DerivedKey, PathComponent,
};

pub fn casa_export<C>(
    public_key: [u8; 33],
    chain_code: [u8; 32],
    fingerprint: NonZeroU32,
) -> BaseHDKey<'static, C>
where
    C: ur::collections::Vec<PathComponent>,
{
    let use_info = CryptoCoinInfo::new(CoinType::BTC, 0);
    let origin = CryptoKeypath::new_master(fingerprint);

    let derived_key = DerivedKey {
        is_private: false,
        key_data: public_key,
        chain_code: Some(chain_code),
        use_info: Some(use_info),
        origin: Some(origin),
        children: None,
        parent_fingerprint: None,
        name: None,
        note: None,
    };

    BaseHDKey::DerivedKey(derived_key)
}
