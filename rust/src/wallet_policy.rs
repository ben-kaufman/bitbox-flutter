use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use bitbox_api::btc::{make_script_config_multisig, make_script_config_policy, KeyOriginInfo};
use bitbox_api::pb;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::NetworkKind;
use miniscript::descriptor::{DescriptorPublicKey, ShInner, Wildcard, WshInner};
use miniscript::{Descriptor, TranslatePk, Translator};

#[derive(Debug, Clone)]
struct AccountKey {
    root_fingerprint: Option<Fingerprint>,
    account_keypath: Option<DerivationPath>,
    xpub: Xpub,
}

impl AccountKey {
    fn to_key_origin_info(&self) -> KeyOriginInfo {
        KeyOriginInfo {
            root_fingerprint: self.root_fingerprint,
            keypath: self.account_keypath.as_ref().map(Into::into),
            xpub: self.xpub,
        }
    }
}

#[derive(Debug, Clone)]
enum ScriptTemplate {
    Multisig {
        threshold: u32,
        script_type: pb::btc_script_config::multisig::ScriptType,
    },
    Miniscript {
        policy: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedWalletPolicy {
    template: ScriptTemplate,
    keys: Vec<AccountKey>,
}

impl ParsedWalletPolicy {
    pub(crate) fn parse(descriptor: &str, expected_network: NetworkKind) -> Result<Self> {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor)
            .map_err(|error| anyhow!("invalid descriptor: {error}"))?;
        descriptor
            .sanity_check()
            .map_err(|error| anyhow!("invalid descriptor: {error}"))?;

        match &descriptor {
            Descriptor::Wsh(wsh) => match wsh.as_inner() {
                WshInner::SortedMulti(multisig) => Self::multisig(
                    multisig.k(),
                    multisig.pks(),
                    pb::btc_script_config::multisig::ScriptType::P2wsh,
                    expected_network,
                ),
                WshInner::Ms(_) => Self::miniscript(&descriptor, expected_network),
            },
            Descriptor::Sh(sh) => match sh.as_inner() {
                ShInner::Wsh(wsh) => match wsh.as_inner() {
                    WshInner::SortedMulti(multisig) => Self::multisig(
                        multisig.k(),
                        multisig.pks(),
                        pb::btc_script_config::multisig::ScriptType::P2wshP2sh,
                        expected_network,
                    ),
                    WshInner::Ms(_) => Err(anyhow!(
                        "BitBox supports only native or nested SegWit multisig and native SegWit Miniscript policies"
                    )),
                },
                _ => Err(anyhow!(
                    "BitBox supports only native or nested SegWit multisig and native SegWit Miniscript policies"
                )),
            },
            _ => Err(anyhow!(
                "BitBox supports only native or nested SegWit multisig and native SegWit Miniscript policies"
            )),
        }
    }

    pub(crate) fn device_candidate_keypaths(
        &self,
        fingerprint: Fingerprint,
    ) -> Vec<DerivationPath> {
        self.keys
            .iter()
            .filter_map(|key| {
                (key.root_fingerprint == Some(fingerprint))
                    .then(|| key.account_keypath.clone())
                    .flatten()
            })
            .collect()
    }

    pub(crate) fn matching_device_key_indices(
        &self,
        fingerprint: Fingerprint,
        device_xpubs: &HashMap<DerivationPath, Xpub>,
    ) -> Vec<usize> {
        self.keys
            .iter()
            .enumerate()
            .filter_map(|(index, key)| {
                let keypath = key.account_keypath.as_ref()?;
                let device_xpub = device_xpubs.get(keypath)?;
                (key.root_fingerprint == Some(fingerprint) && key.xpub == *device_xpub)
                    .then_some(index)
            })
            .collect()
    }

    pub(crate) fn prepare(&self, matching_key_indices: &[usize]) -> Result<PreparedWalletPolicy> {
        let primary_device_key_index = *matching_key_indices.first().ok_or_else(|| {
            anyhow!("the connected BitBox does not control a key in this descriptor")
        })?;
        let device_account_keypath = self.keys[primary_device_key_index]
            .account_keypath
            .clone()
            .ok_or_else(|| {
                anyhow!("the connected BitBox does not control a key in this descriptor")
            })?;

        match &self.template {
            ScriptTemplate::Multisig {
                threshold,
                script_type,
            } => {
                if matching_key_indices.len() != 1 {
                    bail!("the connected BitBox controls more than one key in this multisig descriptor");
                }
                let xpubs = self.keys.iter().map(|key| key.xpub).collect::<Vec<_>>();
                let script_config = make_script_config_multisig(
                    *threshold,
                    &xpubs,
                    primary_device_key_index as u32,
                    *script_type,
                );
                Ok(PreparedWalletPolicy {
                    script_config,
                    registration_keypath: Some(device_account_keypath.clone()),
                    device_account_keypath,
                })
            }
            ScriptTemplate::Miniscript { policy } => {
                // The policy contains all device-owned keys, while the API uses
                // one account keypath as its derivation anchor.
                let keys = self
                    .keys
                    .iter()
                    .map(AccountKey::to_key_origin_info)
                    .collect::<Vec<_>>();
                Ok(PreparedWalletPolicy {
                    script_config: make_script_config_policy(policy, &keys),
                    registration_keypath: None,
                    device_account_keypath,
                })
            }
        }
    }

    fn multisig(
        threshold: usize,
        descriptor_keys: &[DescriptorPublicKey],
        script_type: pb::btc_script_config::multisig::ScriptType,
        expected_network: NetworkKind,
    ) -> Result<Self> {
        let keys = descriptor_keys
            .iter()
            .map(|key| normalize_account_key(key, expected_network))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            template: ScriptTemplate::Multisig {
                threshold: threshold as u32,
                script_type,
            },
            keys,
        })
    }

    fn miniscript(
        descriptor: &Descriptor<DescriptorPublicKey>,
        expected_network: NetworkKind,
    ) -> Result<Self> {
        let mut translator = PolicyTranslator::new(expected_network);
        let translated = descriptor
            .translate_pk(&mut translator)
            .map_err(|error| match error {
                miniscript::TranslateErr::TranslatorErr(error) => error,
                miniscript::TranslateErr::OuterError(error) => {
                    anyhow!("invalid descriptor: {error}")
                }
            })?;
        Ok(Self {
            template: ScriptTemplate::Miniscript {
                policy: format!("{translated:#}"),
            },
            keys: translator.keys,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedWalletPolicy {
    pub(crate) script_config: pb::BtcScriptConfig,
    pub(crate) registration_keypath: Option<DerivationPath>,
    pub(crate) device_account_keypath: DerivationPath,
}

impl PreparedWalletPolicy {
    pub(crate) fn is_miniscript(&self) -> bool {
        matches!(
            self.script_config.config.as_ref(),
            Some(pb::btc_script_config::Config::Policy(_))
        )
    }

    pub(crate) fn script_config_with_keypath(&self) -> pb::BtcScriptConfigWithKeypath {
        pb::BtcScriptConfigWithKeypath {
            script_config: Some(self.script_config.clone()),
            keypath: bitbox_api::Keypath::from(&self.device_account_keypath).to_vec(),
        }
    }

    pub(crate) fn address_keypath(&self, branch: u32, index: u32) -> DerivationPath {
        self.device_account_keypath
            .into_iter()
            .cloned()
            .chain([
                ChildNumber::Normal { index: branch },
                ChildNumber::Normal { index },
            ])
            .collect()
    }

    pub(crate) fn has_standard_multisig_keypath(&self, testnet: bool) -> bool {
        let coin_type = if testnet { 1 } else { 0 };
        let script_type = match &self.script_config.config {
            Some(pb::btc_script_config::Config::Multisig(multisig)) => multisig.script_type,
            _ => return false,
        };
        let expected_script_type =
            if script_type == pb::btc_script_config::multisig::ScriptType::P2wsh as i32 {
                2
            } else if script_type == pb::btc_script_config::multisig::ScriptType::P2wshP2sh as i32 {
                1
            } else {
                return false;
            };
        matches!(
            self.device_account_keypath.as_ref(),
            [
                ChildNumber::Hardened { index: 48 },
                ChildNumber::Hardened { index },
                ChildNumber::Hardened { .. },
                ChildNumber::Hardened { index: script }
            ] if *index == coin_type && *script == expected_script_type
        )
    }
}

struct PolicyTranslator {
    expected_network: NetworkKind,
    key_indices: HashMap<DescriptorPublicKey, usize>,
    keys: Vec<AccountKey>,
}

impl PolicyTranslator {
    fn new(expected_network: NetworkKind) -> Self {
        Self {
            expected_network,
            key_indices: HashMap::new(),
            keys: Vec::new(),
        }
    }
}

impl Translator<DescriptorPublicKey, String, anyhow::Error> for PolicyTranslator {
    fn pk(&mut self, key: &DescriptorPublicKey) -> Result<String> {
        let index = match self.key_indices.get(key) {
            Some(index) => *index,
            None => {
                let index = self.keys.len();
                let account_key = normalize_account_key(key, self.expected_network)?;
                self.keys.push(account_key);
                self.key_indices.insert(key.clone(), index);
                index
            }
        };
        Ok(format!("@{index}/<0;1>/*"))
    }

    fn sha256(
        &mut self,
        hash: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Sha256,
    ) -> Result<String> {
        Ok(hash.to_string())
    }

    fn hash256(
        &mut self,
        hash: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Hash256,
    ) -> Result<String> {
        Ok(hash.to_string())
    }

    fn ripemd160(
        &mut self,
        hash: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Ripemd160,
    ) -> Result<String> {
        Ok(hash.to_string())
    }

    fn hash160(
        &mut self,
        hash: &<DescriptorPublicKey as miniscript::MiniscriptKey>::Hash160,
    ) -> Result<String> {
        Ok(hash.to_string())
    }
}

fn normalize_account_key(
    key: &DescriptorPublicKey,
    expected_network: NetworkKind,
) -> Result<AccountKey> {
    let descriptor_key = match key {
        DescriptorPublicKey::MultiXPub(key) => key,
        DescriptorPublicKey::Single(_) => {
            bail!("every descriptor key must be an extended public key")
        }
        DescriptorPublicKey::XPub(_) => {
            bail!("descriptor keys must use the canonical /<0;1>/* receive and change branches")
        }
    };
    if descriptor_key.xkey.network != expected_network {
        bail!("descriptor extended public key network does not match the selected Bitcoin network");
    }
    if descriptor_key.wildcard != Wildcard::Unhardened {
        bail!("descriptor keys must use the canonical /<0;1>/* receive and change branches");
    }

    let derivation_paths = descriptor_key.derivation_paths.paths();
    if derivation_paths.len() != 2 {
        bail!("descriptor keys must use the canonical /<0;1>/* receive and change branches");
    }
    let account_suffix = account_suffix(&derivation_paths[0], &derivation_paths[1])?;
    let secp = Secp256k1::verification_only();
    let xpub = descriptor_key
        .xkey
        .derive_pub(&secp, &account_suffix)
        .map_err(|_| {
            anyhow!("descriptor keys cannot use hardened derivation after the extended public key")
        })?;
    let (root_fingerprint, account_keypath) = match &descriptor_key.origin {
        Some((fingerprint, origin_path)) => (
            Some(*fingerprint),
            Some(
                origin_path
                    .into_iter()
                    .cloned()
                    .chain(account_suffix.into_iter().cloned())
                    .collect(),
            ),
        ),
        None => (None, None),
    };

    Ok(AccountKey {
        root_fingerprint,
        account_keypath,
        xpub,
    })
}

fn account_suffix(
    receive_path: &DerivationPath,
    change_path: &DerivationPath,
) -> Result<DerivationPath> {
    if receive_path.len() != change_path.len() || receive_path.is_empty() {
        bail!("descriptor keys must use the canonical /<0;1>/* receive and change branches");
    }
    let branch_index = receive_path.len() - 1;
    if receive_path[branch_index] != (ChildNumber::Normal { index: 0 })
        || change_path[branch_index] != (ChildNumber::Normal { index: 1 })
        || receive_path[..branch_index] != change_path[..branch_index]
    {
        bail!("descriptor keys must use the canonical /<0;1>/* receive and change branches");
    }
    Ok(receive_path[..branch_index].to_vec().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use bitcoin::Network;

    #[test]
    fn prepares_native_multisig_config_for_the_matching_device_key() {
        let first = test_account_key(1, "m/48'/1'/0'/2'");
        let second = test_account_key(2, "m/48'/1'/0'/2'");
        let descriptor = format!(
            "wsh(sortedmulti(2,{},{}))",
            first.descriptor, second.descriptor
        );
        let parsed = ParsedWalletPolicy::parse(&descriptor, NetworkKind::Test).unwrap();
        let device_xpubs = HashMap::from([(second.keypath.clone(), second.xpub)]);

        let matching_keys = parsed.matching_device_key_indices(second.fingerprint, &device_xpubs);
        let prepared = parsed.prepare(&matching_keys).unwrap();

        let multisig = match prepared.script_config.config.as_ref().unwrap() {
            pb::btc_script_config::Config::Multisig(multisig) => multisig,
            _ => panic!("expected native multisig configuration"),
        };
        assert_eq!(multisig.threshold, 2);
        assert_eq!(multisig.xpubs.len(), 2);
        assert_eq!(multisig.our_xpub_index, 1);
        assert_eq!(
            multisig.script_type,
            pb::btc_script_config::multisig::ScriptType::P2wsh as i32
        );
        assert_eq!(prepared.registration_keypath, Some(second.keypath));
    }

    #[test]
    fn prepares_nested_segwit_multisig_config() {
        let first = test_account_key(1, "m/48'/1'/0'/1'");
        let second = test_account_key(2, "m/48'/1'/0'/1'");
        let descriptor = format!(
            "sh(wsh(sortedmulti(2,{},{})))",
            first.descriptor, second.descriptor
        );
        let parsed = ParsedWalletPolicy::parse(&descriptor, NetworkKind::Test).unwrap();
        let device_xpubs = HashMap::from([(first.keypath.clone(), first.xpub)]);
        let matching_keys = parsed.matching_device_key_indices(first.fingerprint, &device_xpubs);

        let prepared = parsed.prepare(&matching_keys).unwrap();

        let multisig = match prepared.script_config.config.as_ref().unwrap() {
            pb::btc_script_config::Config::Multisig(multisig) => multisig,
            _ => panic!("expected native multisig configuration"),
        };
        assert_eq!(
            multisig.script_type,
            pb::btc_script_config::multisig::ScriptType::P2wshP2sh as i32
        );
    }

    #[test]
    fn prepares_miniscript_wallet_policy_with_key_origins() {
        let first = test_account_key(1, "m/48'/1'/0'/3'");
        let second = test_account_key(1, "m/48'/1'/1'/3'");
        let hash = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";
        let descriptor = format!(
            "wsh(or_d(pk({}),and_v(v:pk({}),and_v(v:older(20),sha256({hash})))))",
            first.descriptor, second.descriptor
        );
        let parsed = ParsedWalletPolicy::parse(&descriptor, NetworkKind::Test).unwrap();
        let device_xpubs = HashMap::from([
            (first.keypath.clone(), first.xpub),
            (second.keypath.clone(), second.xpub),
        ]);
        let matching_keys = parsed.matching_device_key_indices(first.fingerprint, &device_xpubs);

        let prepared = parsed.prepare(&matching_keys).unwrap();

        let policy = match prepared.script_config.config.as_ref().unwrap() {
            pb::btc_script_config::Config::Policy(policy) => policy,
            _ => panic!("expected wallet policy configuration"),
        };
        assert_eq!(
            policy.policy,
            format!(
                "wsh(or_d(pk(@0/<0;1>/*),and_v(v:pk(@1/<0;1>/*),and_v(v:older(20),sha256({hash})))))"
            )
        );
        assert_eq!(policy.keys.len(), 2);
        assert_eq!(matching_keys, vec![0, 1]);
        assert_eq!(prepared.registration_keypath, None);
        assert_eq!(
            prepared.address_keypath(1, 7),
            "m/48'/1'/0'/3'/1/7".parse().unwrap()
        );
    }

    #[test]
    fn matching_a_device_requires_its_exact_account_xpub() {
        let expected = test_account_key(1, "m/48'/1'/0'/2'");
        let other = test_account_key(2, "m/48'/1'/0'/2'");
        let descriptor = format!("wsh(sortedmulti(1,{}))", expected.descriptor);
        let parsed = ParsedWalletPolicy::parse(&descriptor, NetworkKind::Test).unwrap();
        let device_xpubs = HashMap::from([(expected.keypath, other.xpub)]);

        let matching_keys = parsed.matching_device_key_indices(expected.fingerprint, &device_xpubs);

        assert!(matching_keys.is_empty());
        assert_eq!(
            parsed.prepare(&matching_keys).unwrap_err().to_string(),
            "the connected BitBox does not control a key in this descriptor"
        );
    }

    #[test]
    fn rejects_descriptor_forms_bitbox_cannot_represent() {
        let key = test_account_key(1, "m/48'/1'/0'/3'");
        let nested_miniscript = format!("sh(wsh(pk({})))", key.descriptor);
        let fixed_key = format!("wsh(pk({}))", key.xpub.public_key);
        let hardened_suffix = format!(
            "wsh(pk({}))",
            key.descriptor.replace("/<0;1>/*", "/0'/<0;1>/*")
        );

        assert_eq!(
            ParsedWalletPolicy::parse(&nested_miniscript, NetworkKind::Test)
                .unwrap_err()
                .to_string(),
            "BitBox supports only native or nested SegWit multisig and native SegWit Miniscript policies"
        );
        assert_eq!(
            ParsedWalletPolicy::parse(&fixed_key, NetworkKind::Test)
                .unwrap_err()
                .to_string(),
            "every descriptor key must be an extended public key"
        );
        assert_eq!(
            ParsedWalletPolicy::parse(&format!("wsh(pk({}))", key.descriptor), NetworkKind::Main)
                .unwrap_err()
                .to_string(),
            "descriptor extended public key network does not match the selected Bitcoin network"
        );
        assert_eq!(
            ParsedWalletPolicy::parse(&hardened_suffix, NetworkKind::Test)
                .unwrap_err()
                .to_string(),
            "descriptor keys cannot use hardened derivation after the extended public key"
        );
    }

    struct TestAccountKey {
        descriptor: String,
        fingerprint: Fingerprint,
        keypath: DerivationPath,
        xpub: Xpub,
    }

    fn test_account_key(seed_byte: u8, keypath: &str) -> TestAccountKey {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Testnet, &[seed_byte; 32]).unwrap();
        let fingerprint = master.fingerprint(&secp);
        let keypath = keypath.parse::<DerivationPath>().unwrap();
        let account_xpriv = master.derive_priv(&secp, &keypath).unwrap();
        let xpub = Xpub::from_priv(&secp, &account_xpriv);
        TestAccountKey {
            descriptor: format!(
                "[{fingerprint}{}]{xpub}/<0;1>/*",
                path_without_master(&keypath)
            ),
            fingerprint,
            keypath,
            xpub,
        }
    }

    fn path_without_master(keypath: &DerivationPath) -> String {
        keypath
            .into_iter()
            .map(|child| format!("/{child}"))
            .collect()
    }
}
