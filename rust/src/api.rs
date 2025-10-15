use anyhow::{anyhow, Result};
use bitbox_api::{NoiseConfigNoCache, PairedBitBox, PairingBitBox};
use flutter_rust_bridge::frb;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub use crate::usb_bridge::{get_usb_write_data, set_usb_read_data, PlatformUsbBridge};

#[frb(sync)]
pub fn get_usb_write_data_wrapper(serial_number: String) -> Option<Vec<u8>> {
    crate::usb_bridge::get_usb_write_data(serial_number)
}

#[frb(sync)]
pub fn set_usb_read_data_wrapper(serial_number: String, data: Vec<u8>) -> Result<()> {
    crate::usb_bridge::set_usb_read_data(serial_number, data)
}


const FIRMWARE_CMD: u8 = 0x80 + 0x40 + 0x01;

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub version: String,
    pub initialized: bool,
}

lazy_static! {
    static ref BITBOX_DEVICES: Arc<Mutex<HashMap<String, PairedBitBox<bitbox_api::runtime::TokioRuntime>>>> = 
        Arc::new(Mutex::new(HashMap::new()));
    static ref BITBOX_PAIRING_DEVICES: Arc<Mutex<HashMap<String, PairingBitBox<bitbox_api::runtime::TokioRuntime>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

#[frb]
pub async fn get_root_fingerprint(serial_number: String) -> Result<String> {
    let devices = BITBOX_DEVICES.lock().await;
    let bitbox = devices
        .get(&serial_number)
        .ok_or_else(|| anyhow!("Device not connected. Please perform handshake first."))?;
    
    let fingerprint = bitbox.root_fingerprint().await
        .map_err(|e| anyhow!("Failed to get root fingerprint: {:?}", e))?;
    
    Ok(fingerprint)
}

#[frb]
pub async fn get_device_info(serial_number: String) -> Result<DeviceInfo> {
    let devices = BITBOX_DEVICES.lock().await;
    let bitbox = devices
        .get(&serial_number)
        .ok_or_else(|| anyhow!("Device not connected"))?;
    
    let info = bitbox.device_info().await
        .map_err(|e| anyhow!("Failed to get device info: {:?}", e))?;
    
    Ok(DeviceInfo {
        name: info.name,
        version: bitbox.version().to_string(),
        initialized: info.initialized,
    })
}

#[frb]
pub async fn close_device(serial_number: String) -> Result<()> {
    let mut devices = BITBOX_DEVICES.lock().await;
    devices.remove(&serial_number);
    
    Ok(())
}

pub async fn close_usb_channel(serial_number: String) -> Result<()> {
    crate::usb_bridge::close_device(&serial_number).await;
    Ok(())
}

#[frb]
pub async fn start_pairing(serial_number: String) -> Result<Option<String>> {
    let usb_bridge = PlatformUsbBridge::new(serial_number.clone());
    let noise_config = NoiseConfigNoCache;

    let comm = Box::new(bitbox_api::communication::U2fHidCommunication::from(
        Box::new(usb_bridge),
        FIRMWARE_CMD,
    ));

    let bitbox = match bitbox_api::BitBox::<bitbox_api::runtime::TokioRuntime>::from(
        comm,
        Box::new(noise_config),
    ).await {
        Ok(bb) => bb,
        Err(_) => return Ok(None),
    };

    let pairing_bitbox = match bitbox.unlock_and_pair().await {
        Ok(pb) => pb,
        Err(_) => return Ok(None),
    };

    let pairing_code = pairing_bitbox.get_pairing_code();

    BITBOX_PAIRING_DEVICES.lock().await.insert(serial_number, pairing_bitbox);

    Ok(pairing_code)
}

#[frb]
pub async fn confirm_pairing(serial_number: String) -> Result<bool> {
    let mut pairing_map = BITBOX_PAIRING_DEVICES.lock().await;
    let pairing_bitbox = pairing_map.remove(&serial_number)
        .ok_or_else(|| anyhow!("No pending pairing for device"))?;

    let paired = pairing_bitbox.wait_confirm().await
        .map_err(|e| anyhow!("wait_confirm failed: {:?}", e))?;

    BITBOX_DEVICES.lock().await.insert(serial_number, paired);
    Ok(true)
}

#[frb]
pub async fn get_btc_xpub(serial_number: String, keypath: String, xpub_type: String) -> Result<String> {
    let devices = BITBOX_DEVICES.lock().await;
    let bitbox = devices.get(&serial_number)
        .ok_or_else(|| anyhow!("Device not paired"))?;

    let kp = bitbox_api::Keypath::try_from(keypath.as_str())
        .map_err(|e| anyhow!("Invalid keypath: {:?}", e))?;

    let xpub_ty = match xpub_type.to_lowercase().as_str() {
        "tpub" => bitbox_api::pb::btc_pub_request::XPubType::Tpub,
        "xpub" => bitbox_api::pb::btc_pub_request::XPubType::Xpub,
        _ => bitbox_api::pb::btc_pub_request::XPubType::Xpub,
    };

    let coin = match xpub_ty {
        bitbox_api::pb::btc_pub_request::XPubType::Tpub => bitbox_api::pb::BtcCoin::Tbtc,
        _ => bitbox_api::pb::BtcCoin::Btc,
    };

    let xpub = bitbox.btc_xpub(coin, &kp, xpub_ty, false).await
        .map_err(|e| anyhow!("Failed to get xpub: {:?}", e))?;

    Ok(xpub)
}

#[frb]
pub async fn verify_address(serial_number: String, keypath: String, testnet: bool, script_type: Option<String>) -> Result<String> {
    let devices = BITBOX_DEVICES.lock().await;
    let bitbox = devices.get(&serial_number)
        .ok_or_else(|| anyhow!("Device not paired"))?;

    let coin = if testnet { bitbox_api::pb::BtcCoin::Tbtc } else { bitbox_api::pb::BtcCoin::Btc };

    let simple_type = match script_type.as_deref().unwrap_or("p2wpkh").to_lowercase().as_str() {
        "p2wpkhp2sh" => bitbox_api::pb::btc_script_config::SimpleType::P2wpkhP2sh as i32,
        "p2wpkh" => bitbox_api::pb::btc_script_config::SimpleType::P2wpkh as i32,
        "p2tr" => bitbox_api::pb::btc_script_config::SimpleType::P2tr as i32,
        _ => bitbox_api::pb::btc_script_config::SimpleType::P2wpkh as i32,
    };
    let script_cfg = bitbox_api::pb::BtcScriptConfig {
        config: Some(bitbox_api::pb::btc_script_config::Config::SimpleType(simple_type)),
    };

    let kp = bitbox_api::Keypath::try_from(keypath.as_str())
        .map_err(|e| anyhow!("Invalid keypath: {:?}", e))?;
    let address = bitbox.btc_address(coin, &kp, &script_cfg, true).await
        .map_err(|e| anyhow!("Failed to display/verify address: {:?}", e))?;

    Ok(address)
}

#[frb]
pub async fn sign_psbt(serial_number: String, psbt_str: String, testnet: bool) -> Result<String> {
    use std::str::FromStr;

    let devices = BITBOX_DEVICES.lock().await;
    let bitbox = devices.get(&serial_number)
        .ok_or_else(|| anyhow!("Device not paired"))?;

    let coin = if testnet { bitbox_api::pb::BtcCoin::Tbtc } else { bitbox_api::pb::BtcCoin::Btc };

    let mut psbt = bitcoin::psbt::Psbt::from_str(psbt_str.trim())
        .map_err(|e| anyhow!("Invalid PSBT: {:?}", e))?;

    bitbox.btc_sign_psbt(coin, &mut psbt, None, bitbox_api::pb::btc_sign_init_request::FormatUnit::Default)
        .await
        .map_err(|e| anyhow!("Signing failed: {:?}", e))?;

    let out = psbt.to_string();
    Ok(out)
}
