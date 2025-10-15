import 'rust/api.dart' as api;
import 'rust/frb_generated.dart';
import 'bitbox_flutter_platform.dart';
import 'usb_coordinator.dart';

class BitBoxFlutterApi {
  static bool _initialized = false;

  static Future<void> initialize() async {
    if (_initialized) {
      return;
    }

    await RustLib.init();
    _initialized = true;
  }

  static Future<List<BitBox02Device>> scanDevices() async {
    _ensureInitialized();
    return await BitBoxFlutterPlatform.scanDevices();
  }

  static Future<bool> requestPermission(String deviceName) async {
    _ensureInitialized();
    return await BitBoxFlutterPlatform.requestPermission(deviceName);
  }

  static Future<bool> openDevice(String deviceName, String serialNumber) async {
    _ensureInitialized();

    final opened = await BitBoxFlutterPlatform.openDevice(deviceName);
    if (!opened) {
      return false;
    }

    UsbCoordinator().start(deviceSerial: serialNumber);

    return true;
  }

  static Future<String?> startPairing(String serialNumber) async {
    _ensureInitialized();
    return await api.startPairing(serialNumber: serialNumber);
  }

  static Future<bool> confirmPairing(String serialNumber) async {
    _ensureInitialized();
    return await api.confirmPairing(serialNumber: serialNumber);
  }

  static Future<String> getRootFingerprint(String serialNumber) async {
    _ensureInitialized();
    return await api.getRootFingerprint(serialNumber: serialNumber);
  }

  static Future<String> getBtcXpub({
    required String serialNumber,
    required String keypath,
    String xpubType = 'xpub',
  }) async {
    _ensureInitialized();
    final res = await api.getBtcXpub(
      serialNumber: serialNumber,
      keypath: keypath,
      xpubType: xpubType,
    );
    return res;
  }

  static Future<String> verifyAddress({
    required String serialNumber,
    required String keypath,
    bool testnet = false,
    String scriptType = 'p2wpkh',
  }) async {
    _ensureInitialized();
    return await api.verifyAddress(
      serialNumber: serialNumber,
      keypath: keypath,
      testnet: testnet,
      scriptType: scriptType,
    );
  }

  static Future<String> signPsbt({
    required String serialNumber,
    required String psbt,
    bool testnet = false,
  }) async {
    _ensureInitialized();
    return await api.signPsbt(
      serialNumber: serialNumber,
      psbtStr: psbt,
      testnet: testnet,
    );
  }

  static Future<void> closeDevice(String serialNumber) async {
    _ensureInitialized();

    UsbCoordinator().stop();

    await api.closeUsbChannel(serialNumber: serialNumber);

    await api.closeDevice(serialNumber: serialNumber);

    await BitBoxFlutterPlatform.closeDevice();
  }

  static void _ensureInitialized() {
    if (!_initialized) {
      throw StateError('BitBoxFlutterApi not initialized. Call initialize() first.');
    }
  }
}
