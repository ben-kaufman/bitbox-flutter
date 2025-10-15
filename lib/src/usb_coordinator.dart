import 'dart:async';
import 'dart:typed_data';
import 'bitbox_flutter_platform.dart';
import 'bridge_generated.dart/api.dart' as api;

/// USB Coordinator for BitBox02 Communication
/// 
/// This coordinator manages the communication between Rust and Kotlin
/// by polling for USB data and coordinating the flow.
class UsbCoordinator {
  static final UsbCoordinator _instance = UsbCoordinator._internal();
  factory UsbCoordinator() => _instance;
  UsbCoordinator._internal();

  Timer? _pollTimer;
  bool _isRunning = false;
  String? _currentDevice;
  
  void start({String? deviceSerial}) {
    if (_isRunning) return;
    
    _isRunning = true;
    _currentDevice = deviceSerial;
    
    _pollTimer = Timer.periodic(const Duration(milliseconds: 200), (timer) {
      _pollForData();
    });
  }
  
  void stop() {
    _isRunning = false;
    _pollTimer?.cancel();
    _pollTimer = null;
  }
  
  Future<void> _pollForData() async {
    try {
      final writeData = await api.getUsbWriteDataWrapper(serialNumber: _currentDevice ?? '');
      if (writeData != null && writeData.isNotEmpty) {
        
        await BitBoxFlutterPlatform.sendData(Uint8List.fromList(writeData));

        {
          const int maxWaitMs = 60000;
          int waited = 0;
          while (waited < maxWaitMs) {
            final firstData = await BitBoxFlutterPlatform.receiveData();
            if (firstData.isNotEmpty) {
              api.setUsbReadDataWrapper(serialNumber: _currentDevice ?? '', data: firstData);
              break;
            }

            await Future.delayed(const Duration(milliseconds: 50));
            waited += 50;
          }
        }

        while (true) {
          final nextData = await BitBoxFlutterPlatform.receiveData();
          if (nextData.isEmpty) break;
          api.setUsbReadDataWrapper(serialNumber: _currentDevice ?? '', data: nextData);
          await Future.delayed(const Duration(milliseconds: 5));
        }

        return;
      }

      while (true) {
        final readData = await BitBoxFlutterPlatform.receiveData();
        if (readData.isEmpty) break;
        api.setUsbReadDataWrapper(serialNumber: _currentDevice ?? '', data: readData);
        await Future.delayed(const Duration(milliseconds: 5));
      }
    } catch (e) {
      // Ignore errors during polling
    }
  }
  
  Future<void> sendData(Uint8List data) async {
    await BitBoxFlutterPlatform.sendData(data);
  }
}
