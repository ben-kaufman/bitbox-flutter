# bitbox_flutter

Flutter bindings for the BitBox02 hardware wallet using Rust and flutter_rust_bridge.

## Features

- Connect to BitBox02 hardware wallet on Android
- Perform device handshake
- Get root fingerprint
- Full Rust-powered crypto operations

## Prerequisites

### macOS/Linux
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Install flutter_rust_bridge codegen
cargo install flutter_rust_bridge_codegen --version 2.9.0

# Install LLVM (for macOS with Homebrew)
brew install llvm

# Install LLVM (for Ubuntu/Debian)
sudo apt-get install libclang-dev llvm-dev
```

## Setup

1. Clone the repository
2. Install toolchain dependencies (one-time):
```bash
make install-deps
```
3. Generate bindings and build Android native libraries:
```bash
make android
```
4. Run the example app:
```bash
cd example
flutter run
```

## Usage

```dart
import 'package:bitbox_flutter/bitbox_flutter.dart';

// Initialize
await BitBoxFlutterApi.initialize();

// Scan for devices
final devices = await BitBoxFlutterApi.scanDevices();

// Request USB permission
await BitBoxFlutterApi.requestPermission(devices.first.deviceName);

// Open device (and start coordinator)
await BitBoxFlutterApi.openDevice(
  devices.first.deviceName,
  devices.first.serialNumber,
);

// Start pairing (returns pairing code if needed)
final pairingCode = await BitBoxFlutterApi.startPairing(
  devices.first.serialNumber,
);
// Optionally display pairingCode to the user if not null

// Confirm pairing on the device
final confirmed = await BitBoxFlutterApi.confirmPairing(
  devices.first.serialNumber,
);

// Get root fingerprint
final fingerprint = await BitBoxFlutterApi.getRootFingerprint(devices.first.serialNumber);
```

## Building for Production

### Android

1. Build release version of Rust library:
```bash
cargo ndk -t arm64-v8a -t armeabi-v7a -o android/src/main/jniLibs build --release
```

2. Build Flutter app:
```bash
flutter build apk --release
```

## License

Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

