.PHONY: help install-deps codegen android build-android clean

help:
	@echo "Available commands:"
	@echo "  make codegen        - Generate flutter_rust_bridge bindings"
	@echo "  make android        - Codegen + build Rust .so for Android ABIs"
	@echo "  make build-android  - Build Rust .so for Android ABIs (no codegen)"
	@echo "  make clean          - Clean build artifacts"

codegen:
	flutter_rust_bridge_codegen generate

android: codegen build-android
	find android/src/main/jniLibs -type f -name "libbitbox_api*.so" -delete || true
	@echo "Android native libraries ready under android/src/main/jniLibs"

build-android:
	@echo "Building Rust library for Android..."
	@if [ -z "$$ANDROID_NDK_HOME" ]; then \
		echo "Error: ANDROID_NDK_HOME not set"; \
		echo "Please set it to your NDK path, e.g.:"; \
		echo "export ANDROID_NDK_HOME=$$HOME/Android/Sdk/ndk/25.1.8937393"; \
		exit 1; \
	fi
	cargo install cargo-ndk || true
	rm -rf android/src/main/jniLibs
	mkdir -p android/src/main/jniLibs
	cd rust && cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
		-o ../android/src/main/jniLibs build --release
	find android/src/main/jniLibs -type f -name "libbitbox_api*.so" -delete || true

clean:
	cd rust && cargo clean
	cd example && flutter clean
	flutter clean
	rm -rf android/src/main/jniLibs
	rm -rf lib/src/bridge_generated.*
	rm -rf rust/src/bridge_generated.*

install-deps:
	@echo "Installing dependencies..."
	cargo install flutter_rust_bridge_codegen --version 2.9.0 || true
	cargo install cargo-ndk || true
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android


