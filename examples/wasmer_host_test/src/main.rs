//! Wasmer WAI host test for libsodium
//!
//! This demonstrates calling the libsodium WAI interface from a Rust host.

use anyhow::Result;
use std::sync::Arc;
use wasmer::*;
use wasmer_wasix::{WasiEnv, WasiFunctionEnv};

// Import the WAI interface - this generates the `libsodium` module with bindings
wai_bindgen_wasmer::import!("../../wai/libsodium.wai");

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Wasmer WAI Host Test for libsodium ===\n");

    let wasm_path = std::env::args().nth(1).unwrap_or_else(|| {
        "target/wasm32-wasip1/release/examples/wasmer_wai_test.wasm".to_string()
    });

    println!("Loading WASM module: {}", wasm_path);
    let wasm_bytes = std::fs::read(&wasm_path)?;

    // Create store and module
    let mut store = Store::default();
    let module = Module::new(&store, &wasm_bytes)?;

    // Set up WASIX runtime
    let runtime = Arc::new(wasmer_wasix::runtime::PluggableRuntime::new(Arc::new(
        wasmer_wasix::runtime::task_manager::tokio::TokioTaskManager::new(
            tokio::runtime::Handle::current(),
        ),
    )));

    let mut builder = WasiEnv::builder("libsodium").runtime(runtime);
    builder.set_engine(store.engine().clone());
    let wasi_env = builder.build()?;
    let mut wasi_func_env = WasiFunctionEnv::new(&mut store, wasi_env);
    let mut wasi_imports = wasi_func_env.import_object(&mut store, &module)?;

    // Create the WAI bindings - instantiate merges WASI imports with WAI requirements
    let (libsodium, instance) = libsodium::Libsodium::instantiate(
        &mut store,
        &module,
        &mut wasi_imports,
    )?;

    // Initialize WASI with the instance
    wasi_func_env.initialize(&mut store, instance)?;

    // Test: Initialize
    println!("Testing init...");
    let result = libsodium.init(&mut store)?;
    println!("  init() = {} (0=success, 1=already init)", result);

    // Test: Version
    println!("\nTesting version...");
    let version = libsodium.version_string(&mut store)?;
    println!("  version_string() = {}", version);
    let major = libsodium.library_version_major(&mut store)?;
    let minor = libsodium.library_version_minor(&mut store)?;
    println!("  version: {}.{}", major, minor);

    // Test: Random
    println!("\nTesting random...");
    let r = libsodium.random_u32(&mut store)?;
    println!("  random_u32() = {}", r);
    let r = libsodium.random_uniform(&mut store, 100)?;
    println!("  random_uniform(100) = {}", r);
    let bytes = libsodium.random_bytes(&mut store, 16)?;
    print!("  random_bytes(16) = ");
    for b in &bytes {
        print!("{:02x}", b);
    }
    println!();

    // Test: SHA-256
    println!("\nTesting SHA-256...");
    let msg = b"Hello, libsodium WAI!";
    let hash = libsodium.sha256(&mut store, msg)?;
    print!("  sha256('Hello, libsodium WAI!') = ");
    for b in &hash {
        print!("{:02x}", b);
    }
    println!();

    // Test: Secretbox
    println!("\nTesting secretbox (XSalsa20-Poly1305)...");
    let key = libsodium.secretbox_keygen(&mut store)?;
    println!("  secretbox_keygen() = {} bytes", key.len());
    let nonce: Vec<u8> = libsodium.random_bytes(&mut store, 24)?;
    let plaintext = b"Secret message!";
    let ciphertext = libsodium.secretbox_easy(&mut store, plaintext, &nonce, &key)?;
    match ciphertext {
        Ok(ct) => {
            println!("  secretbox_easy() = {} bytes", ct.len());
            let decrypted = libsodium.secretbox_open_easy(&mut store, &ct, &nonce, &key)?;
            match decrypted {
                Ok(pt) => println!("  secretbox_open_easy() = '{}'", String::from_utf8_lossy(&pt)),
                Err(e) => println!("  decrypt error: {:?}", e),
            }
        }
        Err(e) => println!("  encrypt error: {:?}", e),
    }

    // Test: Box (public-key encryption)
    println!("\nTesting box (X25519-XSalsa20-Poly1305)...");
    let alice = libsodium.box_keypair(&mut store)?;
    let bob = libsodium.box_keypair(&mut store)?;
    println!("  Alice pk: {} bytes, Bob pk: {} bytes", alice.public_key.len(), bob.public_key.len());
    let nonce: Vec<u8> = libsodium.random_bytes(&mut store, 24)?;
    let msg = b"Hello Bob!";
    let ct = libsodium.box_easy(&mut store, msg, &nonce, &bob.public_key, &alice.secret_key)?;
    match ct {
        Ok(ct) => {
            println!("  box_easy() = {} bytes", ct.len());
            let pt = libsodium.box_open_easy(&mut store, &ct, &nonce, &alice.public_key, &bob.secret_key)?;
            match pt {
                Ok(pt) => println!("  box_open_easy() = '{}'", String::from_utf8_lossy(&pt)),
                Err(e) => println!("  decrypt error: {:?}", e),
            }
        }
        Err(e) => println!("  encrypt error: {:?}", e),
    }

    // Test: Sign (Ed25519)
    println!("\nTesting sign (Ed25519)...");
    let kp = libsodium.sign_keypair(&mut store)?;
    println!("  sign_keypair(): pk={} bytes, sk={} bytes", kp.public_key.len(), kp.secret_key.len());
    let msg = b"Message to sign";
    let sig = libsodium.sign_detached(&mut store, msg, &kp.secret_key)?;
    match sig {
        Ok(sig) => {
            println!("  sign_detached() = {} bytes", sig.len());
            let verify = libsodium.sign_verify_detached(&mut store, &sig, msg, &kp.public_key)?;
            match verify {
                Ok(()) => println!("  sign_verify_detached() = verified!"),
                Err(e) => println!("  verify error: {:?}", e),
            }
        }
        Err(e) => println!("  sign error: {:?}", e),
    }

    // Test: BLAKE2b
    println!("\nTesting generichash (BLAKE2b)...");
    let hash = libsodium.generichash(&mut store, b"test message", 32)?;
    match hash {
        Ok(h) => {
            print!("  generichash() = ");
            for b in &h {
                print!("{:02x}", b);
            }
            println!();
        }
        Err(e) => println!("  error: {:?}", e),
    }

    // Test: Utilities
    println!("\nTesting utilities...");
    let data = vec![0xde, 0xad, 0xbe, 0xef];
    let hex = libsodium.bin2hex(&mut store, &data)?;
    println!("  bin2hex([de,ad,be,ef]) = '{}'", hex);
    let decoded = libsodium.hex2bin(&mut store, &hex)?;
    match decoded {
        Ok(d) => println!("  hex2bin('{}') = {:02x?}", hex, d),
        Err(e) => println!("  error: {:?}", e),
    }
    let b64 = libsodium.bin2base64(&mut store, &data)?;
    println!("  bin2base64() = '{}'", b64);

    println!("\n=== All WAI tests passed! ===");
    Ok(())
}
