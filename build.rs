#[cfg(not(windows))]
extern crate cc;

#[cfg(windows)]
extern crate libc;
#[cfg(windows)]
extern crate vcpkg;
#[cfg(windows)]
extern crate zip;

extern crate libflate;
extern crate minisign_verify;
extern crate pkg_config;
extern crate tar;
#[cfg(any(windows, feature = "fetch-latest"))]
extern crate ureq;

use std::{
    env,
    path::{Path, PathBuf},
};

/// Cargo compiles build.rs with the HOST cfg, instead of the TARGET cfg.
/// So we cannot use build-time `#[cfg(..)]`, and instead must query
/// the runtime environment variables set by cargo.
struct Target {
    pub target: String,
    pub is_msvc: bool,

    #[cfg(windows)]
    pub is_release: bool,
    #[cfg(windows)]
    pub is_64: bool,
}

impl Default for Target {
    fn default() -> Self {
        // Determine build target triple
        let mut target = env::var("TARGET").unwrap();
        // Hack for RISC-V; Rust apparently uses a different convention for RISC-V triples
        if target.starts_with("riscv") {
            let mut split = target.split('-');
            let arch = split.next().unwrap();
            let bitness = &arch[5..7];
            let rest = split.collect::<Vec<_>>().join("-");
            target = format!("riscv{bitness}-{rest}");
        }

        Self {
            target,
            is_msvc: std::env::var("CARGO_CFG_TARGET_ENV").unwrap() == "msvc",

            #[cfg(windows)]
            is_release: env::var("PROFILE").unwrap() == "release",
            #[cfg(windows)]
            is_64: std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64",
        }
    }
}

fn main() {
    let tgt = Target::default();

    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_SHARED");
    println!("cargo:rerun-if-env-changed=SODIUM_USE_PKG_CONFIG");

    if tgt.is_msvc {
        // vcpkg requires to set env VCPKGRS_DYNAMIC
        println!("cargo:rerun-if-env-changed=VCPKGRS_DYNAMIC");
    }
    if cfg!(not(windows)) {
        println!("cargo:rerun-if-env-changed=SODIUM_DISABLE_PIE");
    }

    if env::var("SODIUM_STATIC").is_ok() {
        panic!("SODIUM_STATIC is deprecated. Use SODIUM_SHARED instead.");
    }

    let lib_dir_isset = env::var("SODIUM_LIB_DIR").is_ok();
    let use_pkg_isset = if cfg!(feature = "use-pkg-config") {
        true
    } else {
        env::var("SODIUM_USE_PKG_CONFIG").is_ok()
    };
    let shared_isset = env::var("SODIUM_SHARED").is_ok();

    if lib_dir_isset && use_pkg_isset {
        panic!("SODIUM_LIB_DIR is incompatible with SODIUM_USE_PKG_CONFIG. Set the only one env variable");
    }

    if lib_dir_isset {
        find_libsodium_env(&tgt);
    } else if use_pkg_isset {
        if shared_isset {
            println!("cargo:warning=SODIUM_SHARED has no effect with SODIUM_USE_PKG_CONFIG");
        }

        find_libsodium_pkg(&tgt);
    } else {
        if shared_isset {
            println!(
                "cargo:warning=SODIUM_SHARED has no effect for building libsodium from source"
            );
        }

        build_libsodium(&tgt);
    }
}

/* Must be called when SODIUM_LIB_DIR is set to any value
This function will set `cargo` flags.
*/
fn find_libsodium_env(tgt: &Target) {
    let lib_dir = env::var("SODIUM_LIB_DIR").unwrap(); // cannot fail

    println!("cargo:rustc-link-search=native={lib_dir}");
    let mode = if env::var("SODIUM_SHARED").is_ok() {
        "dylib"
    } else {
        "static"
    };
    let name = if tgt.is_msvc { "libsodium" } else { "sodium" };
    println!("cargo:rustc-link-lib={mode}={name}");
    println!("cargo:warning=Using unknown libsodium version.");
}

/* Must be called when no SODIUM_USE_PKG_CONFIG env var is set
This function will set `cargo` flags.
*/
fn find_libsodium_pkg(tgt: &Target) {
    #[cfg(windows)]
    {
        if tgt.is_msvc {
            match vcpkg::probe_package("libsodium") {
                Ok(lib) => {
                    println!("cargo:warning=Using unknown libsodium version");
                    for lib_dir in &lib.link_paths {
                        println!("cargo:lib={}", lib_dir.to_str().unwrap());
                    }
                    for include_dir in &lib.include_paths {
                        println!("cargo:include={}", include_dir.to_str().unwrap());
                    }
                }
                Err(e) => {
                    panic!("Error: {:?}", e);
                }
            };
            return;
        }
    }

    let _tgt = tgt;

    match pkg_config::Config::new().probe("libsodium") {
        Ok(lib) => {
            for lib_dir in &lib.link_paths {
                println!("cargo:lib={}", lib_dir.to_str().unwrap());
            }
            for include_dir in &lib.include_paths {
                println!("cargo:include={}", include_dir.to_str().unwrap());
            }
        }
        Err(e) => {
            panic!("Error: {:?}", e);
        }
    }
}

#[cfg(windows)]
fn make_libsodium(tgt: &Target, _: &Path, install_dir: &Path) -> PathBuf {
    if tgt.is_msvc {
        // We don't build anything on windows, we simply link to precompiled libs.
        use zip::read::ZipArchive;

        // Determine filename for pre-built MSVC binaries
        let basename = "libsodium-1.0.18-stable-msvc";
        let filename = format!("{}.zip", basename);
        let signature_filename = format!("{}.zip.minisig", basename);

        // Read binaries archive from disk (or download if requested) & verify signature
        let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename);

        // Unpack the zip
        let mut archive = ZipArchive::new(std::io::Cursor::new(archive_bin)).unwrap();
        archive.extract(&install_dir).unwrap();

        get_lib_dir(tgt, install_dir)
    } else {
        // We don't build anything on windows, we simply link to precompiled libs.
        use libflate::gzip::Decoder;
        use tar::Archive;

        // Determine filename for pre-built MinGW binaries
        let basename = "libsodium-1.0.18-stable-mingw";
        let filename = format!("{}.tar.gz", basename);
        let signature_filename = format!("{}.tar.gz.minisig", basename);

        // Read binaries archive from disk (or download if requested) & verify signature
        let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename);

        // Unpack the tarball
        let gz_decoder = Decoder::new(std::io::Cursor::new(archive_bin)).unwrap();
        let mut archive = Archive::new(gz_decoder);
        archive.unpack(&install_dir).unwrap();

        get_lib_dir(tgt, install_dir)
    }
}

#[cfg(not(windows))]
fn make_libsodium(tgt: &Target, source_dir: &Path, install_dir: &Path) -> PathBuf {
    use std::{fs, process::Command, str};

    // Decide on CC, CFLAGS and the --host configure argument
    let build_compiler = cc::Build::new().get_compiler();
    let mut compiler = build_compiler.path().to_str().unwrap().to_string();
    let mut cflags = build_compiler.cflags_env().into_string().unwrap();
    let ldflags = env::var("SODIUM_LDFLAGS").unwrap_or_default();
    let host_arg;
    let cross_compiling;
    let help;
    let mut configure_extra = vec![];

    if tgt.target.contains("-wasi") {
        cross_compiling = true;
        compiler = "zig cc --target=wasm32-wasi".to_string();
        host_arg = "--host=wasm32-wasi".to_string();
        configure_extra.push("--disable-ssp");
        configure_extra.push("--without-pthreads");
        env::set_var("AR", "zig ar");
        env::set_var("RANLIB", "zig ranlib");
        help = "The Zig SDK needs to be installed in order to cross-compile to WebAssembly\n";
    } else if tgt.target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_select_output = Command::new("xcode-select").arg("-p").output().unwrap();
        if !xcode_select_output.status.success() {
            panic!("Failed to run xcode-select -p");
        }
        let xcode_dir = str::from_utf8(&xcode_select_output.stdout)
            .unwrap()
            .trim()
            .to_string();

        // Determine SDK directory paths
        let sdk_dir_simulator = Path::new(&xcode_dir)
            .join("Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk")
            .to_str()
            .unwrap()
            .to_string();
        let sdk_dir_ios = Path::new(&xcode_dir)
            .join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk")
            .to_str()
            .unwrap()
            .to_string();

        // Min versions
        let ios_simulator_version_min = "6.0.0";
        let ios_version_min = "6.0.0";

        // Roughly based on `dist-build/ios.sh` in the libsodium sources
        match tgt.target.as_str() {
            "aarch64-apple-ios" => {
                cflags += " -arch arm64";
                cflags += &format!(" -isysroot {sdk_dir_ios}");
                cflags += &format!(" -mios-version-min={ios_version_min}");
                cflags += " -fembed-bitcode";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7-apple-ios" => {
                cflags += " -arch armv7";
                cflags += &format!(" -isysroot {sdk_dir_ios}");
                cflags += &format!(" -mios-version-min={ios_version_min}");
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "armv7s-apple-ios" => {
                cflags += " -arch armv7s";
                cflags += &format!(" -isysroot {sdk_dir_ios}");
                cflags += &format!(" -mios-version-min={ios_version_min}");
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin10".to_string();
            }
            "i386-apple-ios" => {
                cflags += " -arch i386";
                cflags += &format!(" -isysroot {sdk_dir_simulator}");
                cflags += &format!(" -mios-simulator-version-min={ios_simulator_version_min}");
                host_arg = "--host=i686-apple-darwin10".to_string();
            }
            "x86_64-apple-ios" => {
                cflags += " -arch x86_64";
                cflags += &format!(" -isysroot {sdk_dir_simulator}");
                cflags += &format!(" -mios-simulator-version-min={ios_simulator_version_min}");
                host_arg = "--host=x86_64-apple-darwin10".to_string();
            }
            _ => panic!("Unknown iOS build target: {}", tgt.target),
        }
        cross_compiling = true;
        help = "";
    } else {
        if tgt.target.contains("i686") {
            compiler += " -m32 -maes";
            cflags += " -march=i686";
        }
        let host = env::var("HOST").unwrap();
        host_arg = format!("--host={}", tgt.target);
        cross_compiling = tgt.target != host;
        help = if cross_compiling {
            "***********************************************************\n\
             Possible missing dependencies.\n\
             See https://github.com/sodiumoxide/sodiumoxide#cross-compiling\n\
             ***********************************************************\n\n"
        } else {
            ""
        };
    }

    // Run `./configure`
    let prefix_arg = format!("--prefix={}", install_dir.to_str().unwrap());
    let mut configure_cmd = Command::new(fs::canonicalize(source_dir.join("configure")).unwrap());
    if !compiler.is_empty() {
        configure_cmd.env("CC", &compiler);
    }
    if !cflags.is_empty() {
        configure_cmd.env("CFLAGS", &cflags);
    }
    if !ldflags.is_empty() {
        configure_cmd.env("LDFLAGS", &ldflags);
    }
    if env::var("SODIUM_DISABLE_PIE").is_ok() {
        configure_cmd.arg("--disable-pie");
    }
    #[cfg(feature = "optimized")]
    configure_cmd.arg("--enable-opt");
    #[cfg(feature = "minimal")]
    configure_cmd.arg("--enable-minimal");
    let configure_output = configure_cmd
        .current_dir(source_dir)
        .arg(&prefix_arg)
        .arg(&host_arg)
        .args(configure_extra)
        .arg("--enable-shared=no")
        .arg("--disable-dependency-tracking")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run './configure': {}\n{}", error, help);
        });
    if !configure_output.status.success() {
        panic!(
            "\n{:?}\nCFLAGS={}\nLDFLAGS={}\nCC={}\n{}\n{}\n{}\n",
            configure_cmd,
            cflags,
            ldflags,
            compiler,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&configure_output.stderr),
            help
        );
    }

    // Run `make check`, or `make all` if we're cross-compiling
    let j_arg = format!("-j{}", env::var("NUM_JOBS").unwrap());
    let make_arg = if cross_compiling { "all" } else { "check" };
    let mut make_cmd = Command::new("make");
    let make_output = make_cmd
        .current_dir(source_dir)
        .env("V", "1")
        .arg(make_arg)
        .arg(&j_arg)
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make {}': {}\n{}", make_arg, error, help);
        });
    if !make_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n{}\n{}",
            make_cmd,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&make_output.stdout),
            String::from_utf8_lossy(&make_output.stderr),
            help
        );
    }

    // Run `make install`
    let mut install_cmd = Command::new("make");
    let install_output = install_cmd
        .current_dir(source_dir)
        .arg("install")
        .output()
        .unwrap_or_else(|error| {
            panic!("Failed to run 'make install': {}", error);
        });
    if !install_output.status.success() {
        panic!(
            "\n{:?}\n{}\n{}\n{}\n{}\n",
            install_cmd,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&make_output.stdout),
            String::from_utf8_lossy(&install_output.stdout),
            String::from_utf8_lossy(&install_output.stderr)
        );
    }

    install_dir.join("lib")
}

#[cfg(windows)]
fn get_lib_dir(tgt: &Target, install_dir: &Path) -> PathBuf {
    match (tgt.is_msvc, tgt.is_64, tgt.is_release) {
        (true, true, true) => install_dir.join("libsodium\\x64\\Release\\v143\\static\\"),
        (true, true, false) => install_dir.join("libsodium\\x64\\Debug\\v143\\static\\"),
        (true, false, true) => install_dir.join("libsodium\\Win32\\Release\\v143\\static\\"),
        (true, false, false) => install_dir.join("libsodium\\Win32\\Debug\\v143\\static\\"),
        (false, true, _) => install_dir.join("libsodium-win64\\lib\\"),
        (false, false, _) => install_dir.join("libsodium-win32\\lib\\"),
    }
}

fn get_install_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("installed")
}

fn retrieve_and_verify_archive(filename: &str, signature_filename: &str) -> Vec<u8> {
    use minisign_verify::{PublicKey, Signature};
    use std::fs::File;
    use std::io::prelude::*;

    let pk =
        PublicKey::from_base64("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3").unwrap();

    let mut archive_bin = vec![];

    #[cfg(any(windows, feature = "fetch-latest"))]
    {
        let baseurl = "https://download.libsodium.org/libsodium/releases";
        let response = ureq::get(&format!("{}/{}", baseurl, filename)).call();
        response
            .unwrap()
            .into_reader()
            .read_to_end(&mut archive_bin)
            .unwrap();
        File::create(&filename)
            .unwrap()
            .write_all(&archive_bin)
            .unwrap();

        let response = ureq::get(&format!("{}/{}", baseurl, signature_filename)).call();
        let mut signature_bin = vec![];
        response
            .unwrap()
            .into_reader()
            .read_to_end(&mut signature_bin)
            .unwrap();
        File::create(&signature_filename)
            .unwrap()
            .write_all(&signature_bin)
            .unwrap();
    }

    #[cfg(not(any(windows, feature = "fetch-latest")))]
    {
        File::open(filename)
            .unwrap()
            .read_to_end(&mut archive_bin)
            .unwrap();
    }

    let signature = Signature::from_file(signature_filename).unwrap();

    pk.verify(&archive_bin, &signature, false)
        .expect("Invalid signature");

    archive_bin
}

fn build_libsodium(tgt: &Target) {
    use libflate::gzip::Decoder;
    use std::fs;
    use tar::Archive;

    // Determine filenames
    let basedir = "libsodium-stable";
    let basename = "LATEST";
    let filename = format!("{basename}.tar.gz");
    let signature_filename = format!("{basename}.tar.gz.minisig");

    // Read source archive from disk (or download if requested) & verify signature
    let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename);

    // Determine source and install dir
    let mut install_dir = get_install_dir();
    let mut source_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("source");

    // Avoid issues with paths containing spaces by falling back to using a tempfile.
    // See https://github.com/jedisct1/libsodium/issues/207
    if install_dir.to_str().unwrap().contains(' ') {
        let fallback_path = PathBuf::from("/tmp/").join(basename).join(&tgt.target);
        install_dir = fallback_path.join("installed");
        source_dir = fallback_path.join("/source");
        println!(
            "cargo:warning=The path to the usual build directory contains spaces and hence \
             can't be used to build libsodium.  Falling back to use {}.  If running `cargo \
             clean`, ensure you also delete this fallback directory",
            fallback_path.to_str().unwrap()
        );
    }

    // Create directories
    fs::create_dir_all(&install_dir).unwrap();
    fs::create_dir_all(&source_dir).unwrap();

    // Unpack the tarball
    let gz_decoder = Decoder::new(std::io::Cursor::new(archive_bin)).unwrap();
    let mut archive = Archive::new(gz_decoder);
    archive.unpack(&source_dir).unwrap();
    source_dir.push(basedir);

    let lib_dir = make_libsodium(tgt, &source_dir, &install_dir);

    if tgt.is_msvc {
        println!("cargo:rustc-link-lib=static=libsodium");
    } else {
        println!("cargo:rustc-link-lib=static=sodium");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir.to_str().unwrap()
    );

    let include_dir = source_dir.join("src/libsodium/include");

    println!("cargo:include={}", include_dir.to_str().unwrap());
    println!("cargo:lib={}", lib_dir.to_str().unwrap());
}
