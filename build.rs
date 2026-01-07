use std::{
    env,
    path::{Path, PathBuf},
};

struct Target {
    name: String,
    is_release: bool,
}

impl Target {
    fn get() -> Self {
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
            name: target,
            is_release: env::var("PROFILE").unwrap() == "release",
        }
    }
}

// When SODIUM_LIB_DIR has been set, add the directory to the Rust compiler search path
fn find_libsodium_env() {
    let lib_dir = env::var("SODIUM_LIB_DIR").unwrap(); // cannot fail

    println!("cargo:rustc-link-search=native={lib_dir}");
    let mode = if env::var("SODIUM_SHARED").is_ok() {
        "dylib"
    } else {
        "static"
    };
    let name = if cfg!(target_env = "msvc") {
        "libsodium"
    } else {
        "sodium"
    };
    println!("cargo:rustc-link-lib={mode}={name}");
    println!("cargo:warning=Using unknown libsodium version.");
}

// Try to find a system install of libsodium using vcpkg; return false if not found.
// Otherwise, adjust compiler flags and return true.
fn find_libsodium_vpkg() -> bool {
    match vcpkg::probe_package("libsodium") {
        Ok(lib) => {
            println!("cargo:warning=Using unknown libsodium version");
            for lib_dir in &lib.link_paths {
                println!("cargo:lib={}", lib_dir.to_str().unwrap());
            }
            for include_dir in &lib.include_paths {
                println!("cargo:include={}", include_dir.to_str().unwrap());
            }
            true
        }
        Err(_) => false,
    }
}

// Try to find a system install of libsodium using pkg-config; return false if not found.
// Otherwise, adjust compiler flags and return true.
fn find_libsodium_pkgconfig() -> bool {
    match pkg_config::Config::new().probe("libsodium") {
        Ok(lib) => {
            for lib_dir in &lib.link_paths {
                println!("cargo:lib={}", lib_dir.to_str().unwrap());
            }
            for include_dir in &lib.include_paths {
                println!("cargo:include={}", include_dir.to_str().unwrap());
            }
            true
        }
        Err(_) => false,
    }
}

// Extract precompiled MSVC binaries from a zip archive
fn extract_libsodium_precompiled_msvc(_: &str, _: &Path, install_dir: &Path) -> PathBuf {
    use zip::read::ZipArchive;

    // Determine filename for pre-built MSVC binaries
    let basename = "libsodium-1.0.21-stable-msvc";
    let filename = format!("{}.zip", basename);
    let signature_filename = format!("{}.zip.minisig", basename);

    // Read binaries archive from disk (or download if requested) & verify signature
    let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename);

    // Unpack the zip
    let mut archive = ZipArchive::new(std::io::Cursor::new(archive_bin)).unwrap();
    archive.extract(install_dir).unwrap();

    match Target::get().name.as_str() {
        "i686-pc-windows-msvc" => get_precompiled_lib_dir_msvc_win32(install_dir),
        "x86_64-pc-windows-msvc" => get_precompiled_lib_dir_msvc_x64(install_dir),
        "aarch64-pc-windows-msvc" => get_precompiled_lib_dir_msvc_arm64(install_dir),
        _ => panic!("Unsupported target"),
    }
}

// Extract precompiled MinGW binaries from a tarball
fn extract_libsodium_precompiled_mingw(_: &str, _: &Path, install_dir: &Path) -> PathBuf {
    use libflate::gzip::Decoder;
    use tar::Archive;

    // Determine filename for pre-built MinGW binaries
    let basename = "libsodium-1.0.21-stable-mingw";
    let filename = format!("{}.tar.gz", basename);
    let signature_filename = format!("{}.tar.gz.minisig", basename);

    // Read binaries archive from disk (or download if requested) & verify signature
    let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename);

    // Unpack the tarball
    let gz_decoder = Decoder::new(std::io::Cursor::new(archive_bin)).unwrap();
    let mut archive = Archive::new(gz_decoder);
    archive.unpack(install_dir).unwrap();

    match Target::get().name.as_str() {
        "i686-pc-windows-gnu" => install_dir.join("libsodium-win32/lib"),
        "x86_64-pc-windows-gnu" => install_dir.join("libsodium-win64/lib"),
        _ => panic!("Unsupported target"),
    }
}

// Get the directory containing precompiled MSVC binaries for Win32
fn get_precompiled_lib_dir_msvc_win32(install_dir: &Path) -> PathBuf {
    if Target::get().is_release {
        install_dir.join("libsodium/Win32/Release/v143/static/")
    } else {
        install_dir.join("libsodium/Win32/Debug/v143/static/")
    }
}

// Get the directory containing precompiled MSVC binaries for x64
fn get_precompiled_lib_dir_msvc_x64(install_dir: &Path) -> PathBuf {
    if Target::get().is_release {
        install_dir.join("libsodium/x64/Release/v143/static/")
    } else {
        install_dir.join("libsodium/x64/Debug/v143/static/")
    }
}

// Get the directory containing precompiled MSVC binaries for aarch64
fn get_precompiled_lib_dir_msvc_arm64(install_dir: &Path) -> PathBuf {
    if Target::get().is_release {
        install_dir.join("libsodium/ARM64/Release/v143/static/")
    } else {
        install_dir.join("libsodium/ARM64/Debug/v143/static/")
    }
}

// Compile libsodium from source using the traditional autoconf procedure, and return the directory containing the compiled library
fn compile_libsodium_traditional(
    target: &str,
    source_dir: &Path,
    install_dir: &Path,
) -> Result<PathBuf, String> {
    use std::{fs, process::Command, str};

    // Decide on CC, CFLAGS and the --host configure argument
    let build_compiler = cc::Build::new().get_compiler();
    let mut compiler = build_compiler.path().to_str().unwrap().to_string();
    let mut cflags = build_compiler.cflags_env().into_string().unwrap();
    let mut ldflags = env::var("SODIUM_LDFLAGS").unwrap_or_default();
    let host_arg;
    let help;
    let mut configure_extra = vec![];

    if target.contains("-wasi") {
        // Handle both wasm32-wasi (wasip1) and wasm32-wasip2 targets
        // Zig compiles to wasm32-wasi which is compatible with both
        compiler = "zig cc".to_string();
        cflags += " -target wasm32-wasi";
        ldflags += " -target wasm32-wasi";
        host_arg = "--host=wasm32-wasi".to_string();
        configure_extra.push("--disable-ssp");
        configure_extra.push("--without-pthreads");
        env::set_var("AR", "zig ar");
        env::set_var("RANLIB", "zig ranlib");
        help = "The Zig SDK needs to be installed in order to cross-compile to WebAssembly.\n\
                For WASI Component Model (wasip2), use Rust 1.82+ with:\n\
                cargo build --target wasm32-wasip2 --features wasi-component\n";
    } else if target.contains("-ios") {
        // Determine Xcode directory path
        let xcode_select_output = Command::new("xcode-select").arg("-p").output().unwrap();
        if !xcode_select_output.status.success() {
            return Err("Failed to run xcode-select -p".to_string());
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
        let ios_simulator_version_min = "9.0.0";
        let ios_version_min = "9.0.0";

        match target {
            "aarch64-apple-ios" => {
                cflags += " -arch arm64";
                cflags += &format!(" -isysroot {sdk_dir_ios}");
                cflags += &format!(" -mios-version-min={ios_version_min}");
                host_arg = "--host=aarch64-apple-darwin23".to_string();
            }
            "armv7-apple-ios" => {
                cflags += " -arch armv7";
                cflags += &format!(" -isysroot {sdk_dir_ios}");
                cflags += &format!(" -mios-version-min={ios_version_min}");
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin23".to_string();
            }
            "armv7s-apple-ios" => {
                cflags += " -arch armv7s";
                cflags += &format!(" -isysroot {sdk_dir_ios}");
                cflags += &format!(" -mios-version-min={ios_version_min}");
                cflags += " -mthumb";
                host_arg = "--host=arm-apple-darwin23".to_string();
            }
            "x86_64-apple-ios" => {
                cflags += " -arch x86_64";
                cflags += &format!(" -isysroot {sdk_dir_simulator}");
                cflags += &format!(" -mios-simulator-version-min={ios_simulator_version_min}");
                host_arg = "--host=x86_64-apple-darwin23".to_string();
            }
            "aarch64-apple-ios-sim" => {
                cflags += " -arch arm64";
                cflags += &format!(" -isysroot {sdk_dir_simulator}");
                cflags += &format!(" -mios-simulator-version-min={ios_simulator_version_min}");
                host_arg = "--host=aarch64-apple-darwin23".to_string();
            }
            _ => return Err(format!("Unknown iOS build target: {}", target)),
        }
        help = "";
    } else {
        if target.contains("i686") {
            compiler += " -m32 -maes";
            cflags += " -march=i686";
        }
        let host = env::var("HOST").unwrap();
        host_arg = format!("--host={target}");
        let cross_compiling = target != host;
        help = if cross_compiling {
            "***********************************************************\n\
             Use the 'cargo zigbuild' command to cross-compile Rust code\n\
             with C dependencies such as libsodium.\n\
             ***********************************************************\n"
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
    configure_cmd.arg("--disable-ssp");
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
        .output();
    let configure_output = match configure_output {
        Ok(output) => output,
        Err(error) => {
            return Err(format!("Failed to run './configure': {}\n{}", error, help));
        }
    };
    if !configure_output.status.success() {
        return Err(format!(
            "\n{:?}\nCFLAGS={}\nLDFLAGS={}\nCC={}\n{}\n{}\n{}\n",
            configure_cmd,
            cflags,
            ldflags,
            compiler,
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&configure_output.stderr),
            help
        ));
    }

    let j_arg = format!("-j{}", env::var("NUM_JOBS").unwrap());

    // Run `make install`
    let mut install_cmd = Command::new("make");
    let install_output = install_cmd
        .current_dir(source_dir)
        .arg(j_arg)
        .arg("install")
        .output();
    let install_output = match install_output {
        Ok(install_output) => install_output,
        Err(error) => {
            return Err(format!("Failed to run 'make install': {}\n", error));
        }
    };
    if !install_output.status.success() {
        panic!(
            "\n{}\n{}\n{}\n",
            String::from_utf8_lossy(&configure_output.stdout),
            String::from_utf8_lossy(&install_output.stdout),
            String::from_utf8_lossy(&install_output.stderr)
        );
    }
    Ok(install_dir.join("lib"))
}

// Get the directory where Cargo looks for libraries to link to
fn get_cargo_install_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").unwrap()).join("installed")
}

// Retrieve an archive from the internet, verify its signature, and return its contents
fn retrieve_and_verify_archive(filename: &str, signature_filename: &str) -> Vec<u8> {
    use minisign_verify::{PublicKey, Signature};
    use std::fs::{self, File};
    use std::io::prelude::*;

    let pk =
        PublicKey::from_base64("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3").unwrap();

    if let Ok(dist_dir) = env::var("SODIUM_DIST_DIR") {
        let _ = fs::metadata(&dist_dir).expect("SODIUM_DIST_DIR directory does not exist");
        let archive_path = PathBuf::from(&dist_dir).join(filename);
        let signature_path = PathBuf::from(&dist_dir).join(signature_filename);
        let mut archive_bin = vec![];
        File::open(&archive_path)
            .unwrap_or_else(|_| panic!("Failed to open archive [{:?}]", &archive_path))
            .read_to_end(&mut archive_bin)
            .unwrap();
        let signature = Signature::from_file(&signature_path)
            .unwrap_or_else(|_| panic!("Failed to open signature file [{:?}]", &signature_path));
        pk.verify(&archive_bin, &signature, false)
            .expect("Invalid signature");
        return archive_bin;
    }

    let mut archive_bin = vec![];

    #[allow(unused_mut)]
    let mut download = true;
    #[cfg(not(feature = "fetch-latest"))]
    {
        if let Ok(mut file) = File::open(filename) {
            if file.read_to_end(&mut archive_bin).is_ok() {
                download = false;
            }
        }
    }
    if download {
        let baseurl = "http://download.libsodium.org/libsodium/releases";
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(300)))
            .proxy(ureq::Proxy::try_from_env())
            .build()
            .new_agent();
        let mut response = agent
            .get(&format!("{}/{}", baseurl, filename))
            .call()
            .unwrap();
        response
            .body_mut()
            .as_reader()
            .read_to_end(&mut archive_bin)
            .unwrap();
        File::create(filename)
            .unwrap()
            .write_all(&archive_bin)
            .unwrap();

        let mut response = agent
            .get(&format!("{}/{}", baseurl, signature_filename))
            .call()
            .unwrap();
        let mut signature_bin = vec![];
        response
            .body_mut()
            .as_reader()
            .read_to_end(&mut signature_bin)
            .unwrap();
        File::create(signature_filename)
            .unwrap()
            .write_all(&signature_bin)
            .unwrap();
    }
    let signature = Signature::from_file(signature_filename).unwrap();
    pk.verify(&archive_bin, &signature, false)
        .expect("Invalid signature");

    archive_bin
}

// cargo doesn't properly handle #[cfg] and cfg!() in build.rs files,
// so we have to reimplement everything dynamically.

// Install libsodium from source
fn install_from_source() -> Result<(), String> {
    use libflate::gzip::Decoder;
    use std::fs;
    use tar::Archive;

    // Determine build target triple
    let mut target = Target::get().name;
    // Hack for RISC-V; Rust apparently uses a different convention for RISC-V triples
    if target.starts_with("riscv") {
        let mut split = target.split('-');
        let arch = split.next().unwrap();
        let bitness = &arch[5..7];
        let rest = split.collect::<Vec<_>>().join("-");
        target = format!("riscv{bitness}-{rest}");
    }

    // Determine filenames
    let basedir = "libsodium-stable";
    let basename = "LATEST";
    let filename = format!("{basename}.tar.gz");
    let signature_filename = format!("{basename}.tar.gz.minisig");

    // Read source archive from disk (or download if requested) & verify signature
    let archive_bin = retrieve_and_verify_archive(&filename, &signature_filename);

    // Determine source and install dir
    let mut install_dir = get_cargo_install_dir();
    let mut source_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("source");

    // Avoid issues with paths containing spaces by falling back to using a tempfile.
    // See https://github.com/jedisct1/libsodium/issues/207
    if install_dir.to_str().unwrap().contains(' ') {
        let fallback_path = PathBuf::from("/tmp/").join(basename).join(&target);
        install_dir = fallback_path.join("installed");
        source_dir = fallback_path.join("source");
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

    let lib_dir = compile_libsodium_traditional(&target, &source_dir, &install_dir)?;

    if target.contains("msvc") {
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

    Ok(())
}

fn main() {
    dbg!("Compiling for target:", Target::get().name);

    println!("cargo:rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SODIUM_SHARED");
    println!("cargo:rerun-if-env-changed=SODIUM_USE_PKG_CONFIG");
    println!("cargo:rerun-if-env-changed=VCPKGRS_DYNAMIC");
    println!("cargo:rerun-if-env-changed=SODIUM_DISABLE_PIE");

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
        find_libsodium_env();
        return;
    }
    if use_pkg_isset {
        if shared_isset {
            println!("cargo:warning=SODIUM_SHARED has no effect with SODIUM_USE_PKG_CONFIG");
        }
        if !find_libsodium_pkgconfig() && !find_libsodium_vpkg() {
            panic!("libsodium not found via pkg-config or vcpkg");
        }
        return;
    }
    if shared_isset {
        println!("cargo:warning=SODIUM_SHARED has no effect for building libsodium from source");
    }
    let res = install_from_source();
    if res.is_ok() {
        return;
    }
    // If we can't build from source, try to find precompiled binaries
    match Target::get().name.as_str() {
        "i686-pc-windows-msvc" => {
            let install_dir = get_cargo_install_dir();
            let lib_dir =
                extract_libsodium_precompiled_msvc("win32", Path::new("source"), &install_dir);
            println!(
                "cargo:rustc-link-search=native={}",
                lib_dir.to_str().unwrap()
            );
            println!("cargo:rustc-link-lib=static=libsodium");
            println!(
                "cargo:include={}",
                install_dir.join("include").to_str().unwrap()
            );
        }
        "x86_64-pc-windows-msvc" => {
            let install_dir = get_cargo_install_dir();
            let lib_dir =
                extract_libsodium_precompiled_msvc("x64", Path::new("source"), &install_dir);
            println!(
                "cargo:rustc-link-search=native={}",
                lib_dir.to_str().unwrap()
            );
            println!("cargo:rustc-link-lib=static=libsodium");
            println!(
                "cargo:include={}",
                install_dir.join("include").to_str().unwrap()
            );
        }
        "aarch64-pc-windows-msvc" => {
            let install_dir = get_cargo_install_dir();
            let lib_dir =
                extract_libsodium_precompiled_msvc("arm64", Path::new("source"), &install_dir);
            println!(
                "cargo:rustc-link-search=native={}",
                lib_dir.to_str().unwrap()
            );
            println!("cargo:rustc-link-lib=static=libsodium");
            println!(
                "cargo:include={}",
                install_dir.join("include").to_str().unwrap()
            );
        }
        "i686-pc-windows-gnu" => {
            let install_dir = get_cargo_install_dir();
            let lib_dir =
                extract_libsodium_precompiled_mingw("win32", Path::new("source"), &install_dir);
            println!(
                "cargo:rustc-link-search=native={}",
                lib_dir.to_str().unwrap()
            );
            println!("cargo:rustc-link-lib=static=sodium");
            println!(
                "cargo:include={}",
                install_dir.join("include").to_str().unwrap()
            );
        }
        "x86_64-pc-windows-gnu" => {
            let install_dir = get_cargo_install_dir();
            let lib_dir =
                extract_libsodium_precompiled_mingw("x64", Path::new("source"), &install_dir);
            println!(
                "cargo:rustc-link-search=native={}",
                lib_dir.to_str().unwrap()
            );
            println!("cargo:rustc-link-lib=static=sodium");
            println!(
                "cargo:include={}",
                install_dir.join("include").to_str().unwrap()
            );
        }
        _ => {
            panic!(
                "Unable to compile or find precompiled libsodium for target [{}]: [{}]",
                Target::get().name,
                res.unwrap_err()
            );
        }
    }
}
