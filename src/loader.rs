//loader.rs
//PE loading logic for x86 and x64 with staged RW→RX protection
//Author: wanmywann

use std::ffi::CString;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryA},
        },
    }, core::PCSTR
};

use crate::logger::{log_info, log_ok};
use crate::pe_structures::*;
use crate::syscall::*;

// Memory constants (PAGE_* for Nt syscalls)
const PAGE_NOACCESS:           u32 = 0x01;
const PAGE_READONLY:           u32 = 0x02;
const PAGE_READWRITE:          u32 = 0x04;
const PAGE_EXECUTE:            u32 = 0x10;
const PAGE_EXECUTE_READ:       u32 = 0x20;
const PAGE_EXECUTE_READWRITE:  u32 = 0x40;
const MEM_COMMIT:              u32 = 0x1000;
const MEM_RESERVE:             u32 = 0x2000;

// Section characteristic flags
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ:    u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE:   u32 = 0x80000000;

fn nt_current_process() -> HANDLE {
    HANDLE(-1_isize)
}

fn section_protection(characteristics: u32) -> u32 {
    let exec  = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    let read  = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    match (exec, read, write) {
        (true,  true,  true ) => PAGE_EXECUTE_READWRITE,
        (true,  true,  false) => PAGE_EXECUTE_READ,
        (true,  false, true ) => PAGE_EXECUTE_READWRITE,
        (true,  false, false) => PAGE_EXECUTE,
        (false, true,  true ) => PAGE_READWRITE,
        (false, true,  false) => PAGE_READONLY,
        (false, false, true ) => PAGE_READWRITE,
        (false, false, false) => PAGE_NOACCESS,
    }
}

// --- x86 PE loader -----------------------------------------------------------

pub struct X86PeLoader {
    pub raw_bytes: Vec<u8>,
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER32,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X86PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        unsafe {
            let data = bytes.as_ptr();
            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            if dos.e_magic != 0x5A4D {
                return Err("Invalid DOS signature (not MZ)".to_string());
            }

            let nt_offset = dos.e_lfanew as usize;
            let file_hdr: IMAGE_FILE_HEADER = read_struct(data, nt_offset + 4);
            let opt_hdr: IMAGE_OPTIONAL_HEADER32 = read_struct(
                data,
                nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>(),
            );
            let sections_offset = nt_offset
                + 4
                + std::mem::size_of::<IMAGE_FILE_HEADER>()
                + std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>();

            let mut sections = Vec::new();
            for i in 0..file_hdr.number_of_sections as usize {
                let sec: IMAGE_SECTION_HEADER =
                    read_struct(data, sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>());
                sections.push(sec);
            }

            Ok(Self {
                raw_bytes: bytes,
                dos_header: dos,
                file_header: file_hdr,
                optional_header: opt_hdr,
                sections,
            })
        }
    }

    pub fn is_32bit(&self) -> bool {
        self.optional_header.magic == 0x010B
    }
}

pub fn load_x86(pe: &X86PeLoader) -> Result<(), String> {
    unsafe {
        let opt = &pe.optional_header;

        // --- Stage 1: Allocate RW for the entire image ---
        let mut region_size = opt.size_of_image as usize;
        let mut image_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = nt_allocate_virtual_memory(
            nt_current_process(),
            &mut image_base,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if status != 0 {
            return Err(format!("NtAllocateVirtualMemory failed: 0x{:X}", status as u32));
        }

        let base = image_base as *mut u8;
        log_ok(&format!("Allocated {:#X} bytes at {:#X}", region_size, base as usize));

        // --- Stage 2: Copy headers ---
        let raw = pe.raw_bytes.as_ptr();
        std::ptr::copy_nonoverlapping(raw, base, opt.size_of_headers as usize);

        // --- Stage 3: Copy sections ---
        for sec in &pe.sections {
            if sec.size_of_raw_data == 0 {
                continue;
            }
            let dest = base.add(sec.virtual_address as usize);
            std::ptr::copy_nonoverlapping(
                raw.add(sec.pointer_to_raw_data as usize),
                dest,
                sec.size_of_raw_data as usize,
            );
            log_info(&format!(
                "Section {:>8} mapped to {:#X}",
                sec.name_str(),
                dest as usize
            ));
        }

        // --- Stage 4: Apply base relocations ---
        let delta = image_base as i64 - opt.image_base as i64;
        if delta != 0 {
            let reloc_dir = &opt.base_relocation_table;
            if reloc_dir.size == 0 {
                return Err("Relocation table size is zero".to_string());
            }
            let reloc_base = base.add(reloc_dir.virtual_address as usize);
            let mut offset: usize = 0;

            loop {
                let block: IMAGE_BASE_RELOCATION = read_struct(reloc_base, offset);
                if block.size_of_block == 0 {
                    break;
                }
                let count = ((block.size_of_block - 8) / 2) as usize;
                let fixup_base = base.add(block.virtual_address as usize);

                for i in 0..count {
                    let value = std::ptr::read_unaligned(
                        reloc_base.add(offset + 8 + i * 2) as *const u16,
                    );
                    let reloc_type = value >> 12;
                    let rva = (value & 0xFFF) as usize;

                    if reloc_type == 0x3 {
                        let patch = fixup_base.add(rva) as *mut i32;
                        let original = std::ptr::read_unaligned(patch);
                        std::ptr::write_unaligned(patch, original + delta as i32);
                    }
                }
                offset += block.size_of_block as usize;
            }
        }

        // --- Stage 5: Resolve imports ---
        let import_dir = &opt.import_table;
        if import_dir.size == 0 {
            return Err("Import table size is zero".to_string());
        }

        let desc_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let mut desc_ptr =
            base.add(import_dir.virtual_address as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        loop {
            let desc: IMAGE_IMPORT_DESCRIPTOR = std::ptr::read_unaligned(desc_ptr);
            if desc.name == 0 {
                break;
            }

            let ptr_dll_name = base.add(desc.name as usize);
            let dll_name = read_ansi_string(ptr_dll_name);
            log_info(&format!("Import DLL: {}", dll_name));

            let dll_cstr = CString::new(dll_name.clone()).map_err(|e| e.to_string())?;
            let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8))
                .map_err(|e| format!("LoadLibrary({}) failed: {}", dll_name, e))?;

            let mut thunk_ref = base.add(if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            }) as *const u32;

            let mut func_ref = base.add(desc.first_thunk as usize) as *mut u32;

            loop {
                let thunk_data = std::ptr::read_unaligned(thunk_ref);
                if thunk_data == 0 {
                    break;
                }

                let func_addr = if (thunk_data & 0x80000000) != 0 {
                    let ordinal = (thunk_data & 0xFFFF) as usize;
                    GetProcAddress(h_dll, PCSTR(ordinal as *const u8))
                } else {
                    let p_name = base.add(thunk_data as usize + 2);
                    let func_name = read_ansi_string(p_name);
                    let func_cstr = CString::new(func_name).map_err(|e| e.to_string())?;
                    GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
                };

                if let Some(addr) = func_addr {
                    std::ptr::write_unaligned(func_ref, addr as usize as u32);
                }

                thunk_ref = thunk_ref.add(1);
                func_ref = func_ref.add(1);
            }

            desc_ptr = (desc_ptr as *const u8).add(desc_size) as *const IMAGE_IMPORT_DESCRIPTOR;
        }

        // --- Stage 6: Apply per-section memory protection ---
        log_info("Applying staged memory protections");

        let mut old_protect: u32 = 0;

        // Protect headers → READONLY
        let mut header_size = opt.size_of_headers as usize;
        let mut header_ptr = base as *mut std::ffi::c_void;
        let _ = nt_protect_virtual_memory(
            nt_current_process(),
            &mut header_ptr,
            &mut header_size,
            PAGE_READONLY,
            &mut old_protect,
        );

        // Protect each section based on its characteristics
        for sec in &pe.sections {
            let mut sec_addr = base.add(sec.virtual_address as usize) as *mut std::ffi::c_void;
            let mut sec_size = sec.virtual_size as usize;
            if sec_size == 0 {
                sec_size = sec.size_of_raw_data as usize;
            }
            if sec_size == 0 {
                continue;
            }

            let prot = section_protection(sec.characteristics);
            let _ = nt_protect_virtual_memory(
                nt_current_process(),
                &mut sec_addr,
                &mut sec_size,
                prot,
                &mut old_protect,
            );
            log_info(&format!(
                "Section {:>8} protection set to 0x{:02X}",
                sec.name_str(),
                prot
            ));
        }

        // --- Stage 7: Execute entry point via syscall ---
        let entry = base.add(opt.address_of_entry_point as usize);
        log_ok(&format!("Jumping to OEP @ {:#X}", entry as usize));

        let mut h_thread = HANDLE::default();
        let status = nt_create_thread_ex(
            &mut h_thread,
            0x1FFFFF,
            std::ptr::null_mut(),
            nt_current_process(),
            entry as *mut std::ffi::c_void,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status != 0 {
            return Err(format!("NtCreateThreadEx failed: 0x{:X}", status as u32));
        }

        nt_wait_for_single_object(h_thread, false, std::ptr::null_mut());
        Ok(())
    }
}

// --- x64 PE loader -----------------------------------------------------------

pub struct X64PeLoader {
    pub raw_bytes: Vec<u8>,
    pub dos_header: IMAGE_DOS_HEADER,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header32: IMAGE_OPTIONAL_HEADER32,
    pub optional_header64: IMAGE_OPTIONAL_HEADER64,
    pub sections: Vec<IMAGE_SECTION_HEADER>,
}

impl X64PeLoader {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        unsafe {
            let data = bytes.as_ptr();

            let dos: IMAGE_DOS_HEADER = read_struct(data, 0);
            if dos.e_magic != 0x5A4D {
                return Err("Invalid DOS signature (not MZ)".to_string());
            }

            let nt_offset = dos.e_lfanew as usize;
            let file_hdr: IMAGE_FILE_HEADER = read_struct(data, nt_offset + 4);
            let opt_offset = nt_offset + 4 + std::mem::size_of::<IMAGE_FILE_HEADER>();
            let is_32bit = (file_hdr.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0;

            let opt32: IMAGE_OPTIONAL_HEADER32 = if is_32bit {
                read_struct(data, opt_offset)
            } else {
                Default::default()
            };

            let opt64: IMAGE_OPTIONAL_HEADER64 = if !is_32bit {
                read_struct(data, opt_offset)
            } else {
                Default::default()
            };

            let sections_offset = opt_offset
                + if is_32bit {
                    std::mem::size_of::<IMAGE_OPTIONAL_HEADER32>()
                } else {
                    std::mem::size_of::<IMAGE_OPTIONAL_HEADER64>()
                };

            let mut sections = Vec::new();
            for i in 0..file_hdr.number_of_sections as usize {
                let sec: IMAGE_SECTION_HEADER = read_struct(
                    data,
                    sections_offset + i * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
                );
                sections.push(sec);
            }

            Ok(Self {
                raw_bytes: bytes,
                dos_header: dos,
                file_header: file_hdr,
                optional_header32: opt32,
                optional_header64: opt64,
                sections,
            })
        }
    }

    pub fn is_32bit_header(&self) -> bool {
        (self.file_header.characteristics & IMAGE_FILE_32BIT_MACHINE) != 0
    }
}

pub fn load_x64(pe: &X64PeLoader) -> Result<(), String> {
    unsafe {
        let opt = &pe.optional_header64;
        let raw = pe.raw_bytes.as_ptr();

        // --- Stage 1: Reserve full image range (RW) ---
        let mut region_size = opt.size_of_image as usize;
        let mut image_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = nt_allocate_virtual_memory(
            nt_current_process(),
            &mut image_base,
            0,
            &mut region_size,
            MEM_RESERVE,
            PAGE_READWRITE,
        );
        if status != 0 {
            return Err(format!("NtAllocateVirtualMemory reserve failed: 0x{:X}", status as u32));
        }

        let base = image_base as *mut u8;
        log_ok(&format!("Reserved {:#X} bytes at {:#X}", region_size, base as usize));

        // --- Stage 2: Commit headers area and copy ---
        let mut header_commit_size = opt.size_of_headers as usize;
        if header_commit_size > 0 {
            let mut header_base = base as *mut std::ffi::c_void;
            let st = nt_allocate_virtual_memory(
                nt_current_process(),
                &mut header_base,
                0,
                &mut header_commit_size,
                MEM_COMMIT,
                PAGE_READWRITE,
            );
            if st == 0 {
                std::ptr::copy_nonoverlapping(raw, base, opt.size_of_headers as usize);
            }
        }

        // --- Stage 3: Commit and copy each section individually ---
        log_info("Mapping sections");
        for sec in &pe.sections {
            if sec.size_of_raw_data == 0 && sec.virtual_size == 0 {
                continue;
            }
            let commit_size = std::cmp::max(sec.size_of_raw_data, sec.virtual_size) as usize;
            let mut dest_base = base.add(sec.virtual_address as usize) as *mut std::ffi::c_void;
            let mut commit_sz = commit_size;

            let st = nt_allocate_virtual_memory(
                nt_current_process(),
                &mut dest_base,
                0,
                &mut commit_sz,
                MEM_COMMIT,
                PAGE_READWRITE,
            );
            if st != 0 {
                log_info(&format!(
                    "Section {:>8} commit warning: 0x{:X}",
                    sec.name_str(),
                    st
                ));
            }

            if sec.size_of_raw_data > 0 {
                std::ptr::copy_nonoverlapping(
                    raw.add(sec.pointer_to_raw_data as usize),
                    dest_base as *mut u8,
                    sec.size_of_raw_data as usize,
                );
            }

            log_info(&format!(
                "Section {:>8} mapped to {:#X}",
                sec.name_str(),
                dest_base as usize
            ));
        }

        // --- Stage 4: Apply base relocations ---
        let delta = image_base as i64 - opt.image_base as i64;
        log_ok(&format!("Delta = {:#X}", delta));

        let reloc_va = opt.base_relocation_table.virtual_address;
        let reloc_size = opt.base_relocation_table.size;

        if reloc_size > 0 {
            let reloc_table = base.add(reloc_va as usize);
            let base_reloc_size = std::mem::size_of::<IMAGE_BASE_RELOCATION>();
            let mut current_offset: usize = 0;
            let total_reloc_size = reloc_size as usize;

            while current_offset < total_reloc_size {
                let block: IMAGE_BASE_RELOCATION = read_struct(reloc_table, current_offset);
                if block.size_of_block == 0 {
                    break;
                }

                let entry_count = (block.size_of_block as usize - base_reloc_size) / 2;
                let dest = base.add(block.virtual_address as usize);

                for i in 0..entry_count {
                    let value = std::ptr::read_unaligned(
                        reloc_table.add(current_offset + base_reloc_size + i * 2) as *const u16,
                    );
                    let reloc_type = value >> 12;
                    let fixup = (value & 0xFFF) as usize;

                    if reloc_type == 0xA {
                        let patch = dest.add(fixup) as *mut i64;
                        let original = std::ptr::read_unaligned(patch);
                        std::ptr::write_unaligned(patch, original + delta);
                    }
                }

                current_offset += block.size_of_block as usize;
            }
        }

        // --- Stage 5: Resolve imports ---
        let import_rva = opt.import_table.virtual_address as usize;
        let desc_size = std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let mut j = 0usize;

        loop {
            let desc: IMAGE_IMPORT_DESCRIPTOR = read_struct(base, import_rva + j * desc_size);

            if desc.name == 0 {
                break;
            }

            let dll_name = read_ansi_string(base.add(desc.name as usize));
            log_info(&format!("Import DLL: {}", dll_name));

            let dll_cstr = CString::new(dll_name.clone()).map_err(|e| e.to_string())?;
            let h_dll = LoadLibraryA(PCSTR(dll_cstr.as_ptr() as *const u8))
                .map_err(|e| format!("LoadLibrary({}) failed: {}", dll_name, e))?;

            let int_rva = if desc.original_first_thunk != 0 {
                desc.original_first_thunk as usize
            } else {
                desc.first_thunk as usize
            };
            let iat_rva = desc.first_thunk as usize;

            let mut k = 0usize;
            loop {
                let thunk =
                    std::ptr::read_unaligned(base.add(int_rva + k * 8) as *const u64);
                if thunk == 0 {
                    break;
                }

                let func_addr = if (thunk & (1u64 << 63)) != 0 {
                    let ordinal = (thunk & 0xFFFF) as usize;
                    GetProcAddress(h_dll, PCSTR(ordinal as *const u8))
                } else {
                    let name_ptr = base.add((thunk & 0x7FFF_FFFF_FFFF) as usize + 2);
                    let func_name = read_ansi_string(name_ptr);
                    let func_cstr = CString::new(func_name).map_err(|e| e.to_string())?;
                    GetProcAddress(h_dll, PCSTR(func_cstr.as_ptr() as *const u8))
                };

                if let Some(addr) = func_addr {
                    let iat_entry = base.add(iat_rva + k * 8) as *mut u64;
                    std::ptr::write_unaligned(iat_entry, addr as usize as u64);
                }

                k += 1;
            }

            j += 1;
        }

        // --- Stage 6: Apply per-section memory protection ---
        log_info("Applying staged memory protections");

        let mut old_protect: u32 = 0;

        // Protect headers → READONLY
        if opt.size_of_headers > 0 {
            let mut hdr_size = opt.size_of_headers as usize;
            let mut hdr_ptr = base as *mut std::ffi::c_void;
            let _ = nt_protect_virtual_memory(
                nt_current_process(),
                &mut hdr_ptr,
                &mut hdr_size,
                PAGE_READONLY,
                &mut old_protect,
            );
        }

        // Protect each section based on its characteristics
        for sec in &pe.sections {
            let mut sec_addr = base.add(sec.virtual_address as usize) as *mut std::ffi::c_void;
            let mut sec_size = sec.virtual_size as usize;
            if sec_size == 0 {
                sec_size = sec.size_of_raw_data as usize;
            }
            if sec_size == 0 {
                continue;
            }

            let prot = section_protection(sec.characteristics);
            let _ = nt_protect_virtual_memory(
                nt_current_process(),
                &mut sec_addr,
                &mut sec_size,
                prot,
                &mut old_protect,
            );
            log_info(&format!(
                "Section {:>8} protection set to 0x{:02X}",
                sec.name_str(),
                prot
            ));
        }

        // --- Stage 7: Execute entry point via syscall ---
        let entry = base.add(opt.address_of_entry_point as usize);
        log_ok(&format!("Jumping to OEP @ {:#X}", entry as usize));

        let mut h_thread = HANDLE::default();
        let status = nt_create_thread_ex(
            &mut h_thread,
            0x1FFFFF,
            std::ptr::null_mut(),
            nt_current_process(),
            entry as *mut std::ffi::c_void,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status != 0 {
            return Err(format!("NtCreateThreadEx failed: 0x{:X}", status as u32));
        }

        nt_wait_for_single_object(h_thread, false, std::ptr::null_mut());
        Ok(())
    }
}
