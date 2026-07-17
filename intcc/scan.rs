#!/usr/bin/env cargo
/*
[package]
name = "scanner"
version = "0.1.0"
edition = "2026"

[dependencies]
*/

use std::os::raw::{c_char, c_int};
use std::slice;
use std::thread;
use std::time::Duration;

const INT3: u8 = 0xCC;
const SCAN_INTERVAL_MS: u64 = 100;

/// 单次扫描内存段 [start_ptr, end_ptr) 中是否存在 int3 (0xCC) 指令。
/// 返回值:
///   >= 0 : 找到 int3 的偏移量（相对于 start_ptr）
///   -1   : 参数无效
///   -2   : 未找到 int3
#[no_mangle]
pub extern "C" fn scan(start_ptr: *const c_char, end_ptr: *const c_char) -> i32 {
    if start_ptr.is_null() || end_ptr.is_null() || start_ptr >= end_ptr {
        return -1;
    }

    let len = (end_ptr as usize) - (start_ptr as usize);
    let slice = unsafe { slice::from_raw_parts(start_ptr as *const u8, len) };

    for (i, &byte) in slice.iter().enumerate() {
        if byte == INT3 {
            return i as i32;
        }
    }

    -2
}

#[no_mangle]
pub extern "C" fn scan_loop(
    start_ptr: *const c_char,
    end_ptr: *const c_char,
    interval_ms: c_int,
) -> i32 {
    if start_ptr.is_null() || end_ptr.is_null() || start_ptr >= end_ptr {
        return -1;
    }

    let ms = if interval_ms > 0 {
        interval_ms as u64
    } else {
        SCAN_INTERVAL_MS
    };

    let len = (end_ptr as usize) - (start_ptr as usize);

    loop {
        let slice = unsafe { slice::from_raw_parts(start_ptr as *const u8, len) };

        for (i, &byte) in slice.iter().enumerate() {
            if byte == INT3 {
                return i as i32;
            }
        }

        thread::sleep(Duration::from_millis(ms));
    }
}
