#!/usr/bin/env cargo
/*
[package]
name = "scanner"
version = "0.1.0"
edition = "2026"

[dependencies]
# thread
*/

use std::os::raw::{c_char, c_int};
use std::thread
use std::slice;

#[no_mangle]
pub extern "C" fn scan(start_ptr: *const c_char, end_ptr: *const c_char) -> i32 {
    if start_ptr.is_null() || end_ptr.is_null() || start_ptr > end_ptr {
        return -1;
    }
}
