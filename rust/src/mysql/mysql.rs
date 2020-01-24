/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

// written by Giuseppe Longo <giuseppe@glongo.it>

extern crate nom;

use applayer;
use conf;
use core;
use core::{sc_detect_engine_state_free, AppProto, Flow, ALPROTO_UNKNOWN};
use log::*;
use mysql::parser::*;
use parser::*;
use std;
use std::ffi::{CStr, CString};

/// MySQL charset types
pub const MYSQL_CHARSET_BIG5        : u8 = 1;
pub const MYSQL_CHARSET_DEC8        : u8 = 3;
pub const MYSQL_CHARSET_CP850       : u8 = 4;
pub const MYSQL_CHARSET_HP8         : u8 = 6;
pub const MYSQL_CHARSET_KOI8R       : u8 = 7;
pub const MYSQL_CHARSET_LATIN1      : u8 = 8;
pub const MYSQL_CHARSET_LATIN2      : u8 = 9;
pub const MYSQL_CHARSET_SWE7        : u8 = 10;
pub const MYSQL_CHARSET_ASCII       : u8 = 11;
pub const MYSQL_CHARSET_UJIS        : u8 = 12;
pub const MYSQL_CHARSET_SJIS        : u8 = 13;
pub const MYSQL_CHARSET_HEBREW      : u8 = 16;
pub const MYSQL_CHARSET_TIS620      : u8 = 18;
pub const MYSQL_CHARSET_EUCKR       : u8 = 19;
pub const MYSQL_CHARSET_KOI8U       : u8 = 22;
pub const MYSQL_CHARSET_GB2312      : u8 = 24;
pub const MYSQL_CHARSET_GREEK       : u8 = 25;
pub const MYSQL_CHARSET_CP1250      : u8 = 26;
pub const MYSQL_CHARSET_GBK         : u8 = 28;
pub const MYSQL_CHARSET_LATIN5      : u8 = 30;
pub const MYSQL_CHARSET_ARMSCII8    : u8 = 32;
pub const MYSQL_CHARSET_UTF8        : u8 = 33;
pub const MYSQL_CHARSET_UCS2        : u8 = 35;
pub const MYSQL_CHARSET_CP866       : u8 = 36;
pub const MYSQL_CHARSET_KEYBCS2     : u8 = 37;
pub const MYSQL_CHARSET_MACCE       : u8 = 38;
pub const MYSQL_CHARSET_MACROMAN    : u8 = 39;
pub const MYSQL_CHARSET_CP852       : u8 = 40;
pub const MYSQL_CHARSET_LATIN7      : u8 = 41;
pub const MYSQL_CHARSET_CP1251      : u8 = 51;
pub const MYSQL_CHARSET_UTF16       : u8 = 54;
pub const MYSQL_CHARSET_UTF16LE     : u8 = 56;
pub const MYSQL_CHARSET_CP1256      : u8 = 57;
pub const MYSQL_CHARSET_CP1257      : u8 = 59;
pub const MYSQL_CHARSET_UTF32       : u8 = 60;
pub const MYSQL_CHARSET_BINARY      : u8 = 63;
pub const MYSQL_CHARSET_GEOSTD8     : u8 = 92;
pub const MYSQL_CHARSET_CP932       : u8 = 95;
pub const MYSQL_CHARSET_EUCJPMS     : u8 = 97;
pub const MYSQL_CHARSET_GB18030     : u8 = 248;
pub const MYSQL_CHARSET_UTF8MB4     : u8 = 255;

#[repr(u32)]
pub enum MysqlEvent {
    IncompleteData = 0,
    InvalidData,
}

impl MysqlEvent {
    fn from_i32(value: i32) -> Option<MysqlEvent> {
        match value {
            0 => Some(MysqlEvent::IncompleteData),
            1 => Some(MysqlEvent::InvalidData),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum MysqlTransactionItem {
    Unknown,
    HandshakeRequest(MysqlHandshakeRequest),
    HandshakeResponse(MysqlHandshakeResponse),
    Request(MysqlRequest),
    Response(MysqlResponse),
}

pub struct MysqlState {
    transactions: Vec<MysqlTransaction>,
    tx_id: u64,
    command_code: u8
}

pub struct MysqlTransaction {
    pub id: u64,
    pub item: MysqlTransactionItem,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    logged: applayer::LoggerFlags,
}

impl MysqlState {
    pub fn new() -> MysqlState {
        println!("NEW STATE");
        MysqlState {
            transactions: Vec::new(),
            tx_id: 0,
            command_code: 0
        }
    }

    pub fn free(&mut self) {
        self.transactions.clear();
    }

    fn new_tx(&mut self, item: MysqlTransactionItem) -> MysqlTransaction {
        self.tx_id += 1;
        MysqlTransaction::new(self.tx_id, item)
    }

    fn get_tx_by_id(&mut self, tx_id: u64) -> Option<&MysqlTransaction> {
        self.transactions.iter().find(|&tx| tx.id == tx_id + 1)
    }

    fn free_tx(&mut self, tx_id: u64) {
        let tx = self
            .transactions
            .iter()
            .position(|ref tx| tx.id == tx_id + 1);
        debug_assert!(tx != None);
        if let Some(idx) = tx {
            let _ = self.transactions.remove(idx);
        }
    }

    fn set_event(&mut self, event: MysqlEvent) {
        if let Some(tx) = self.transactions.last_mut() {
            let ev = event as u8;
            core::sc_app_layer_decoder_events_set_event_raw(&mut tx.events, ev);
        }
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        println!("REQ TX");
        if self.command_code == 0 {
            if let Ok((_, handshake)) = mysql_parse_handshake_response(input) {
                //println!("got handshake response");
                let mut tx = self.new_tx(MysqlTransactionItem::HandshakeResponse(handshake));
                self.transactions.push(tx);
                return true;
            }
        }
        println!("after handshake");
        if let Ok((_, req)) = mysql_parse_request(input) {
            //println!("parsing query");
            self.command_code = req.command_code;
            let mut tx = self.new_tx(MysqlTransactionItem::Request(req));
            self.transactions.push(tx);
            return true;
        }
//        match sip_parse_request(input) {
//            Ok((_, request)) => {
//                let mut tx = self.new_tx();
//                tx.request = Some(request);
//                if let Ok((_, req_line)) = sip_take_line(input) {
//                    tx.request_line = req_line;
//                }
//                self.transactions.push(tx);
//                return true;
//            }
//            Err(nom::Err::Incomplete(_)) => {
//                self.set_event(SIPEvent::IncompleteData);
//                return false;
//            }
//            Err(_) => {
//                self.set_event(SIPEvent::InvalidData);
//                return false;
//            }
//        }
        return false;
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        println!("RESP TX, code {}", self.command_code);
        if let Ok((_, handshake)) = mysql_parse_handshake(input) {
            //println!("got handshake");
            let mut tx = self.new_tx(MysqlTransactionItem::HandshakeRequest(handshake));
            self.transactions.push(tx);
            return true;
        }
        if let Ok((_, resp)) = mysql_parse_response(input, self.command_code) {
            let mut tx = self.new_tx(MysqlTransactionItem::Response(resp));
            self.transactions.push(tx);
            return true;
        }
//        match sip_parse_response(input) {
//            Ok((_, response)) => {
//                let mut tx = self.new_tx();
//                tx.response = Some(response);
//                if let Ok((_, resp_line)) = sip_take_line(input) {
//                    tx.response_line = resp_line;
//                }
//                self.transactions.push(tx);
//                return true;
//            }
//            Err(nom::Err::Incomplete(_)) => {
//                self.set_event(SIPEvent::IncompleteData);
//                return false;
//            }
//            Err(_) => {
//                self.set_event(SIPEvent::InvalidData);
//                return false;
//            }
//        }
        return false;
    }
}

impl MysqlTransaction {
    pub fn new(id: u64, item: MysqlTransactionItem) -> MysqlTransaction {
        MysqlTransaction {
            id,
            item,
            de_state: None,
            events: std::ptr::null_mut(),
            logged: applayer::LoggerFlags::new(),
        }
    }
}

impl Drop for MysqlTransaction {
    fn drop(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            sc_detect_engine_state_free(state);
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_new() -> *mut std::os::raw::c_void {
    let state = MysqlState::new();
    let boxed = Box::new(state);
    return unsafe { std::mem::transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_free(state: *mut std::os::raw::c_void) {
    let mut state: Box<MysqlState> = unsafe { std::mem::transmute(state) };
    state.free();
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, MysqlState);
    match state.get_tx_by_id(tx_id) {
        Some(tx) => unsafe { std::mem::transmute(tx) },
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, MysqlState);
    state.tx_id
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, MysqlState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_progress_completion_status(_direction: u8) -> std::os::raw::c_int {
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_mysql_tx_get_alstate_progress(
    _tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    1
}

#[no_mangle]
pub extern "C" fn rs_mysql_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, MysqlTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_mysql_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, MysqlTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_set_tx_detect_state(
    tx: *mut std::os::raw::c_void,
    de_state: &mut core::DetectEngineState,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, MysqlTransaction);
    tx.de_state = Some(de_state);
    0
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_tx_detect_state(
    tx: *mut std::os::raw::c_void,
) -> *mut core::DetectEngineState {
    let tx = cast_pointer!(tx, MysqlTransaction);
    match tx.de_state {
        Some(ds) => ds,
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, MysqlTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_event_info(
    event_name: *const std::os::raw::c_char,
    event_id: *mut std::os::raw::c_int,
    event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    if event_name == std::ptr::null() {
        return -1;
    }
    let c_event_name: &CStr = unsafe { CStr::from_ptr(event_name) };
    let event = match c_event_name.to_str() {
        Ok(s) => {
            match s {
                "incomplete_data" => MysqlEvent::IncompleteData as i32,
                "invalid_data" => MysqlEvent::InvalidData as i32,
                _ => -1, // unknown event
            }
        }
        Err(_) => -1, // UTF-8 conversion failed
    };
    unsafe {
        *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        *event_id = event as std::os::raw::c_int;
    };
    0
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_event_info_by_id(
    event_id: std::os::raw::c_int,
    event_name: *mut *const std::os::raw::c_char,
    event_type: *mut core::AppLayerEventType,
) -> i8 {
    if let Some(e) = MysqlEvent::from_i32(event_id as i32) {
        let estr = match e {
            MysqlEvent::IncompleteData => "incomplete_data\0",
            MysqlEvent::InvalidData => "invalid_data\0",
        };
        unsafe {
            *event_name = estr.as_ptr() as *const std::os::raw::c_char;
            *event_type = core::APP_LAYER_EVENT_TYPE_TRANSACTION;
        };
        0
    } else {
        -1
    }
}

static mut ALPROTO_MYSQL: AppProto = ALPROTO_UNKNOWN;

#[no_mangle]
pub extern "C" fn rs_mysql_probing_parser_ts(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    //println!("probe ts {:#x?}", buf);
    return unsafe { ALPROTO_MYSQL };
}

#[no_mangle]
pub extern "C" fn rs_mysql_probing_parser_tc(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8,
) -> AppProto {
    let buf = build_slice!(input, input_len as usize);
    //println!("probe tc {:#x?}", buf);
    return unsafe { ALPROTO_MYSQL };
}

#[no_mangle]
pub extern "C" fn rs_mysql_parse_request(
    _flow: *const core::Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let buf = build_slice!(input, input_len as usize);
    //println!("req {:#x?}", buf);
    let state = cast_pointer!(state, MysqlState);
    if state.parse_request(buf) {
        1
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rs_mysql_parse_response(
    _flow: *const core::Flow,
    state: *mut std::os::raw::c_void,
    _pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let buf = build_slice!(input, input_len as usize);
    //println!("resp {:#x?}", buf);
    let state = cast_pointer!(state, MysqlState);
    if state.parse_response(buf) {
        1
    } else {
        -1
    }
}

const PARSER_NAME: &'static [u8] = b"mysql\0";

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_register_parser() {
    let default_port = CString::new("3306").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: core::IPPROTO_TCP,
        probe_ts: rs_mysql_probing_parser_ts,
        probe_tc: rs_mysql_probing_parser_tc,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_mysql_state_new,
        state_free: rs_mysql_state_free,
        tx_free: rs_mysql_state_tx_free,
        parse_ts: rs_mysql_parse_request,
        parse_tc: rs_mysql_parse_response,
        get_tx_count: rs_mysql_state_get_tx_count,
        get_tx: rs_mysql_state_get_tx,
        tx_get_comp_st: rs_mysql_state_progress_completion_status,
        tx_get_progress: rs_mysql_tx_get_alstate_progress,
        get_tx_logged: Some(rs_mysql_tx_get_logged),
        set_tx_logged: Some(rs_mysql_tx_set_logged),
        get_de_state: rs_mysql_state_get_tx_detect_state,
        set_de_state: rs_mysql_state_set_tx_detect_state,
        get_events: Some(rs_mysql_state_get_events),
        get_eventinfo: Some(rs_mysql_state_get_event_info),
        get_eventinfo_byid: Some(rs_mysql_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: None,
        get_tx_detect_flags: None,
        set_tx_detect_flags: None,
    };

    /* For 5.0 we want this disabled by default, so check that it
     * has been explicitly enabled. */
    if !conf::conf_get_bool("app-layer.protocols.mysql.enabled") {
        return;
    }

    let ip_proto_str = CString::new("tcp").unwrap();
    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MYSQL = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
    } else {
        SCLogDebug!("Protocol detector and parser disabled for MySQL.");
    }
}
