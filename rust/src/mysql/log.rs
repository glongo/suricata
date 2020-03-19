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

use json::*;
use mysql::mysql::{MysqlState, MysqlTransaction, MysqlTransactionItem};
use mysql::parser::*;

pub fn mysql_charset_string(charset: u8) -> String {
    match charset {
        MYSQL_CHARSET_BIG5 => "big5_chinese_ci",
        MYSQL_CHARSET_DEC8 => "dec8_swedish_ci",
        MYSQL_CHARSET_CP850 => "cp850_general_ci",
        MYSQL_CHARSET_HP8 => "hp8_english_ci",
        MYSQL_CHARSET_KOI8R => "koi8r_general_ci",
        MYSQL_CHARSET_LATIN1 => "latin1_swedish_ci",
        MYSQL_CHARSET_LATIN2 => "latin2_general_ci",
        MYSQL_CHARSET_SWE7 => "swe7_swedish_ci",
        MYSQL_CHARSET_ASCII => "ascii_general_ci",
        MYSQL_CHARSET_UJIS => "ujis_japanese_ci",
        MYSQL_CHARSET_SJIS => "sjis_japanese_ci",
        MYSQL_CHARSET_HEBREW => "hebrew_general_ci",
        MYSQL_CHARSET_TIS620 => "tis620_thai_ci",
        MYSQL_CHARSET_EUCKR => "euckr_korean_ci",
        MYSQL_CHARSET_GB2312 => "gb2312_chinese_ci",
        MYSQL_CHARSET_GREEK => "greek_general_ci",
        MYSQL_CHARSET_CP1250 => "cp1250_general_ci",
        MYSQL_CHARSET_GBK => "gbk_chinese_ci",
        MYSQL_CHARSET_LATIN5 => "latin5_turkish_ci",
        MYSQL_CHARSET_ARMSCII8 => "armscii8_general_ci",
        MYSQL_CHARSET_UTF8 => "utf8_general_ci",
        MYSQL_CHARSET_UCS2 => "ucs2_general_ci",
        MYSQL_CHARSET_CP866 => "cp866_general_ci",
        MYSQL_CHARSET_KEYBCS => "keybcs2_general_ci",
        MYSQL_CHARSET_MACCE => "macce_general_ci",
        MYSQL_CHARSET_MACROMAN => "macroman_general_ci",
        MYSQL_CHARSET_CP852 => "cp852_general_ci",
        MYSQL_CHARSET_LATIN7 => "latin7_general_ci",
        MYSQL_CHARSET_CP1251 => "cp1251_general_ci",
        MYSQL_CHARSET_UTF16 => "utf16_general_ci",
        MYSQL_CHARSET_UTF16LE => "utf16le_general_ci",
        MYSQL_CHARSET_CP1256 => "cp1256_general_ci",
        MYSQL_CHARSET_CP1257 => "cp1257_general_ci",
        MYSQL_CHARSET_UTF32 => "utf32_general_ci",
        MYSQL_CHARSET_BINARY => "binary",
        MYSQL_CHARSET_GEOSTD8 => "geostd8_general_ci",
        MYSQL_CHARSET_CP932 => "cp932_japanese_ci",
        MYSQL_CHARSET_EUCJPMS => "eucjpms_japanese_ci",
        MYSQL_CHARSET_GB18030 => "gb18030_chinese_ci",
        MYSQL_CHARSET_UTF8MB4 => "utf8mb4_0900_ai_ci",
        _ => {
            return charset.to_string();
        }
    }.to_string()
}

#[no_mangle]
pub extern "C" fn rs_mysql_log_json(_state: &mut MysqlState, tx: &mut MysqlTransaction) -> *mut JsonT {
    let js = Json::object();

    //println!("{:#x?}", tx.item);

    match tx.item {
        MysqlTransactionItem::HandshakeRequest(ref req)  => {
            //println!("version {:#x?}", req.version);
            js.set_integer("pkt_len", req.header.pkt_len as u64);
            js.set_integer("pkt_num", req.header.pkt_num as u64);
            js.set_integer("protocol", req.protocol as u64);
            js.set_string("version", &req.version);
            js.set_integer("conn_id", req.conn_id as u64);
            js.set_string("salt1", &req.salt1);
            js.set_string("salt2", &req.salt2);
            js.set_string("character_set", &mysql_charset_string(req.character_set));
            js.set_integer("auth_plugin_len", req.auth_plugin_len as u64);
        },
        MysqlTransactionItem::HandshakeResponse(ref resp) => {
            js.set_integer("pkt_len", resp.header.pkt_len as u64);
            js.set_integer("pkt_num", resp.header.pkt_num as u64);
            js.set_integer("max_pkt_size", resp.max_packet_size as u64);
            js.set_string("character_set", &mysql_charset_string(resp.character_set));
            js.set_string("username", &resp.username);
        },
        MysqlTransactionItem::Request(ref req) => {
            js.set_integer("pkt_len", req.header.pkt_len as u64);
            js.set_integer("pkt_num", req.header.pkt_num as u64);
            match req.command {
                MysqlCommand::Quit => {
                    js.set_string("command", "quit");
                },
                MysqlCommand::InitDb {ref schema} => {
                    js.set_string("command", "init_db");
                    js.set_string("schema", &schema);
                },
                MysqlCommand::Query {ref query} => {
                    js.set_string("command", "query");
                    js.set_string("statement", &query);
                },
                MysqlCommand::FieldList {ref table} => {
                    js.set_string("command", "show_fields");
                    js.set_string("table", &table);
                },
                _ => {
                    js.set_string("command", "unknown");
                }
            }
        },
        MysqlTransactionItem::Response(ref resp) => {
            js.set_string("type", "response");
            match resp.item {
                MysqlResponsePacket::Ok {ref header, rows, flags, warnings} => {
                    js.set_integer("pkt_len", header.pkt_len as u64);
                    js.set_integer("pkt_num", header.pkt_num as u64);
                    js.set_string("status", "ok");
                    js.set_integer("affected_rows", rows as u64);
                    // flags
                    js.set_integer("warnings", warnings as u64);
                },
                MysqlResponsePacket::FieldsList {ref columns, ref eof} => {
                    let jsa = Json::array();
                    for c in columns {
                        let jscol = Json::object();

                        jscol.set_integer("pkt_len", c.header.pkt_len as u64);
                        jscol.set_integer("pkt_num", c.header.pkt_num as u64);
                        jscol.set_string("catalog", &c.catalog);
                        jscol.set_string("schema", &c.schema);
                        jscol.set_string("table", &c.table);
                        jscol.set_string("origin_table", &c.orig_table);
                        jscol.set_string("name", &c.name);
                        jscol.set_string("orig_name", &c.orig_name);

                        jsa.array_append(jscol);
                    }

                    let jseof = Json::object();
                    jseof.set_integer("pkt_len", eof.header.pkt_len as u64);
                    jseof.set_integer("pkt_num", eof.header.pkt_num as u64);
                    jseof.set_integer("warnings", eof.warnings as u64);
                    jseof.set_integer("status_flags", eof.status_flags as u64);

                    js.set("columns", jsa);
                    js.set("eof", jseof);
                },
                MysqlResponsePacket::ResultSet {ref header, n_cols, ref columns, ref eof, ref rows} => {
                    js.set_integer("pkt_len", header.pkt_len as u64);
                    js.set_integer("pkt_num", header.pkt_num as u64);
                    js.set_integer("num_columns", n_cols as u64);

                    let jsa = Json::array();
                    for c in columns {
                        let jscol = Json::object();

                        jscol.set_integer("pkt_len", c.header.pkt_len as u64);
                        jscol.set_integer("pkt_num", c.header.pkt_num as u64);
                        jscol.set_string("catalog", &c.catalog);
                        jscol.set_string("schema", &c.schema);
                        jscol.set_string("table", &c.table);
                        jscol.set_string("origin_table", &c.orig_table);
                        jscol.set_string("name", &c.name);
                        jscol.set_string("orig_name", &c.orig_name);

                        jsa.array_append(jscol);
                    }
                    js.set("columns", jsa);
                },
                _ => {
                    js.set_string("type", "response");
                    js.set_string("status", "unknown");
                }
            }
        },
        _ => {}
    }
    return js.unwrap();
}
