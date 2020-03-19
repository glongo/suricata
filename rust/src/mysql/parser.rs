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

use nom::*;
use nom::multi::many_m_n;
use nom::{crlf, IResult};
use std;

fn read_uint(buf: &[u8], nbytes: usize) -> u64 {
    assert!(1 <= nbytes && nbytes <= 8 && nbytes <= buf.len());
    let mut out = 0u64;
    let ptr_out = &mut out as *mut u64 as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(), ptr_out, nbytes
        );
    }
    out.to_le()
}

fn read_u24(buf: &[u8]) -> u32 {
    read_uint(buf, 3) as u32
}

#[derive(Debug)]
pub struct MysqlPacket {
    pub pkt_len: u32,
    pub pkt_num: u8,
}

#[derive(Debug)]
pub struct MysqlHandshakeRequest {
    pub header: MysqlPacket,
    pub protocol: u8,
    pub version: String,
    pub conn_id: u32,
    pub salt1: String,
    pub capability_flag1: u16,
    pub character_set: u8,
    pub status_flags: u16,
    pub capability_flags2: u16,
    pub auth_plugin_len: u8,
    pub salt2: String,
    pub auth_plugin_data: Option<String>
}

#[derive(Debug)]
pub struct MysqlHandshakeResponse {
    pub header: MysqlPacket,
    pub capability_flags1: u16,
    pub capability_flags2: u16,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: String,
    pub password: Vec<u8>
}

#[derive(Debug)]
pub enum MysqlCommand {
    Unknown,
    Quit,
    InitDb {schema: String},
    Query {query: String},
    FieldList {table: String},
}

#[derive(Debug)]
pub struct MysqlRequest {
    pub header: MysqlPacket,
    pub command_code: u8,
    pub command: MysqlCommand
}

#[derive(Debug)]
pub struct MysqlResponse {
    pub item: MysqlResponsePacket,
}

#[derive(Debug)]
pub enum MysqlResponsePacket {
    Unknown,
    Ok {header: MysqlPacket, rows: u8, flags: u16, warnings: u16},
    FieldsList {columns: Vec<MysqlColumnDefinition>, eof: MysqlEofPacket},
    ResultSet {
        header: MysqlPacket,
        n_cols: u8,
        columns: Vec<MysqlColumnDefinition>,
        eof: MysqlEofPacket,
        //rows: Vec<MysqlResultSetRow>,
        rows: Vec<u8>,
    }
}

#[derive(Debug)]
pub struct MysqlColumnDefinition {
    pub header: MysqlPacket,
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub orig_table: String,
    pub name: String,
    pub orig_name: String,
    pub character_set: u16,
    pub column_length: u32,
    pub field_type: u8,
    pub flags: u16,
    pub decimals: u8
}

#[derive(Debug)]
pub struct MysqlResultSetRow {
    pub header: MysqlPacket,
    pub text: Vec<String>
}

#[derive(Debug)]
pub struct MysqlEofPacket {
    pub header: MysqlPacket,
    pub warnings: u16,
    pub status_flags: u16
}

named!(pub mysql_parse_handshake<&[u8], MysqlHandshakeRequest>,
    do_parse!(
        pkt_len: map!(take!(3), |len: &[u8]| read_u24(len)) >>
        pkt_num: be_u8 >>
        //protocol: be_u8 >>
        protocol: verify!(be_u8, |x| x == 0x0a as u8) >>
        version: map!(take_till!(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap()) >>
        nil: take!(1) >>
        conn_id: le_u32 >>
        salt1: map!(take_str!(8), |s: &str| s.into()) >>
        nil: take!(1) >>
        capability_flag1: le_u16 >>
        character_set: be_u8 >>
        status_flags: le_u16 >>
        capability_flags2: be_u16 >>
        auth_plugin_len: be_u8 >>
        reversed: take!(10) >>
        salt2: map!(take_till!(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap()) >>
        auth_plugin_data: cond!(auth_plugin_len > 0, map!(take_till!(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap()))
        >>
        (
            MysqlHandshakeRequest {
                header: MysqlPacket {
                    pkt_len,
                    pkt_num,
                },
                protocol: 0x0a,
                version,
                conn_id,
                salt1,
                capability_flag1,
                character_set,
                status_flags,
                capability_flags2,
                auth_plugin_len,
                salt2,
                auth_plugin_data
            }
        )
    )
);

named!(pub mysql_parse_handshake_response<&[u8], MysqlHandshakeResponse>,
    do_parse!(
        pkt_len: map!(take!(3), |len: &[u8]| read_u24(len))  >>
        pkt_num: be_u8 >>
        capability_flags1: le_u16 >>
        capability_flags2: le_u16 >>
        max_packet_size: le_u32 >>
        character_set: be_u8 >>
        reserved: take!(23) >>
        username: map!(take_till!(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap()) >>
        nil: take!(1) >>
        len: be_u8 >>
        password: map!(take!(20), |s: &[u8]| s.to_vec())
        >>
        (
            MysqlHandshakeResponse {
                header: MysqlPacket {
                    pkt_len,
                    pkt_num,
                },
                capability_flags1,
                capability_flags2,
                max_packet_size,
                character_set,
                username,
                password
            }
        )
    )
);

named!(pub mysql_parse_request<&[u8], MysqlRequest>,
    dbg_dmp!(do_parse!(
        pkt_len: map!(take!(3), |len: &[u8]| read_u24(len)) >>
        pkt_num: be_u8 >>
        command_code: be_u8 >>
        command: switch!(value!(command_code),
            0x01 => value!(MysqlCommand::Quit)        |
            0x02 => call!(mysql_parse_init_db_cmd)    |
            0x03 => call!(mysql_parse_query_cmd)      |
            0x04 => call!(mysql_parse_field_list_cmd) |
            _ => value!(MysqlCommand::Unknown)
        ) >>
        (
            MysqlRequest {
                header: MysqlPacket {
                    pkt_len,
                    pkt_num
                },
                command_code,
                command
            }
        )
    ))
);

//pub fn mysql_parse_response(input: &[u8], code: u8) -> IResult<&[u8], MysqlResponse> {
//    match code {
//        3 => {
//            if let Ok((i, item)) = mysql_parse_response_ok(input) {
//                return Ok((i, MysqlResponse { item }));
//            }
//            Ok((input, MysqlResponse { item: MysqlResponsePacket::Unknown }))
//        },
//        4 => {
//            let header = MysqlPacket{ pkt_len: 0, pkt_num: 0 };
//            if let Ok((i, item)) = mysql_parse_response_field_list(input) {
//                return Ok((i, MysqlResponse { item }));
//            }
//            Ok((input, MysqlResponse { item: MysqlResponsePacket::Unknown }))
//        },
//        _ => {
//            let (i, item) = alt!(input, mysql_parse_response_ok)?;
//            Ok((i, MysqlResponse {item}))
//        }
//    }
//}

named_args!(pub mysql_parse_response(code: u8)<MysqlResponse>,
    switch!(value!(code),
        0x03 => alt!(call!(mysql_parse_response_ok) | call!(mysql_parse_resultset)) |
        0x04 => alt!(call!(mysql_parse_response_ok) | call!(mysql_parse_response_field_list)) |
        _ => value!(MysqlResponse {item: MysqlResponsePacket::Unknown})
    )
);

//fn mysql_parse_init_db_cmd(input: &[u8]) -> IResult<&[u8], MysqlCommand> {
//    // check if input is > 0 and return Err in case
//    let schema = String::from_utf8(input.to_vec()).unwrap();
//
//    Ok((&[][..], MysqlCommand::InitDb { schema }))
//}

named!(mysql_parse_init_db_cmd<&[u8], MysqlCommand>,
    do_parse!(
        schema: parse_to!(String)
        >>
        (MysqlCommand::InitDb {schema})
    )
);

named!(mysql_parse_query_cmd<&[u8], MysqlCommand>,
    do_parse!(
        query: parse_to!(String)
        >>
        (MysqlCommand::Query {query})
    )
);

//fn mysql_parse_query_cmd(input: &[u8]) -> IResult<&[u8], MysqlCommand> {
//    // check if input is > 0 and return Err in case
//    let query = String::from_utf8(input.to_vec()).unwrap();
//
//    Ok((&[][..], MysqlCommand::Query { query }))
//}

fn mysql_parse_field_list_cmd(input: &[u8]) -> IResult<&[u8], MysqlCommand> {
    do_parse! {
        input,
        table: map!(take_till!(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap())
        >>
        (MysqlCommand::FieldList { table })
    }
}

named!(mysql_parse_packet_header<&[u8], MysqlPacket>,
    do_parse!(
        pkt_len: map!(take!(3), |len: &[u8]| read_u24(len)) >>
        pkt_num: be_u8
        >>
        (
            MysqlPacket {
                pkt_len,
                pkt_num
            }
        )
    )
);

/*
named!(pub mysql_parse_response<&[u8], MysqlResponse>,
    do_parse!( 
        pkt_len: map!(take!(3), |len: &[u8]| read_u24(len)) >>
        pkt_num: be_u8 >>
        response_code: be_u8 >>
        response: switch!(value!(response_code),
            0x00 => call!(mysql_parse_response_ok) |
            _ => value!(MysqlResponsePacket::Unknown)
        ) >>
        (
            MysqlResponse {
                header: MysqlPacket {
                    pkt_len,
                    pkt_num
                },
                response
            }
        )
    )
);
*/
named!(pub mysql_parse_response_ok<&[u8], MysqlResponse>,
    dbg_dmp!(do_parse!(
        header: mysql_parse_packet_header >>
        code: verify!(be_u8, |x| x == 0x00 as u8) >>
        rows: be_u8 >>
        flags: le_u16 >>
        warnings: le_u16
        >>
        (
            MysqlResponse {
                item: MysqlResponsePacket::Ok {
                    header,
                    rows,
                    flags,
                    warnings
                }
            }
        )
    ))
);


named!(mysql_parse_eof_packet<&[u8], MysqlEofPacket>,
    do_parse!(
        header: mysql_parse_packet_header >>
        tag: verify!(be_u8, |x| x == 0xfe) >>
        warnings: le_u16 >>
        status_flags: le_u16
        >>
        (
            MysqlEofPacket {
                header,
                warnings,
                status_flags
            }
        )
    )
);

named!(mysql_parse_response_field_list<&[u8], MysqlResponse>,
    do_parse!(
        fields: many_till!(call!(mysql_parse_column_definition),
                           call!(mysql_parse_eof_packet))
        >>
        (
            MysqlResponse {
                item: MysqlResponsePacket::FieldsList {
                    columns: fields.0,
                    eof: fields.1
                }
            }
        )
    )
);

named!(mysql_parse_column_definition<&[u8], MysqlColumnDefinition>,
    dbg_dmp!(do_parse!(
        header: mysql_parse_packet_header >>
        _len: be_u8 >>
        catalog: take_str!(_len) >>
        _len: be_u8 >>
        schema: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        table: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        orig_table: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        name: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        orig_name: map!(take_str!(_len), |s: &str| s.into()) >>
        nil: take!(1) >>
        character_set: be_u16 >>
        column_length: le_u32 >>
        field_type: be_u8 >>
        flags: be_u16 >>
        decimals: be_u8 >>
        //filler: take!(5)
        filler: take!(2) >>
        len: be_u8 >>
        def_str: cond!(len != 0xfb, take!(len))
        >>
        (
            MysqlColumnDefinition {
                header,
                catalog: "def".to_string(),
                schema,
                table,
                orig_table,
                name,
                orig_name,
                character_set,
                column_length,
                field_type,
                flags,
                decimals
            }
        )

    ))
);

named!(mysql_parse_column_definition2<&[u8], MysqlColumnDefinition>,
    dbg_dmp!(do_parse!(
        header: mysql_parse_packet_header >>
        _len: be_u8 >>
        catalog: take_str!(_len) >>
        _len: be_u8 >>
        schema: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        table: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        orig_table: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        name: map!(take_str!(_len), |s: &str| s.into()) >>
        _len: be_u8 >>
        orig_name: map!(take_str!(_len), |s: &str| s.into()) >>
        nil: take!(1) >>
        character_set: be_u16 >>
        column_length: le_u32 >>
        field_type: be_u8 >>
        flags: be_u16 >>
        decimals: be_u8 >>
        //filler: take!(5)
        filler: take!(2)
        >>
        (
            MysqlColumnDefinition {
                header,
                catalog: "def".to_string(),
                schema,
                table,
                orig_table,
                name,
                orig_name,
                character_set,
                column_length,
                field_type,
                flags,
                decimals
            }
        )

    ))
);

//fn mysql_parse_field_list_cmd(input: &[u8]) -> IResult<&[u8], MysqlCommand> {
//    do_parse! {
//        input,
//        table: map!(take_till!(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap())
//        >>
//        (MysqlCommand::FieldList { table })
//    }
//}

//fn mysql_parse_resultset(input: &[u8]) -> IResult<&[u8], MysqlResponse> {
//    do_parse! {
//        input,
//        header: mysql_parse_packet_header >>
//        n_cols: be_u8 >>
//        columns: many_m_n!(1, n_cols as usize, call!(mysql_parse_column_definition2)) >>
//        eof: mysql_parse_eof_packet >>
////        rows: fold_many1!(call!(mysql_parse_resultset_row(input, n_cols)), Vec::new(), |mut rows: Vec<_>, r| {
////            rows.push(r);
////            rows
////        })
//        rows: fold_many1!(mysql_parse_resultset_row(input, n_cols), Vec::new(), |mut acc: Vec<u8>, item| {
//            acc.push(1);
//            acc
//            })
//        >>
//        (
//            MysqlResponse {
//                item: MysqlResponsePacket::ResultSet {
//                    header,
//                    n_cols,
//                    columns,
//                    eof,
//                    rows
//                }
//            }
//        )
//    }
//}

//fn mysql_parse_resultset_row(input: &[u8], n_cols: u8) -> IResult<&[u8], MysqlResultSetRow> {
//    do_parse! {
//        input,
//        header: mysql_parse_packet_header >>
//        len: be_u8 >>
//        text: many_m_n!(1, n_cols as usize,
//                do_parse!(
//                    len: be_u8 >>
//                    text: map!(take_str!(len), |s: &str| s.into())
//                    >>
//                    (text)
//                )
//              )
//        >>
//        (
//            MysqlResultSetRow {
//                header,
//                text
//            }
//        )
//    }
//}

//named!(mysql_parse_resultset<&[u8], MysqlResponse>,
//    dbg_dmp!(do_parse!(
//        header: mysql_parse_packet_header >>
//        n_cols: be_u8 >>
//        columns: many_m_n!(1, n_cols as usize, call!(mysql_parse_column_definition2)) >>
//        eof: mysql_parse_eof_packet >>
//        rows: fold_many1!(call!(mysql_parse_resultset_row(n_cols)), Vec::new(), |mut rows: Vec<_>, r| {
//            rows.push(r);
//            rows
//        })
//        >>
//        (
//            MysqlResponse {
//                item: MysqlResponsePacket::ResultSet {
//                    header,
//                    n_cols,
//                    columns,
//                    eof,
//                    rows
//                }
//            }
//        )
//    ))
//);

fn mysql_parse_resultset(input: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (input, header) = mysql_parse_packet_header(input)?;
    let (input, n_cols) = be_u8(input)?;
    let (input, columns) = many_m_n!(1, n_cols as usize, call!(mysql_parse_column_definition2))?;

}

//named!(mysql_parse_resultset_row<&[u8], MysqlResultSetRow>,
//    do_parse!(
//        header: mysql_parse_packet_header >>
//        len: be_u8 >>
//        text: many_m_n!(1, 2 as usize,
//                do_parse!(
//                    len: be_u8 >>
//                    text: map!(take_str!(len), |s: &str| s.into())
//                    >>
//                    (text)
//                )
//              )
//        >>
//        (
//            MysqlResultSetRow {
//                header,
//                text
//            }
//        )
//    )
//);

named_args!(mysql_parse_resultset_row(n_cols: u8)<MysqlResultSetRow>,
    do_parse!(
        header: mysql_parse_packet_header >>
        len: be_u8 >>
        text: many_m_n!(1, n_cols as usize,
                do_parse!(
                    len: be_u8 >>
                    text: map!(take_str!(len), |s: &str| s.into())
                    >>
                    (text)
                )
              )
        >>
        (
            MysqlResultSetRow {
                header,
                text
            }
        )
    )
);


#[cfg(test)]
mod tests {

    use crate::mysql::parser::*;

    #[test]
    fn test_init_db() {
        let buf: &[u8] = &[
            0x05, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x73, 0x74
        ];

        match mysql_parse_request(buf) {
            Ok((_, req)) => {
                assert_eq!(req.header.pkt_len, 5);
                assert_eq!(req.header.pkt_num, 0);
                assert_eq!(req.command_code, 2);
                match req.command {
                    MysqlCommand::InitDb {ref schema} => {
                        assert_eq!(schema, "test");
                    }
                    _ => {
                        assert!(false);
                    }
                }
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_query_cmd() {
        let buf: &[u8] = &[
            0x0f, 0x00, 0x00, 0x00, 0x03, 0x73, 0x68, 0x6f,
            0x77, 0x20, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61,
            0x73, 0x65, 0x73
        ];

        match mysql_parse_request(buf) {
            Ok((_, req)) => {
                assert_eq!(req.header.pkt_len, 15);
                assert_eq!(req.header.pkt_num, 0);
                assert_eq!(req.command_code, 3);
                match req.command {
                    MysqlCommand::Query {ref query} => {
                        assert_eq!(query, "show databases");
                    }
                    _ => {
                        assert!(false);
                    }
                }
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_resultset_response() {
        let buf: &[u8] = &[
            0x01, 0x00, 0x00, 0x01, 0x01, 0x27, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65,
            0x66, 0x00, 0x00, 0x00, 0x11, 0x40, 0x40, 0x76, 0x65, 0x72, 0x73, 0x69,
            0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x00, 0x0c,
            0x21, 0x00, 0x4b, 0x00, 0x00, 0x00, 0xfd, 0x01, 0x00, 0x1f, 0x00, 0x00,
            0x05, 0x00, 0x00, 0x03, 0xfe, 0x00, 0x00, 0x02, 0x00,
            0x1a, 0x00, 0x00, 0x04, 0x19, 0x47, 0x65, 0x6e, 0x74, 0x6f, 0x6f, 0x20,
            0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x2d,
            0x35, 0x2e, 0x30, 0x2e, 0x35, 0x34
        ];

        match mysql_parse_response(buf, 0x03) {
            Ok((_, resp)) => {
                match resp.item {
                    MysqlResponsePacket::ResultSet {ref header, n_cols, ref columns, ref eof, ref rows} => {
                        assert_eq!(header.pkt_len, 1);
                        assert_eq!(header.pkt_num, 1);
                        assert_eq!(n_cols, 1);
                        assert_eq!(columns[0].header.pkt_len, 39);
                        assert_eq!(columns[0].header.pkt_num, 2);
                        assert_eq!(columns[0].catalog, "def");
                        assert_eq!(columns[0].decimals, 31);
                        assert_eq!(eof.header.pkt_len, 5);
                        assert_eq!(eof.header.pkt_num, 3);
                        assert_eq!(eof.warnings, 0);
                        assert_eq!(eof.status_flags, 2);
                        assert_eq!(rows[0].header.pkt_len, 26);
                        assert_eq!(rows[0].header.pkt_num, 4);
                        assert_eq!(rows[0].text, "Gentoo Linux mysql-5.0.54");
                    }
                    _ => {
                        assert!(false)
                    }
                }
            }
            _ => {
                assert!(false);
            }
        }
    }
//    #[test]
//    fn test_parse_request() {
//        let buf: &[u8] = &[
//            0x34, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x30, 0x2e, 0x35, 0x34,
//            0x00, 0x5e, 0x00, 0x00, 0x00, 0x3e, 0x7e, 0x24, 0x34, 0x75, 0x74,
//            0x68, 0x2c, 0x00, 0x2c, 0xa2, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e,
//            0x36, 0x31, 0x32, 0x49, 0x57, 0x5a, 0x3e, 0x66, 0x68, 0x57, 0x58,
//            0x00
//        ];
//
//        match mysql_parse_message(buf) {
//            Ok((_, msg)) => {
//                assert_eq!(msg.length, &[0x34, 0x00, 0x00]);
//                assert_eq!(msg.sequence_id, &[0x00]);
//                match msg.payload {
//                    MysqlFunction::Handshake {
//                        protocol,
//                        version,
//                        conn_id,
//                        salt1,
//                        capability_flag1,
//                        character_set,
//                        status_flags,
//                        capability_flags2,
//                        auth_plugin_len,
//                        salt2,
//                        auth_plugin_data
//                    } => {
//                        assert_eq!(protocol, 10);
//                        assert_eq!(version, "5.0.54");
//                        assert_eq!(conn_id, 94);
//                        assert_eq!(salt1, ">~$4uth,");
//                        assert_eq!(capability_flag1, 0xa22c);
//                        assert_eq!(character_set, 0x21);
//                        assert_eq!(status_flags, 0x0002);
//                        assert_eq!(capability_flags2, 0x0000);
//                        assert_eq!(auth_plugin_len, 0);
//                        assert_eq!(salt2, ">612IWZ>fhWX");
//                        assert_eq!(auth_plugin_data, None);
//                    }
//                    _ => {
//                        assert!(false);
//                    }
//                }
//            }
//            _ => {
//                assert!(false);
//            }
//        }
//    }

//    #[test]
//    fn test_parse_handshake_response() {
//        let buf: &[u8] = &[
//            0x3e, 0x00, 0x00, 0x01, 0x85, 0xa6, 0x03, 0x00, 0x00, 0x00, 0x00,
//            0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//            0x00, 0x00, 0x00, 0x74, 0x66, 0x6f, 0x65, 0x72, 0x73, 0x74, 0x65,
//            0x00, 0x14, 0xee, 0xfd, 0x6d, 0x55, 0x62, 0x85, 0x1b, 0xc5, 0x96,
//            0x6a, 0x0b, 0x41, 0x23, 0x6a, 0xe3, 0xf2, 0x31, 0x5e, 0xfc, 0xc4
//        ];
//
//        match mysql_parse_handshake_response(buf) {
//            Ok((_, response)) => {
//                match response {
//                    MysqlFunction::HandshakeResponse {
//                        capability_flags1,
//                        capability_flags2,
//                        max_packet_size,
//                        character_set,
//                        username,
//                        password
//                    } => {
//                        assert_eq!(capability_flags1, 0xa685);
//                        assert_eq!(max_packet_size, 16777216);
//                        assert_eq!(character_set, 0x21);
//                        assert_eq!(username, "tfoerste");
//                        assert_eq!(password, vec![0xee, 0xfd, 0x6d, 0x55, 0x62,
//                                                  0x85, 0x1b, 0xc5, 0x96, 0x6a,
//                                                  0x0b, 0x41, 0x23, 0x6a, 0xe3,
//                                                  0xf2, 0x31, 0x5e, 0xfc, 0xc4]);
//                    }
//                    _ => {
//                        assert!(false);
//                    }
//                }
//            }
//            _ => {
//                assert!(false);
//            }
//        }
//
//    }
}
