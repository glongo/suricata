use nom::*;
use nom::{crlf, IResult};
use std;

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

pub fn mysql_parse_handshake(i: &[u8]) -> IResult<&[u8], MysqlHandshakeRequest> {
    let (i, pkt_len) = be_u24(i)?;
    let (i, pkt_num) = be_u8(i)?;
    let (i, protocol) = verify(be_u8, |x| x == 0x0a as u8)(i)?;
    let (i, version) = map(take_till(|ch| ch == 0x00), |s: &[u8]| String::from_utf8(s.to_vec()).unwrap())(i)?;
    let (i, _) = take(1)(i)?;
    let (i, conn_id) = le_u32(i)?;
    let (i, salt1) = map(take_str(8), |s: &str| s.into())(i)?;
    let (i, _) = take(1)(i)?;
    let (i, capability_flags1) = le_u16(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, status_flags) = le_u16(i)?;
    let (i, capability_flags2) = be_u16(i)?;
    
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