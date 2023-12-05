use nom7::bytes::complete::{take, take_till};
use nom7::combinator::{cond, map, verify};
use nom7::number::complete::{be_u16, be_u24, be_u8, le_u16, le_u32};
use nom7::IResult;
use std;

const CLIENT_PLUGIN_AUTH: u64 = 0x8000;

#[derive(Debug)]
pub struct MysqlPacket {
    pub pkt_len: u32,
    pub pkt_num: u8,
}

#[derive(Debug)]
pub struct MysqlHandshakeRequest<'a> {
    pub header: MysqlPacket,
    pub protocol: u8,
    pub version: &'a [u8],
    pub conn_id: u32,
    pub salt1: &'a [u8],
    pub capability_flags1: u16,
    pub character_set: u8,
    pub status_flags: u16,
    pub capability_flags2: u16,
    pub auth_plugin_len: u8,
    pub salt2: &'a [u8],
    pub auth_plugin_data: Option<&'a [u8]>,
}

#[derive(Debug)]
pub struct MysqlHandshakeResponse<'a> {
    pub header: MysqlPacket,
    pub client_flags: u32,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: &'a [u8],
    pub auth_response: &'a [u8],
    pub database: &'a [u8],
    pub client_plugin_name: &'a [u8],
}

pub fn mysql_parse_handshake<'a>(i: &'a [u8]) -> IResult<&'a [u8], MysqlHandshakeRequest<'a>> {
    let (i, pkt_len) = be_u24(i)?;
    let (i, pkt_num) = be_u8(i)?;
    let (i, protocol) = verify(be_u8, |x| *x == 0x0a as u8)(i)?;
    let (i, version) = take_till(|ch| ch == 0x00)(i)?;
    let (i, _) = take(1_usize)(i)?;
    let (i, conn_id) = le_u32(i)?;
    let (i, salt1) = take(8_usize)(i)?;
    let (i, _) = take(1_usize)(i)?;
    let (i, capability_flags1) = le_u16(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, status_flags) = le_u16(i)?;
    let (i, capability_flags2) = be_u16(i)?;
    let (i, auth_plugin_len) = be_u8(i)?;
    let (i, _) = take(10_usize)(i)?;
    let (i, salt2) = take_till(|ch| ch == 0x00)(i)?;
    let (i, auth_plugin_data) = cond(auth_plugin_len > 0, take_till(|ch| ch == 0x00))(i)?;

    Ok((
        i,
        MysqlHandshakeRequest {
            header: MysqlPacket { pkt_len, pkt_num },
            protocol: 0x0a,
            version,
            conn_id,
            salt1,
            capability_flags1,
            character_set,
            status_flags,
            capability_flags2,
            auth_plugin_len,
            salt2,
            auth_plugin_data,
        },
    ))
}

pub fn mysql_parse_handshake_response<'a>(i: &'a [u8]) -> IResult<&'a [u8], MysqlHandshakeResponse<'a>> {
    let (i, pkt_len) = be_u24(i)?;
    let (i, pkt_num) = be_u8(i)?;
    let (i, client_flags) = be_u32(i)?;
    let (i, max_packet_size) = be_u32(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, _) = take(23)(i)?;
    let (i, username) = take_till(|ch| ch == 0x00)(i)?;
}
