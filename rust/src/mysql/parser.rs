use nom7::bytes::complete::{take, take_till, take_until};
use nom7::combinator::{cond, map, verify};
use nom7::number::complete::{be_u16, be_u24, be_u8, be_u32, le_u16, le_u24, le_u32};
use nom7::IResult;
use std;

const CLIENT_CONNECT_WITH_DB: u32 = BIT_U32!(3);
const CLIENT_PLUGIN_AUTH: u32 = BIT_U32!(19);

#[derive(Debug)]
pub struct MysqlHeader {
    pub pkt_len: u32,
    pub pkt_num: u8,
}

#[derive(Debug)]
pub struct MysqlHandshakeRequest<'a> {
    pub hdr: MysqlHeader,
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
    pub hdr: MysqlHeader,
    pub client_flags1: u16,
    pub client_flags2: u16,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: &'a [u8],
    pub password: &'a [u8],
    //pub auth_response: &'a [u8],
    pub database: Option<&'a [u8]>,
    //pub client_plugin_name: &'a [u8],
}

#[derive(Debug)]
pub struct MysqlSSLRequest {
    pub hdr: MysqlHeader,
    pub client_flags: u32,
    pub max_packet_size: u32,
    pub character_set: u8,
}

pub fn mysql_parse_header(i: &[u8]) -> IResult<&[u8], MysqlHeader> {
    let (i, pkt_len) = le_u24(i)?;
    let (i, pkt_num) = be_u8(i)?;

    Ok((i, MysqlHeader {
        pkt_len,
        pkt_num,
    }))
}

pub fn mysql_parse_handshake<'a>(i: &'a [u8]) -> IResult<&'a [u8], MysqlHandshakeRequest<'a>> {
    let (i, hdr) = mysql_parse_header(i)?;
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
            hdr,
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
    let (i, hdr) = mysql_parse_header(i)?;
    let (i, client_flags1) = le_u16(i)?;
    let (i, client_flags2) = le_u16(i)?;
    let (i, max_packet_size) = le_u32(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, _) = take(23_usize)(i)?;
    let (i, username) = take_until("\x00")(i)?;
    let (i, _) = be_u8(i)?;
    let (i, pwd_len) = be_u8(i)?;
    let (i, password) = take(pwd_len)(i)?;
    let (i, database) = cond(client_flags1 as u32 & CLIENT_CONNECT_WITH_DB != 0, take_till(|ch| ch == 0x00))(i)?;

    Ok((i, MysqlHandshakeResponse {
        hdr,
        client_flags1,
        client_flags2,
        max_packet_size,
        character_set,
        username,
        password,
        database,
    }))
}

pub fn mysql_parse_ssl_request(i: &[u8]) -> IResult<&[u8], MysqlSSLRequest> {
    let (i, hdr) = mysql_parse_header(i)?;
    let (i, client_flags) = be_u32(i)?;
    let (i, max_packet_size) = be_u32(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, _) = take(23_usize)(i)?;

    Ok((i, MysqlSSLRequest {
        hdr,
        client_flags,
        max_packet_size,
        character_set,
    }))
}

#[cfg(test)]
mod tests {

    use crate::mysql::parser::*;

    #[test]
    fn test_parse_handshake_request() {
        let buf: &[u8] = &[
            0x34, 0x00, 0x00, 0x00, 0x0a, 0x34, 0x2e, 0x31, 
            0x2e, 0x32, 0x32, 0x00, 0x18, 0x00, 0x00, 0x00, 
            0x2e, 0x7d, 0x4e, 0x4f, 0x7e, 0x4f, 0x51, 0x26, 
            0x00, 0x2c, 0xa2, 0x08, 0x02, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x68, 0x5a, 0x6c, 0x30, 0x46, 
            0x52, 0x47, 0x50, 0x3a, 0x6e, 0x40, 0x32, 0x00            
        ];

        match mysql_parse_handshake(buf) {
            Ok((_, req)) => {
                assert_eq!(req.hdr.pkt_len, 52);
                assert_eq!(req.hdr.pkt_num, 0);
                assert_eq!(String::from_utf8(req.version.to_vec()).unwrap(), "4.1.22");
                assert_eq!(req.conn_id, 24);
                assert_eq!(String::from_utf8(req.salt1.to_vec()).unwrap(), ".}NO~OQ&");
                assert_eq!(req.capability_flags1, 0xa22c);
                assert_eq!(req.character_set, 0x08);
                assert_eq!(req.status_flags, 0x0002);
                assert_eq!(req.capability_flags2, 0x0000);
                assert_eq!(req.auth_plugin_len, 0x00);
                assert_eq!(String::from_utf8(req.salt2.to_vec()).unwrap(), "hZl0FRGP:n@2");
            },
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_parse_handshake_response() {
        let buf: &[u8] = &[
            0x40, 0x00, 0x00, 0x01, 0x8d, 0xa6, 0x03, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
            0x6e, 0x00, 0x14, 0x5f, 0x28, 0xee, 0xab, 0x88,
            0xbf, 0xc7, 0x39, 0x93, 0x8d, 0xb3, 0x14, 0x59,
            0x1f, 0xf3, 0xf9, 0x50, 0x1e, 0x8c, 0xd5, 0x74,
            0x65, 0x73, 0x74, 0x00
        ];

        match mysql_parse_handshake_response(buf) {
            Ok((_, resp)) => {
                assert_eq!(resp.hdr.pkt_len, 64);
                assert_eq!(resp.hdr.pkt_num, 1);
                assert_eq!(resp.client_flags1, 0xa68d);
                assert_eq!(resp.client_flags2, 0x0003);
                assert_eq!(resp.max_packet_size, 16777216);
                assert_eq!(resp.character_set, 0x08);
                assert_eq!(String::from_utf8(resp.username.to_vec()).unwrap(), "admin");
                assert_eq!(resp.password, &[0x5f, 0x28, 0xee, 0xab, 0x88, 0xbf, 0xc7, 0x39,
                    0x93, 0x8d, 0xb3, 0x14, 0x59, 0x1f, 0xf3, 0xf9,
                    0x50, 0x1e, 0x8c, 0xd5]);
                assert_eq!(String::from_utf8(resp.database.unwrap().to_vec()).unwrap(), "test");
            },
            _ => {
                assert!(false);
            }
        }
    }
}
