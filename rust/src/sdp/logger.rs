/* Copyright (C) 2024 Open Information Security Foundation
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

use crate::jsonbuilder::{JsonBuilder, JsonError};

use super::parser::{ConnectionData, MediaDescription, SdpMessage};

pub fn sdp_log(msg: &SdpMessage, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.set_uint("version", msg.version as u64)?;

    js.open_object("origin")?;
    js.set_string("username", &msg.origin.username)?;
    js.set_string("session_id", &msg.origin.sess_id)?;
    js.set_string("session_version", &msg.origin.sess_version)?;
    js.set_string("nettype", &msg.origin.nettype)?;
    js.set_string("addrtype", &msg.origin.addrtype)?;
    js.set_string("unicast_address", &msg.origin.unicast_address)?;
    js.close()?;

    js.set_string("session_name", &msg.session_name)?;

    if let Some(session_info) = &msg.session_info {
        js.set_string("session_info", session_info)?;
    }
    if let Some(uri) = &msg.uri {
        js.set_string("uri", uri)?;
    }
    if let Some(email) = &msg.email {
        js.set_string("email", email)?;
    }
    if let Some(phone_number) = &msg.phone_number {
        js.set_string("phone_number", phone_number)?;
    }
    if let Some(conn_data) = &msg.connection_data {
        log_connection_data(conn_data, js)?;
    }
    if let Some(bws) = &msg.bandwidths {
        log_bandwidth(bws, js)?;
    }
    js.set_string("t", &msg.time)?;
    if let Some(repeat_time) = &msg.time_zone {
        js.set_string("r", repeat_time)?;
    }
    if let Some(tz) = &msg.time_zone {
        js.set_string("z", tz)?;
    }
    if let Some(enc_key) = &msg.encryption_key {
        js.set_string("k", enc_key)?;
    }
    if let Some(attrs) = &msg.attributes {
        log_attributes(attrs, js)?;
    }
    if let Some(media) = &msg.media_description {
        log_media_description(media, js)?;
    }
    Ok(())
}

fn log_media_description(
    media: &Vec<MediaDescription>, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    if !media.is_empty() {
        js.open_array("m")?;
        for m in media {
            js.start_object()?;
            js.set_string("media", &m.media)?;
            let port = if let Some(num_ports) = m.number_of_ports {
                format!("{}/{}", m.port, num_ports)
            } else {
                format!("{}", m.port)
            };
            js.set_string("port", &port)?;
            js.set_string("protocol", &m.proto)?;

            js.open_array("fmt")?;
            for f in &m.fmt {
                js.append_string(f)?;
            }
            js.close()?;

            if let Some(session_info) = &m.session_info {
                js.set_string("session_info", session_info)?;
            };
            if let Some(bws) = &m.bandwidths {
                log_bandwidth(bws, js)?;
            }
            if let Some(conn_data) = &m.connection_data {
                log_connection_data(conn_data, js)?;
            }
            if let Some(attrs) = &m.attributes {
                log_attributes(attrs, js)?;
            }
            js.close()?;
        }
    }
    js.close()?;

    Ok(())
}

fn log_bandwidth(bws: &Vec<String>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if !bws.is_empty() {
        js.open_array("b")?;
        for bw in bws {
            js.append_string(bw)?;
        }
        js.close()?;
    }
    Ok(())
}

fn log_connection_data(conn_data: &ConnectionData, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("c")?;
    js.set_string("nettype", &conn_data.nettype)?;
    js.set_string("addrtype", &conn_data.addrtype)?;
    js.set_string("address", &conn_data.connection_address.to_string())?;
    if let Some(ttl) = conn_data.ttl {
        js.set_uint("ttl", ttl as u64)?;
    }
    if let Some(num_addrs) = conn_data.number_of_addresses {
        js.set_uint("number_of_addresses", num_addrs as u64)?;
    }
    js.close()?;
    Ok(())
}

fn log_attributes(attrs: &Vec<String>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if !attrs.is_empty() {
        js.open_array("a")?;
        for attr in attrs {
            js.append_string(attr)?;
        }
        js.close()?;
    }
    Ok(())
}
