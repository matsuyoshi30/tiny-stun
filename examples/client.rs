use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr};
use tinystun::message::*;

#[tokio::main]
async fn main() {
    let stun_server_address = "stun.l.google.com:19302";
    stun_request(stun_server_address).await;
}

async fn stun_request(stun_server_address: &str) {
    let mut msg = Message::new(MessageClass::Request, MessageMethod::Binding);

    let socket = UdpSocket::bind("0.0.0.0:34255").expect("couldn't bind to address");
    socket
        .connect(stun_server_address)
        .expect("couldn't connect to address");
    socket.send(&msg.encode()).expect("couldn't send message");

    let mut buf = [0; 100];
    let mut receive_bytes = 0;
    match socket.recv(&mut buf) {
        Ok(received) => receive_bytes = received,
        Err(e) => println!("recv function failed: {:?}", e),
    }
    if let Some((ipaddr, port)) = decode_response(&buf[..receive_bytes]) {
        println!("Global IP: {:?}:{:?}", ipaddr, port)
    }
}

#[derive(Debug, PartialEq)]
enum StunAttributeType {
    MappedAddress,
    XorMappedAddress,
    Unknown(u16),
}

impl From<u16> for StunAttributeType {
    fn from(value: u16) -> Self {
        // https://datatracker.ietf.org/doc/html/rfc5389#section-18.2
        match value {
            0x0001 => StunAttributeType::MappedAddress,
            0x0020 => StunAttributeType::XorMappedAddress,
            _ => StunAttributeType::Unknown(value),
        }
    }
}
fn decode_response(response: &[u8]) -> Option<(IpAddr, u16)> {
    let magic_cookie = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    let mut offset = 20; // skip header

    while offset < response.len() {
        // https://datatracker.ietf.org/doc/html/rfc5389#section-15
        //
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |         Type                  |            Length             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                         Value (variable)                ....
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let attribute_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attribute_length = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let attribute_value = &response[offset + 4..offset + 4 + attribute_length as usize];

        match StunAttributeType::from(attribute_type) {
            StunAttributeType::MappedAddress => {
                // MAPPED-ADDRESS
                //
                // https://datatracker.ietf.org/doc/html/rfc5389#section-15.1
                //
                // 0                   1                   2                   3
                // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |0 0 0 0 0 0 0 0|    Family     |           Port                |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                                                               |
                // |                 Address (32 bits or 128 bits)                 |
                // |                                                               |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                if attribute_value[1] == 0x01 {
                    // IPv4
                    let port = u16::from_be_bytes([attribute_value[2], attribute_value[3]]);
                    let ip = Ipv4Addr::new(
                        attribute_value[4],
                        attribute_value[5],
                        attribute_value[6],
                        attribute_value[7],
                    );
                    return Some((IpAddr::V4(ip), port));
                }
                // TODO: IPv6
            }
            StunAttributeType::XorMappedAddress => {
                // XOR-MAPPED-ADDRESS
                //
                // https://datatracker.ietf.org/doc/html/rfc5389#section-15.2
                //
                // 0                   1                   2                   3
                // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |x x x x x x x x|    Family     |         X-Port                |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |                X-Address (Variable)
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                if attribute_value[1] == 0x01 {
                    // IPv4
                    let port = u16::from_be_bytes([attribute_value[2], attribute_value[3]])
                        ^ (magic_cookie >> 16) as u16;
                    let ip_bytes = [
                        attribute_value[4] ^ (magic_cookie.to_be_bytes()[0]),
                        attribute_value[5] ^ (magic_cookie.to_be_bytes()[1]),
                        attribute_value[6] ^ (magic_cookie.to_be_bytes()[2]),
                        attribute_value[7] ^ (magic_cookie.to_be_bytes()[3]),
                    ];
                    let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                    return Some((IpAddr::V4(ip), port));
                }
                // TODO: IPv6
            }
            _ => {}
        }

        offset += 4 + attribute_length as usize;
    }

    None
}
