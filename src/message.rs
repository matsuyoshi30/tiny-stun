use rand::Rng;

// https://datatracker.ietf.org/doc/html/rfc5389#section-6
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |0 0|     STUN Message Type     |         Message Length        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Magic Cookie                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                     Transaction ID (96 bits)                  |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

const BYTE: usize = 8;
const TRANSACTION_ID_SIZE: usize = 96 / BYTE;

#[derive(Debug)]
struct Header {
    message_type: MessageType,
    message_length: u16,
    magic_cookie: u32,
    transaction_id: [u8; TRANSACTION_ID_SIZE],
}

// Figure 3: Format of STUN Message Type Field
//
// 0                 1
// 2  3  4 5 6 7 8 9 0 1 2 3 4 5
//
// +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
// |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
// |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
// +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug)]
struct MessageType {
    message_class: MessageClass,
    message_method: MessageMethod,
}

#[derive(Clone, Debug)]
pub enum MessageClass {
    Request = 0x00,
}

#[derive(Clone, Debug)]
pub enum MessageMethod {
    Binding = 0x001,
}

#[derive(Debug)]
pub struct Message {
    header: Header,
}

const MAGIC_COOKIE: u32 = 0x2112A442;

impl Message {
    pub fn new(class: MessageClass, method: MessageMethod) -> Self {
        let mut transaction_id = [0; TRANSACTION_ID_SIZE];
        rand::thread_rng().fill(&mut transaction_id);
        Message {
            header: Header {
                message_type: MessageType {
                    message_class: class,
                    message_method: method,
                },
                message_length: 0,
                magic_cookie: MAGIC_COOKIE,
                transaction_id,
            },
        }
    }

    pub fn encode(&mut self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let message_type = self.get_message_type();
        buffer.extend_from_slice(&message_type.to_be_bytes());
        buffer.extend_from_slice(&self.header.message_length.to_be_bytes());
        buffer.extend_from_slice(&self.header.magic_cookie.to_be_bytes());
        buffer.extend_from_slice(&self.header.transaction_id);
        buffer
    }

    fn get_message_type(&self) -> u16 {
        let class_value = self.header.message_type.message_class.clone() as u16;
        let method_value = self.header.message_type.message_method.clone() as u16;
        (class_value << 14) | (method_value & 0x3FFF)
    }
}
