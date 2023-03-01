//! A parser for Reticulum packets
use std::fmt::Write;

#[derive(Debug)]
enum PropagationType {
    Broadcast,
    Transport,
    Reserved,
    Reserved2,
}

#[derive(Debug)]
enum DestinationType {
    Single,
    Group,
    Plain,
    Link,
}

#[derive(Debug, PartialEq)]
enum PacketType {
    Data,
    Announce,
    Linkrequest,
    Proof,
}

#[derive(Debug, PartialEq)]
enum Context {
    None,
    Resource,
    ResourceAdv,
    ResourceReq,
    ResourceHmu,
    ResourcePrf,
    ResourceIcl,
    ResourceRcl,
    CacheRequest,
    Request,
    Response,
    PathResponse,
    Command,
    CommandStatus,
    Keepalive,
    Linkidentify,
    Linkclose,
    Linkproof,
    Lrrtt,
    Lrproof,
    NotImplemented,
}

/// A struct that represents a packet. It's a deserialized packet, stripped from
/// any start/end bytes, as well as any HDLC/KISS framing.
pub struct Packet {
    header: u8,
    hops: u8,
    iac: Vec<u8>,
    address: [u8; 16],
    hop_address: [u8; 16],
    context: u8,
    data: Vec<u8>,
    propagation_type: PropagationType,
    destination_type: DestinationType,
    packet_type: PacketType,
    context_type: Context,
}

#[derive(Debug)]
pub struct Announcement {
    public_key: [u8; 64],
    hash_name: [u8; 10],
    random_hash: [u8; 10],
    signature: [u8; 64],
    app_data: Vec<u8>,
}

impl Announcement {
    pub fn debug_announcement(&self) -> String {
        let mut announcement_fmt = String::from("");
        announcement_fmt.push_str(
            format!(
                "App data as UTF-8 {:?}, App data raw {:02X?}",
                String::from_utf8_lossy(&self.app_data),
                self.app_data
            )
            .as_str(),
        );
        announcement_fmt
    }
}

impl Packet {
    pub fn debug_packet(&self, verbose: usize) -> String {
        let mut packet_info = String::from("");
        if (self.header & 0b10000000) >> 7 != 0 {
            packet_info.push_str(
                format!("IFAC bit is set and the Access Code is {:02X?} ", self.iac).as_str(),
            );
        }
        if self.is_hop() {
            packet_info
                .push_str(format!("Hop Address: {}, ", bytes_to_hex(&self.hop_address)).as_str());
        }
        packet_info.push_str(format!("Address: {}, Hops: {:?}, Header Type: {:?}, Context: {:?}, Destination Type: {:?}, Propagation Type: {:?}, Packet Type: {:?}", bytes_to_hex(&self.address), self.hops, ((self.header & 0b01000000) >> 6) + 1, self.context_type, self.destination_type, self.propagation_type, self.packet_type).as_str());
        if verbose != 0 {
            let mut limit = verbose;
            if limit > self.data.len() {
                limit = self.data.len();
            }
            packet_info.push_str(format!(" Data: {:02X?}", &self.data[..limit]).as_str());
        }
        packet_info
    }

    pub fn parse_announce(&self) -> Result<Announcement, String> {
        if self.packet_type != PacketType::Announce || self.data.len() < 148 {
            return Err(String::from("Invalid announce packet"));
        }
        let public_key = self.data[0..64].try_into().unwrap();
        let hash_name = self.data[64..74].try_into().unwrap();
        let random_hash = self.data[74..84].try_into().unwrap();
        let signature = self.data[84..148].try_into().unwrap();
        let app_data = self.data[148..].to_vec();
        Ok(Announcement {
            public_key,
            hash_name,
            random_hash,
            signature,
            app_data,
        })
    }

    pub fn address(&self) -> [u8; 16] {
        self.address
    }

    pub fn hop_address(&self) -> [u8; 16] {
        self.hop_address
    }

    pub fn is_hop(&self) -> bool {
        if self.hop_address != [0; 16] {
            return true;
        }
        false
    }
}

//TODO: This needs to be modular so it supports other encodings (KISS) as well
fn decode_packet(mut packet: Vec<u8>) -> Result<Vec<u8>, String> {
    if packet[0] != 0x7e
        || packet.last() != Some(&0x7e)
        || packet.iter().filter(|&b| *b == 0x7e).count() != 2
    {
        return Err(String::from("Invalid packet"));
    }
    packet.retain(|&x| x != 0x7e);

    if packet.last() == Some(&0x7d) {
        return Err(String::from(
            "Invalid packet, escape character at the end of the packet",
        ));
    }

    let mut t = vec![];
    for (i, v) in packet.iter().enumerate() {
        if v == &0x7d {
            t.push(i);
            match packet[i + 1] {
                0x5d | 0x5e => continue,
                _ => {
                    return Err(String::from(
                        "Invalid packet, illegal escaped bytes following escape character",
                    ))
                }
            }
        }
    }
    packet.retain(|&x| x != 0x7d);

    for (i, v) in t.iter().enumerate() {
        packet[v - i] ^= 0x20;
    }
    Ok(packet)
}

/// Try to parse a `Vec<u8>` as a Reticulum packet.
///
/// The Python reference implementation of Reticulum prepares bytes to be send
/// over the wire in two different steps. First step is to create the packet,
/// this is the same for all interfaces. The second step is encoding the packet
/// according to Interface specific requirements.
///
/// This function accepts a `Vec<u8>` and a tuple. The `Vec<u8>` is the byte
/// representation of the packet and it can either be HDLC framed and escaped or
/// just raw bytes.
///
/// The tuple takes three arguments: A bool to signal if the packet is framed or
/// not, a string for the IFAC password and a usize for the number of bytes of
/// IFAC. The IFAC settings are currently ignored.
pub fn parse_packet(
    raw_packet: Vec<u8>,
    packet_options: (bool, &String, &usize),
) -> Result<Packet, String> {
    let mut packet = raw_packet;
    let (decode, ifac, ifac_size) = packet_options;

    if packet.len() < 5 {
        return Err(String::from("Invalid packet, packet length is too small"));
    }

    if decode {
        packet = decode_packet(packet)?;
    }

    let size_addr = if ((packet[0] & 0b01000000) >> 6) == 0 {
        16
    } else {
        32
    };

    // We need one byte for the header, one for the context and one for the hops. The rest are
    // calculated based on packet information.
    if packet.len() < 3 + size_addr + ifac_size {
        return Err(String::from("Invalid packet, packet length is too small"));
    }

    let ifac_bit = (packet[0] & 0b10000000) >> 7;
    if ifac_bit == 1 && ifac.is_empty() {
        return Err(String::from("IFAC bit is set but no IFAC string provided"));
    }

    let iac = if ifac_bit != 0 {
        Vec::from(&packet[2..2 + ifac_size])
    } else {
        vec![0; 0]
    };

    let propagation_type: PropagationType = match (packet[0] & 0b00110000) >> 4 {
        0 => PropagationType::Broadcast,
        1 => PropagationType::Transport,
        2 => PropagationType::Reserved,
        _ => PropagationType::Reserved2,
    };

    let destination_type: DestinationType = match (packet[0] & 0b00001100) >> 2 {
        0 => DestinationType::Single,
        1 => DestinationType::Group,
        2 => DestinationType::Plain,
        _ => DestinationType::Link,
    };

    let packet_type: PacketType = match packet[0] & 0b00000011 {
        0 => PacketType::Data,
        1 => PacketType::Announce,
        2 => PacketType::Linkrequest,
        _ => PacketType::Proof,
    };

    let context_type: Context = match packet[2 + ifac_size + size_addr] {
        0x00 => Context::None,
        0x01 => Context::Resource,
        0x02 => Context::ResourceAdv,
        0x03 => Context::ResourceReq,
        0x04 => Context::ResourceHmu,
        0x05 => Context::ResourcePrf,
        0x06 => Context::ResourceIcl,
        0x07 => Context::ResourceRcl,
        0x08 => Context::CacheRequest,
        0x09 => Context::Request,
        0x0A => Context::Response,
        0x0B => Context::PathResponse,
        0x0C => Context::Command,
        0x0D => Context::CommandStatus,
        0xFA => Context::Keepalive,
        0xFB => Context::Linkidentify,
        0xFC => Context::Linkclose,
        0xFD => Context::Linkproof,
        0xFE => Context::Lrrtt,
        0xFF => Context::Lrproof,
        _ => Context::NotImplemented,
    };

    if context_type == Context::NotImplemented {
        return Err(format!(
            "Invalid context type {:?}",
            packet[2 + ifac_size + size_addr]
        ));
    }

    let address: [u8; 16];
    let mut hop_address: [u8; 16] = [0; 16];
    if size_addr == 32 {
        hop_address = packet[2 + ifac_size..18 + ifac_size].try_into().unwrap();
        address = packet[18 + ifac_size..2 + ifac_size + size_addr]
            .try_into()
            .unwrap();
    } else {
        address = packet[2 + ifac_size..2 + ifac_size + size_addr]
            .try_into()
            .unwrap();
    }
    let context = packet[2 + ifac_size + size_addr];
    let data = Vec::from(&packet[3 + ifac_size + size_addr..]);

    Ok(Packet {
        header: packet[0],
        hops: packet[1],
        iac,
        address,
        hop_address,
        context,
        data,
        propagation_type,
        destination_type,
        packet_type,
        context_type,
    })
}

fn bytes_to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for i in input {
        write!(s, "{i:02X}").unwrap();
    }
    s
}
