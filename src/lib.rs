const PIPE_IFAC_SIZE: usize = 8;

#[derive(Debug)]
enum PropagationType {
    BROADCAST,
    TRANSPORT,
    RESERVED,
    RESERVED2,
}

#[derive(Debug)]
enum DestinationType {
    SINGLE,
    GROUP,
    PLAIN,
    LINK,
}

#[derive(Debug)]
enum PacketType {
    DATA,
    ANNOUNCE,
    LINKREQUEST,
    PROOF,
}

enum Context {
    NONE,
    RESOURCE,
    RESOUCE_ADV,
    RESOURCE_REQ,
    RESOURCE_HMU,
    RESOURCE_PRF,
    RESOURCE_UCL,
    RESOURCE_RCL,
    CACHE_REQUEST,
    REQUEST,
    RESPONSE,
    PATH_RESPONSE,
    COMMAND,
    COMMAND_STATUS,
    KEEPALIVE,
    LINKIDENTIFY,
    LINKCLOSE,
    LINKPROOF,
    LRRTT,
    LRPROOF,
}

pub struct Packet {
    header: u8,
    hops: u8,
    iac: Vec<u8>,
    addresses: Vec<u8>,
    context: u8,
    data: Vec<u8>,
    propagation_type: PropagationType,
    destination_type: DestinationType,
    packet_type: PacketType,
}

impl Packet {
    pub fn debug_packet(self, verbose: bool) {
        if (self.header & 0b10000000) >> 7 != 0 {
            eprintln!("IFAC bit is set and the Access Code is {:02X?}", self.iac);
        }
        eprintln!("Addresses: {:02X?}", self.addresses);
        eprintln!("Hops: {:?}, Header Type: {:?}, Context: 0x{:02X?}, Destination Type: {:?}, Propagation Type: {:?}, Packet Type: {:?}", self.hops, ((self.header & 0b01000000) >> 6) + 1, self.context, self.destination_type, self.propagation_type, self.packet_type);
        if verbose {
            eprintln!("Data: {:02X?}", self.data)
        }
    }
}

//pub fn parse_packet(raw_packet: &[u8]) -> Result<Packet, String> {
pub fn parse_packet(raw_packet: Vec<u8>) -> Result<Packet, String> {
    let mut packet = raw_packet;
    let mut t = vec![];

    for (i, v) in packet.iter().enumerate() {
        if v == &0x7d {
            t.push(i);
        }
    }
    packet.retain(|&x| x != 0x7d);

    for (i, v) in t.iter().enumerate() {
        packet[v - i] ^= 0x20;
    }

    let ifac = (packet[0] & 0b10000000) >> 7;
    let mut ifac_size = 0;
    let iac = if ifac != 0 {
        ifac_size = PIPE_IFAC_SIZE;
        Vec::from(&packet[2..2 + ifac_size])
    } else {
        vec![0; 0]
    };
    let num_addr = if ((packet[0] & 0b01000000) >> 6) == 0 {
        16
    } else {
        32
    };

    let propagation_type: PropagationType = match (packet[0] & 0b00110000) >> 4 {
        0 => PropagationType::BROADCAST,
        1 => PropagationType::TRANSPORT,
        2 => PropagationType::RESERVED,
        _ => PropagationType::RESERVED2,
    };

    let destination_type: DestinationType = match (packet[0] & 0b00001100) >> 2 {
        0 => DestinationType::SINGLE,
        1 => DestinationType::GROUP,
        2 => DestinationType::PLAIN,
        _ => DestinationType::LINK,
    };

    let packet_type: PacketType = match packet[0] & 0b00000011 {
        0 => PacketType::DATA,
        1 => PacketType::ANNOUNCE,
        2 => PacketType::LINKREQUEST,
        _ => PacketType::PROOF,
    };

    let addresses = Vec::from(&packet[2 + ifac_size..2 + ifac_size + num_addr]);
    let context = packet[2 + ifac_size + num_addr];
    let data = Vec::from(&packet[3 + ifac_size + num_addr..]);

    Ok(Packet {
        header: packet[0],
        hops: packet[1],
        iac,
        addresses,
        context,
        data,
        propagation_type,
        destination_type,
        packet_type,
    })
}
