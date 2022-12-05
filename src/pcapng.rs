use std::collections::HashMap;
use std::collections::hash_map::Entry as HashMapEntry;
use std::fmt;
use std::io::{self, Write};

use crate::ndiscap::{Encapsulation, PacketDataEvent};


/// The timestamp resolution stored in the pcapng files, with n representing a resolution of
/// 10**(-n) seconds.
///
/// Windows events use the timestamp format recording the number of 100ns units since 1601-01-01
/// 00:00:00; 100ns = 10**(-7) seconds, so store 7.
const TIMESTAMP_RESOLUTION: u8 = 7;


/// An error that can occur during pcapng serialization.
#[derive(Debug)]
pub enum PcapngSerError {
    /// An encapsulation mismatch occurred.
    EncapMismatch {
        miniport_if_index: u32,
        lower_if_index: u32,
        previous_encap: Encapsulation,
        sudden_encap: Encapsulation,
    },

    /// A name does not fit into the size allowed by the pcapng file format.
    NameTooLong(String),

    /// Due to the length of data items, a header is too large for the pcapng file format.
    BlockTooLong,

    /// The interface of a packet is missing from the list of interfaces.
    InterfaceNotFound {
        miniport_if_index: u32,
        lower_if_index: u32,
    },

    /// An I/O error occurred.
    Io(io::Error),
}
impl fmt::Display for PcapngSerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncapMismatch { miniport_if_index, lower_if_index, previous_encap, sudden_encap }
                => write!(
                    f, "encapsulation mismatch for miniport_if_index={} lower_if_index={} -- previously {:?}, now suddenly {:?}",
                    miniport_if_index, lower_if_index, previous_encap, sudden_encap,
                ),
            Self::NameTooLong(n)
                => write!(f, "name {:?} does not fit", n),
            Self::BlockTooLong
                => write!(f, "header too long"),
            Self::InterfaceNotFound { miniport_if_index, lower_if_index }
                => write!(f, "interface with miniport index {} and lower interface index {} not found", miniport_if_index, lower_if_index),
            Self::Io(e)
                => write!(f, "I/O error: {}", e)
        }
    }
}
impl std::error::Error for PcapngSerError {
}
impl From<io::Error> for PcapngSerError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}


/// A device to be registered in the capture file.
pub struct Device {
    pub encapsulation: Encapsulation,
    pub name: Option<String>,
}


trait WriteExt {
    // Writes the given 16-bit unsigned integer in native-endian byte order.
    fn write_u16_ne(&mut self, value: u16) -> Result<(), io::Error>;

    // Writes the given 32-bit unsigned integer in native-endian byte order.
    fn write_u32_ne(&mut self, value: u32) -> Result<(), io::Error>;

    // Writes the given 64-bit unsigned integer in native-endian byte order.
    fn write_u64_ne(&mut self, value: u64) -> Result<(), io::Error>;
}
impl<W: Write> WriteExt for W {
    fn write_u16_ne(&mut self, value: u16) -> Result<(), io::Error> {
        let value_bytes: [u8; 2] = value.to_ne_bytes();
        self.write_all(&value_bytes)
    }

    fn write_u32_ne(&mut self, value: u32) -> Result<(), io::Error> {
        let value_bytes: [u8; 4] = value.to_ne_bytes();
        self.write_all(&value_bytes)
    }

    fn write_u64_ne(&mut self, value: u64) -> Result<(), io::Error> {
        let value_bytes: [u8; 8] = value.to_ne_bytes();
        self.write_all(&value_bytes)
    }
}


/// Collects the known interfaces from an iterator of packet data events.
///
/// The return value is a tuple containing:
///
/// 1. A vector of devices, in the order in which they should be written into the capture file.
///
/// 2. A mapping of (`miniport_if_index`, `lower_if_index`) pairs to the PCAP device index (i.e.,
/// the index into the vector, represented as a 32-bit number as expected by the pcapng format).
pub fn collect_interfaces<'a, I: Iterator<Item = &'a PacketDataEvent>>(data_events: I) -> Result<(Vec<Device>, HashMap<(u32, u32), u32>), PcapngSerError> {
    let mut devices = Vec::new();
    let mut miniport_and_lower_to_pcap_index: HashMap<(u32, u32), u32> = HashMap::new();

    for event in data_events {
        match miniport_and_lower_to_pcap_index.entry((event.miniport_if_index, event.lower_if_index)) {
            HashMapEntry::Occupied(entry) => {
                // check that the encapsulation hasn't changed midway
                let index_u32 = *entry.get();
                let index: usize = index_u32.try_into()
                    .expect("existing index does not fit into usize");
                let known_device: &Device = &devices[index];
                if known_device.encapsulation != event.encapsulation {
                    return Err(PcapngSerError::EncapMismatch {
                        miniport_if_index: event.miniport_if_index,
                        lower_if_index: event.lower_if_index,
                        previous_encap: known_device.encapsulation,
                        sudden_encap: event.encapsulation,
                    });
                }
            },
            HashMapEntry::Vacant(entry) => {
                let next_index = u32::try_from(devices.len())
                    .expect("new index does not fit into u32");
                let name = match event.encapsulation {
                    Encapsulation::Ethernet => format!("eth:{}", event.lower_if_index),
                    Encapsulation::Ieee80211 => format!("wifi:{}", event.lower_if_index),
                    Encapsulation::RawIp => format!("rawip:{}", event.lower_if_index),
                };
                let device = Device {
                    encapsulation: event.encapsulation,
                    name: Some(name),
                };
                devices.push(device);
                entry.insert(next_index);
            },
        }
    }

    Ok((devices, miniport_and_lower_to_pcap_index))
}


/// Returns the zero-valued bytes necessary to pad a value of the given length to the next multiple
/// of 4 bytes.
#[inline]
fn padding_to_4_bytes(current_length: usize) -> &'static [u8] {
    // the outer "% 4" ensures that 4 folds to 0
    let pad_len = (4 - (current_length % 4)) % 4;
    &[0x00, 0x00, 0x00][..pad_len]
}

/// Writes out the events into a pcapng file.
pub fn write_pcapng<'a, I: Iterator<Item = &'a PacketDataEvent>, W: Write>(
    data_events: I,
    mut writer: W,
    devices: &[Device],
    miniport_and_lower_to_pcap_index: &HashMap<(u32, u32), u32>,
) -> Result<(), PcapngSerError> {
    // see IETF draft-tuexen-opsawg-pcapng
    const SECTION_HEADER_BLOCK_TYPE: u32 = 0x0A0D0D0A;
    const SECTION_HEADER_BLOCK_LENGTH: u32 = 32;
    const SECTION_HEADER_BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D; // reads differently depending on endianness
    const SECTION_HEADER_MAJOR_VERSION: u16 = 1;
    const SECTION_HEADER_MINOR_VERSION: u16 = 0;

    const INTERFACE_DESCRIPTION_BLOCK_TYPE: u32 = 0x0000_0001;
    const INTERFACE_DESCRIPTION_RESERVED_VALUE: u16 = 0x0000;
    const INTERFACE_DESCRIPTION_SNAPLEN_UNLIMITED: u32 = 0x0000_0000;
    const INTERFACE_DESCRIPTION_OPTION_NAME: u16 = 2;
    const INTERFACE_DESCRIPTION_OPTION_TIMESTAMP_RESOLUTION: u16 = 9;

    const ENHANCED_PACKET_BLOCK_TYPE: u32 = 0x0000_0006;
    const ENHANCED_PACKET_OPTION_FLAGS: u16 = 2;

    const OPTION_END_OF_OPTIONS: u16 = 0;
    const OPTION_COMMENT: u16 = 1;

    const LENGTH_VALUE_UNSPECIFIED: u64 = 0xFFFF_FFFF_FFFF_FFFF; // "no idea, read the file"
    const LENGTH_OPTION_END_OF_OPTIONS: u16 = 0;
    const LENGTH_OPTION_TIMESTAMP_RESOLUTION: u16 = 1;
    const LENGTH_OPTION_FLAGS: u16 = 4;

    // see IETF draft-richardson-opsawg-pcaplinktype
    const LINK_TYPE_ETHERNET: u16 = 1;
    const LINK_TYPE_RAW: u16 = 101;
    const LINK_TYPE_IEEE802_11: u16 = 105;

    // section header block
    writer.write_u32_ne(SECTION_HEADER_BLOCK_TYPE)?;
    writer.write_u32_ne(SECTION_HEADER_BLOCK_LENGTH)?;
    writer.write_u32_ne(SECTION_HEADER_BYTE_ORDER_MAGIC)?;
    writer.write_u16_ne(SECTION_HEADER_MAJOR_VERSION)?;
    writer.write_u16_ne(SECTION_HEADER_MINOR_VERSION)?;
    writer.write_u64_ne(LENGTH_VALUE_UNSPECIFIED)?;

    writer.write_u16_ne(OPTION_END_OF_OPTIONS)?;
    writer.write_u16_ne(LENGTH_OPTION_END_OF_OPTIONS)?;

    writer.write_u32_ne(SECTION_HEADER_BLOCK_LENGTH)?;

    for device in devices {
        // interface description block

        // calculate length
        // block_type(4) + block_length(4) + link_type(2) + reserved(2) + snaplen(4) [+ options] + end_of_options_type(2) + end_of_options_length(2) + block_length2(4)
        let mut idb_length = 4 + 4 + 2 + 2 + 4 + 2 + 2 + 4;
        if let Some(name) = &device.name {
            // option if_name: option_type(2) + option_length(2) + option_data(name.len().pad_to(4))
            if name.len() > 0xFFFF {
                return Err(PcapngSerError::NameTooLong(name.clone()));
            }
            idb_length += 2 + 2 + name.len() + padding_to_4_bytes(name.len()).len();
        }
        // option if_tsresol: option_type(2) + option_length(2) + option_data(1) + option_data_padding(3)
        idb_length += 2 + 2 + 1 + padding_to_4_bytes(1).len();

        let idb_length_u32: u32 = idb_length.try_into()
            .or(Err(PcapngSerError::BlockTooLong))?;

        // calculate link type
        let link_type = match device.encapsulation {
            Encapsulation::Ethernet => LINK_TYPE_ETHERNET,
            Encapsulation::Ieee80211 => LINK_TYPE_IEEE802_11,
            Encapsulation::RawIp => LINK_TYPE_RAW,
        };

        writer.write_u32_ne(INTERFACE_DESCRIPTION_BLOCK_TYPE)?;
        writer.write_u32_ne(idb_length_u32)?;
        writer.write_u16_ne(link_type)?;
        writer.write_u16_ne(INTERFACE_DESCRIPTION_RESERVED_VALUE)?;
        writer.write_u32_ne(INTERFACE_DESCRIPTION_SNAPLEN_UNLIMITED)?;

        if let Some(name) = &device.name {
            writer.write_u16_ne(INTERFACE_DESCRIPTION_OPTION_NAME)?;
            let name_length: u16 = name.len().try_into().unwrap();
            writer.write_u16_ne(name_length)?;
            writer.write_all(name.as_bytes())?;
            writer.write_all(padding_to_4_bytes(name.len()))?;
        }

        writer.write_u16_ne(INTERFACE_DESCRIPTION_OPTION_TIMESTAMP_RESOLUTION)?;
        writer.write_u16_ne(LENGTH_OPTION_TIMESTAMP_RESOLUTION)?;
        writer.write_all(&[TIMESTAMP_RESOLUTION, 0x00, 0x00, 0x00])?; // 1 byte + padding to 4 bytes

        writer.write_u16_ne(OPTION_END_OF_OPTIONS)?;
        writer.write_u16_ne(LENGTH_OPTION_END_OF_OPTIONS)?;

        writer.write_u32_ne(idb_length_u32)?;
    }

    for event in data_events {
        // enhanced packet block

        // find interface
        let interface_index = miniport_and_lower_to_pcap_index.get(&(event.miniport_if_index, event.lower_if_index))
            .ok_or(PcapngSerError::InterfaceNotFound { miniport_if_index: event.miniport_if_index, lower_if_index: event.lower_if_index })?;

        // comment
        let comment = format!("PID={} TID={}", event.event_metadata.process_id, event.event_metadata.thread_id);
        let comment_len_u16: u16 = comment.len().try_into().unwrap();

        // calculate length
        // block_type(4) + block_length(4) + interface_id(4) + timestamp_high(4) + timestamp_low(4) + captured_packet_length(4) + orig_packet_length(4) [+ data + data_padding] [+ options] + end_of_options_type(2) + end_of_options_length(2) + block_length2(4)
        let mut epb_length = 4 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 2 + 4;
        // + data + data_padding
        epb_length += event.fragment.len() + padding_to_4_bytes(event.fragment.len()).len();
        // + option_comment_type(2) + option_comment_length(2) + option_comment_value(comment.len().pad_to(4))
        epb_length += 2 + 2 + comment.len() + padding_to_4_bytes(comment.len()).len();
        // + option_flags_type(2) + option_flags_length(2) + option_flags_value(4)
        epb_length += 2 + 2 + 4;

        let epb_length_u32: u32 = epb_length.try_into()
            .or(Err(PcapngSerError::BlockTooLong))?;

        let packet_length_u32: u32 = event.fragment.len().try_into().unwrap();

        // timestamp calculations
        let timestamp_secs = event.event_metadata.timestamp.timestamp();
        let timestamp_subsec_nanos = event.event_metadata.timestamp.timestamp_subsec_nanos();
        let timestamp_subsec_100ns = timestamp_subsec_nanos / 100;
        let timestamp_100ns = timestamp_secs * (1_000_000_000 / 100) + i64::from(timestamp_subsec_100ns);

        let timestamp_high: u32 = (((timestamp_100ns as u64) >> 32) & 0xFFFF_FFFF).try_into().unwrap();
        let timestamp_low: u32 = (((timestamp_100ns as u64) >> 0) & 0xFFFF_FFFF).try_into().unwrap();

        // calculate flags
        let flags = if event.outbound {
            0b0000_0000_0000_0010
        } else {
            0b0000_0000_0000_0001
        };

        writer.write_u32_ne(ENHANCED_PACKET_BLOCK_TYPE)?;
        writer.write_u32_ne(epb_length_u32)?;
        writer.write_u32_ne(*interface_index)?;
        writer.write_u32_ne(timestamp_high)?;
        writer.write_u32_ne(timestamp_low)?;
        writer.write_u32_ne(packet_length_u32)?; // captured length
        writer.write_u32_ne(packet_length_u32)?; // original length
        writer.write_all(&event.fragment)?;
        writer.write_all(padding_to_4_bytes(event.fragment.len()))?;

        writer.write_u16_ne(ENHANCED_PACKET_OPTION_FLAGS)?;
        writer.write_u16_ne(LENGTH_OPTION_FLAGS)?;
        writer.write_u32_ne(flags)?;

        writer.write_u16_ne(OPTION_COMMENT)?;
        writer.write_u16_ne(comment_len_u16)?;
        writer.write_all(&comment.as_bytes())?;
        writer.write_all(padding_to_4_bytes(comment.len()))?;

        writer.write_u16_ne(OPTION_END_OF_OPTIONS)?;
        writer.write_u16_ne(LENGTH_OPTION_END_OF_OPTIONS)?;

        writer.write_u32_ne(epb_length_u32)?;
    }

    Ok(())
}
