//! Functionality for decoding NDIS captures from Windows events.


use std::{error::Error, io::Read};
use std::fmt;
use std::io::Cursor;

use chrono::{DateTime, Utc};

use crate::etl::{decode_timestamp_duration, Event, WindowsGuid};


/// The GUID identifying the NDIS capture event provider.
///
/// The official name of the provider is `Microsoft-Windows-NDIS-PacketCapture`. The GUID can be
/// found in its manifest, among other places.
const NDIS_CAPTURE_GUID: WindowsGuid = WindowsGuid::from_u128(0x2ED6006E_4729_4609_B423_3EE7BCD678EF);


/// Event keyword (bitflag) identifying a Wireless WAN packet, which has a raw IP header.
///
/// The keyword is known as `WirelessWAN` and can be found in the NDIS capture manifest.
const KEYWORD_WIRELESS_WAN: u64 = 0x0200;


/// Event keyword (bitflag) identifying a native 802.11 packet.
///
/// The keyword is known as `Native802.11` and can be found in the NDIS capture manifest.
const KEYWORD_NATIVE_802_11: u64 = 0x0001_0000;


/// Event keyword (bitflag) identifying an outbound packet.
///
/// The keyword is known as `ut:SendPath` and can be found in the NDIS capture manifest.
const KEYWORD_UT_SEND_PATH: u64 = 0x0001_0000_0000;


/// An NDIS event that represents a captured packet.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum NdisCaptureEvent {
    /// Packet data event in an NDIS capture.
    PacketData(PacketDataEvent),

    /// Packet metadata event in an NDIS capture.
    PacketMetadata(PacketMetadataEvent),

    /// Rundown information in an NDIS capture.
    SourceInfo(SourceInfoEvent),

    /// Source information in an NDIS capture.
    RundownInfo(RundownInfoEvent),
}

/// A packet data event in an NDIS capture.
///
/// The event is provided by the NDIS capture event provider (see [`NDIS_CAPTURE_GUID`]); the event
/// ID is 1001.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketDataEvent {
    pub event_metadata: NdisEventMetadata,
    pub encapsulation: Encapsulation,
    pub miniport_if_index: u32,
    pub lower_if_index: u32,
    pub outbound: bool,
    pub fragment: Vec<u8>,
}

/// A packet metadata event in an NDIS capture.
///
/// The event is provided by the NDIS capture event provider (see [`NDIS_CAPTURE_GUID`]); the event
/// ID is 1002.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketMetadataEvent {
    pub event_metadata: NdisEventMetadata,
    pub miniport_if_index: u32,
    pub lower_if_index: u32,
    pub metadata: Vec<u8>,
}

/// A rundown information event in an NDIS capture.
///
/// The event is provided by the NDIS capture event provider (see [`NDIS_CAPTURE_GUID`]); the event
/// ID is 5100.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct RundownInfoEvent {
    pub event_metadata: NdisEventMetadata,
    pub source_id: u8,
    pub rundown_id: u32,
    pub param1: u64,
    pub param2: u64,
    pub param_string: String,
    pub description: String,
}

/// A source information event in an NDIS capture.
///
/// The event is provided by the NDIS capture event provider (see [`NDIS_CAPTURE_GUID`]); the event
/// ID is 5101.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceInfoEvent {
    pub event_metadata: NdisEventMetadata,
    pub source_id: u8,
    pub source_name: String,
    pub interface_index: u32,
    pub layer_info: Vec<i16>,
}

/// Metadata of an NDIS capture event, common to all Windows events.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct NdisEventMetadata {
    pub thread_id: u32,
    pub process_id: u32,
    pub timestamp: DateTime<Utc>,
}

/// The type of encapsulation of the packet fragment.
///
/// Flags that can be used to detect the encapsulation of a packet are stored in the keywords of the
/// event.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub enum Encapsulation {
    /// Ethernet (IEEE 802.3) encapsulation.
    Ethernet,

    /// IEEE 802.11 (WiFi) encapsulation.
    Ieee80211,

    /// Raw IP (no layer 1/2) encapsulation.
    RawIp,
}
impl Default for Encapsulation {
    fn default() -> Self { Self::Ethernet }
}


/// An error that can occur when trying to decode an event.
#[derive(Debug)]
pub(crate) enum NdisEventError {
    /// The event was logged by a provider that is not the NDIS capture event provider.
    WrongProvider,

    /// The event ID is not supported.
    UnsupportedEventId(u16),

    /// The source name could not be decoded.
    SourceNameDecodingError(Vec<u16>),

    /// An I/O error occurred.
    Io(std::io::Error),
}
impl fmt::Display for NdisEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongProvider => write!(f, "wrong provider for NDIS capture events"),
            Self::UnsupportedEventId(evid) => write!(f, "unsupported event ID {}", evid),
            Self::SourceNameDecodingError(_wchars) => write!(f, "failed to decode source name"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}
impl Error for NdisEventError {
}
impl From<std::io::Error> for NdisEventError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}


/// Reads a little-endian 16-bit-character NUL-terminated string.
fn read_str16le<R: Read>(mut whence: R) -> Result<String, NdisEventError> {
    let mut u16_chars: Vec<u16> = Vec::new();
    loop {
        let mut wchar_buf = [0u8; 2];
        whence.read_exact(&mut wchar_buf)?;
        let wchar = u16::from_le_bytes(wchar_buf);
        if wchar == 0x0000 {
            break;
        }
        u16_chars.push(wchar);
    }
    String::from_utf16(&u16_chars)
        .map_err(|_| NdisEventError::SourceNameDecodingError(u16_chars))
}


/// Attempts to decode an NDIS capture event.
pub(crate) fn decode_event(event: &Event, base_time: DateTime<Utc>, timestamp_scale: f64) -> Result<NdisCaptureEvent, NdisEventError> {
    if event.header.provider_id != NDIS_CAPTURE_GUID {
        return Err(NdisEventError::WrongProvider);
    }

    let timestamp_duration = decode_timestamp_duration(
        (timestamp_scale * (event.header.time_stamp as f64)) as i64
    );
    let timestamp = base_time + timestamp_duration;
    let event_metadata = NdisEventMetadata {
        thread_id: event.header.thread_id,
        process_id: event.header.process_id,
        timestamp,
    };

    let mut payload_cursor = Cursor::new(&event.payload);

    let inner_event = match event.header.event_descriptor.id {
        1001 => {
            let mut base_buf = [0u8; 12];
            payload_cursor.read_exact(&mut base_buf)?;
            let miniport_if_index = u32::from_le_bytes(base_buf[0..4].try_into().unwrap());
            let lower_if_index = u32::from_le_bytes(base_buf[4..8].try_into().unwrap());
            let fragment_size = u32::from_le_bytes(base_buf[8..12].try_into().unwrap());

            let fragment_size_usize: usize = fragment_size.try_into().unwrap();
            let mut fragment = vec![0u8; fragment_size_usize];
            payload_cursor.read_exact(&mut fragment)?;

            let encapsulation = if event.header.event_descriptor.keyword & KEYWORD_NATIVE_802_11 != 0 {
                Encapsulation::Ieee80211
            } else if event.header.event_descriptor.keyword & KEYWORD_WIRELESS_WAN != 0 {
                Encapsulation::RawIp
            } else {
                Encapsulation::Ethernet
            };
            let outbound = event.header.event_descriptor.keyword & KEYWORD_UT_SEND_PATH != 0;

            NdisCaptureEvent::PacketData(PacketDataEvent {
                event_metadata,
                encapsulation,
                miniport_if_index,
                lower_if_index,
                outbound,
                fragment,
            })
        },
        1002 => {
            let mut base_buf = [0u8; 12];
            payload_cursor.read_exact(&mut base_buf)?;
            let miniport_if_index = u32::from_le_bytes(base_buf[0..4].try_into().unwrap());
            let lower_if_index = u32::from_le_bytes(base_buf[4..8].try_into().unwrap());
            let metadata_size = u32::from_le_bytes(base_buf[8..12].try_into().unwrap());

            let metadata_size_usize: usize = metadata_size.try_into().unwrap();
            let mut metadata = vec![0u8; metadata_size_usize];
            payload_cursor.read_exact(&mut metadata)?;

            NdisCaptureEvent::PacketMetadata(PacketMetadataEvent {
                event_metadata,
                miniport_if_index,
                lower_if_index,
                metadata,
            })
        },
        5100 => {
            let mut base_buf = [0u8; 21];
            payload_cursor.read_exact(&mut base_buf)?;

            let source_id = base_buf[0];
            let rundown_id = u32::from_le_bytes(base_buf[1..5].try_into().unwrap());
            let param1 = u64::from_le_bytes(base_buf[5..13].try_into().unwrap());
            let param2 = u64::from_le_bytes(base_buf[13..21].try_into().unwrap());
            let param_string = read_str16le(&mut payload_cursor)?;
            let description = read_str16le(&mut payload_cursor)?;

            NdisCaptureEvent::RundownInfo(RundownInfoEvent {
                source_id,
                event_metadata,
                rundown_id,
                param1,
                param2,
                param_string,
                description,
            })
        },
        5101 => {
            let mut base_buf = [0u8; 2];
            payload_cursor.read_exact(&mut base_buf[0..1])?;
            let source_id = base_buf[0];
            let source_name = read_str16le(&mut payload_cursor)?;

            let mut rest_buf = [0u8; 6];
            payload_cursor.read_exact(&mut rest_buf)?;
            let interface_index = u32::from_le_bytes(rest_buf[0..4].try_into().unwrap());
            let layer_count = u16::from_le_bytes(rest_buf[4..6].try_into().unwrap());

            let mut layer_info = Vec::with_capacity(layer_count.into());
            for _ in 0..layer_count {
                let mut layer_info_buf = [0u8; 2];
                payload_cursor.read_exact(&mut layer_info_buf)?;
                layer_info.push(i16::from_le_bytes(layer_info_buf));
            }

            NdisCaptureEvent::SourceInfo(SourceInfoEvent {
                event_metadata,
                source_id,
                source_name,
                interface_index,
                layer_info,
            })
        },
        other => return Err(NdisEventError::UnsupportedEventId(other)),
    };

    Ok(inner_event)
}
