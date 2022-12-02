//! Functionality for decoding NDIS captures from Windows events.


use std::{error::Error, io::Read};
use std::fmt;
use std::io::Cursor;

use chrono::{DateTime, Utc};

use crate::etl::{decode_timestamp_duration, Event, WindowsGuid};


/// The GUID identifying the NDIS capture event provider.
///
/// The official name of the provider is `Microsoft-Windows-NDIS-PacketCapture`.
const NDIS_CAPTURE_GUID: WindowsGuid = WindowsGuid::from_u128(0x2ED6006E_4729_4609_B423_3EE7BCD678EF);


/// An NDIS event that represents a captured packet.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum NdisCaptureEvent {
    /// Packet data event in an NDIS capture.
    PacketData(PacketDataEvent),

    /// Packet metadata event in an NDIS capture.
    PacketMetadata(PacketMetadataEvent),
}

/// A packet data event in an NDIS capture.
///
/// The event is provided by the NDIS capture event provider (see [`NDIS_CAPTURE_GUID`]); the event
/// ID is 1001.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct PacketDataEvent {
    pub event_metadata: NdisEventMetadata,
    pub miniport_if_index: u32,
    pub lower_if_index: u32,
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

/// Metadata of an NDIS capture event, common to all Windows events.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct NdisEventMetadata {
    pub thread_id: u32,
    pub process_id: u32,
    pub timestamp: DateTime<Utc>,
}

/// An error that can occur when trying to decode an event.
#[derive(Debug)]
pub(crate) enum NdisEventError {
    /// The event was logged by a provider that is not the NDIS capture event provider.
    WrongProvider,

    /// The event ID is not supported.
    UnsupportedEventId(u16),

    /// An I/O error occurred.
    Io(std::io::Error),
}
impl fmt::Display for NdisEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongProvider => write!(f, "wrong provider for NDIS capture events"),
            Self::UnsupportedEventId(evid) => write!(f, "unsupported event ID {}", evid),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}
impl Error for NdisEventError {
}
impl From<std::io::Error> for NdisEventError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}


/// Attempts to decode an NDIS capture event.
pub(crate) fn decode_event(event: &Event, start_time: DateTime<Utc>) -> Result<NdisCaptureEvent, NdisEventError> {
    if event.header.provider_id != NDIS_CAPTURE_GUID {
        return Err(NdisEventError::WrongProvider);
    }

    let timestamp_duration = decode_timestamp_duration(event.header.time_stamp);
    let timestamp = start_time + timestamp_duration;

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

            // TODO: identify and pass on fragment type from event headers: Ethernet vs. 802.11 vs. raw (naked IP)

            NdisCaptureEvent::PacketData(PacketDataEvent {
                event_metadata: NdisEventMetadata {
                    thread_id: event.header.thread_id,
                    process_id: event.header.process_id,
                    timestamp,
                },
                miniport_if_index,
                lower_if_index,
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
                event_metadata: NdisEventMetadata {
                    thread_id: event.header.thread_id,
                    process_id: event.header.process_id,
                    timestamp,
                },
                miniport_if_index,
                lower_if_index,
                metadata,
            })
        },
        other => return Err(NdisEventError::UnsupportedEventId(other)),
    };

    Ok(inner_event)
}
