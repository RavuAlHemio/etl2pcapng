//! Functionality for reading ETL tracing files.
//!
//! To read an ETL file:
//!
//! 1. Repeatedly call [read_wmi_buffer] to obtain each buffer.
//!
//! 2. For each WMI buffer, repeatedly call [read_event] to obtain each event.


use std::fmt;
use std::io::{self, BufRead, Cursor, Read};
use std::string::FromUtf16Error;

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use from_to_repr::from_to_other;


const HOOK_UPPER_EVENT_TRACE_GROUP_HEADER: u16 = 0x0000;

const HOOK_LOWER_EVENT_TRACE_TYPE_INFO: u16 = 0x00;
const HOOK_LOWER_EVENT_TRACE_TYPE_EXTENSION: u16 = 0x05;

const HOOK_WMI_LOG_TYPE_HEADER: u16 = HOOK_UPPER_EVENT_TRACE_GROUP_HEADER | HOOK_LOWER_EVENT_TRACE_TYPE_INFO;
const HOOK_WMI_LOG_TYPE_HEADER_EXTENSION: u16 = HOOK_UPPER_EVENT_TRACE_GROUP_HEADER | HOOK_LOWER_EVENT_TRACE_TYPE_EXTENSION;


/// An error produced by reading ETL data.
#[derive(Debug)]
pub(crate) enum EtlError {
    /// A low-level input/output error.
    Io(io::Error),

    /// An unknown or unsupported header type was encountered.
    UnknownHeaderType(TraceHeaderType),

    /// Failed to decode a string as UTF-8.
    Utf16Decoding(FromUtf16Error),

    /// Mismatched length when trying to decode an inner field.
    LengthMismatch { field_type: &'static str, expected: usize, obtained: usize },

    /// An unknown or unsupported system header type was encountered.
    UnknownSystemHeaderType(u16),
}
impl fmt::Display for EtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e)
                => write!(f, "I/O error: {}", e),
            Self::UnknownHeaderType(e)
                => write!(f, "unsupported header type {:?}", e),
            Self::Utf16Decoding(e)
                => write!(f, "UTF-16 decoding failed: {}", e),
            Self::LengthMismatch { field_type, expected, obtained }
                => write!(f, "failed to decode {}: expected {} bytes, obtained {}", field_type, expected, obtained),
            Self::UnknownSystemHeaderType(ht)
                => write!(f, "unknown system header type 0x{:04X}", ht),
        }
    }
}
impl std::error::Error for EtlError {
}
impl From<io::Error> for EtlError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}
impl From<FromUtf16Error> for EtlError {
    fn from(e: FromUtf16Error) -> Self { Self::Utf16Decoding(e) }
}


/// Information about the ETW (Event Tracing for Windows) buffer context.
///
/// Reconstructed from (a simplified interpretation of) [Microsoft's `ETW_BUFFER_CONTEXT` documentation].
///
/// [Microsoft's `ETW_BUFFER_CONTEXT` documentation](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-etw_buffer_context)
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct EtwBufferContext {
    pub processor_index: u16,
    pub logger_id: u16,
}


/// A padding value, either stored or dropped (but of a known size).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum PossiblePadding {
    Stored(Vec<u8>),
    DroppedSize(usize),
}
impl PossiblePadding {
    pub fn len(&self) -> usize {
        match self {
            Self::Stored(padding) => padding.len(),
            Self::DroppedSize(size) => *size,
        }
    }
}
impl Default for PossiblePadding {
    fn default() -> Self { Self::Stored(Vec::with_capacity(0)) }
}


/// The header of each buffer in an ETL file.
///
/// This structure is only guaranteed to be used since Windows version 6.1 (Windows 7). Previous
/// Windows versions structure this differently and the differences are sometimes wild.
///
/// Reconstructed from [Geoff Chappell's description of `WMI_BUFFER_HEADER`].
/// 
/// [Geoff Chappell's description of `WMI_BUFFER_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/wmi_buffer_header.htm)
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct WmiBufferHeader {
    pub buffer_size: u32,
    pub saved_offset: u32,
    pub current_offset: u32,
    pub reference_count: i32,
    pub time_stamp: i64,
    pub sequence_number: i64,
    pub clock_type_and_frequency: u64, // 3 bits clock_type, 61 bits frequency
    pub context: EtwBufferContext,
    pub padding0: u32,
    pub offset: u32,
    pub buffer_flag: u16,
    pub buffer_type: u16,
    pub union_of_pretty_much_everything: [u8; 16],
}


/// A complete WMI buffer.
///
/// A buffer consists of a header, a payload and padding. The length of the header is fixed (0x48 =
/// 72 bytes). The length of the payload is stored in the header's `offset` field. The padding is
/// generally a sequence of bytes with value 0xFF; its length can be calculated from `buffer_size`,
/// which is the sum of the lengths of header, payload (whose length is in `offset`), and padding.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct WmiBuffer {
    pub header: WmiBufferHeader,
    pub payload: Vec<u8>,
    pub padding: PossiblePadding,
}


/// The type of trace header.
///
/// This type is stored in basically all kinds of event headers at offset 3.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[from_to_other(base_type = u8)]
pub(crate) enum TraceHeaderType {
    System32 = 0x01,
    System64 = 0x02,
    Compact32 = 0x03,
    Compact64 = 0x04,
    Full32 = 0x0A,
    Instance32 = 0x0B,
    Timed = 0x0C,
    Error = 0x0D,
    WnodeHeader = 0x0E,
    Message = 0x0F,
    PerfInfo32 = 0x10,
    PerfInfo64 = 0x11,
    EventHeader32 = 0x12,
    EventHeader64 = 0x13,
    Full64 = 0x14,
    Instance64 = 0x15,
    Other(u8),
}
impl TraceHeaderType {
    pub fn is_system(&self) -> bool {
        match self {
            Self::System32 => true,
            Self::System64 => true,
            Self::Compact32 => true,
            Self::Compact64 => true,
            _ => false,
        }
    }

    pub fn is_system_compact(&self) -> bool {
        match self {
            Self::Compact32 => true,
            Self::Compact64 => true,
            _ => false,
        }
    }

    pub fn is_64_bit(&self) -> bool {
        match self {
            Self::System64 => true,
            Self::Compact64 => true,
            Self::PerfInfo64 => true,
            Self::EventHeader64 => true,
            Self::Full64 => true,
            Self::Instance64 => true,
            _ => false,
        }
    }

    pub fn is_event_header(&self) -> bool {
        match self {
            Self::EventHeader32 => true,
            Self::EventHeader64 => true,
            _ => false,
        }
    }

    pub fn is_event_trace_header(&self) -> bool {
        match self {
            Self::Full32 => true,
            Self::Full64 => true,
            _ => false,
        }
    }
}


/// Windows chaotic-endian GUID encoding.
///
/// Reconstructed from [Microsoft's `GUID` documentation].
///
/// [Raymond Chen explains] how its structure used to make sense for version-1 GUIDs.
///
/// [Microsoft's `GUID` documentation](https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid)
/// [Raymond Chen explains](https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221)
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct WindowsGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}
impl WindowsGuid {
    pub const fn from_u128(value: u128) -> Self {
        Self {
            data1: ((value >> 96) & 0xFFFFFFFF) as u32,
            data2: ((value >> 80) & 0xFFFF) as u16,
            data3: ((value >> 64) & 0xFFFF) as u16,
            data4: [
                ((value >> 56) & 0xFF) as u8,
                ((value >> 48) & 0xFF) as u8,
                ((value >> 40) & 0xFF) as u8,
                ((value >> 32) & 0xFF) as u8,
                ((value >> 24) & 0xFF) as u8,
                ((value >> 16) & 0xFF) as u8,
                ((value >>  8) & 0xFF) as u8,
                ((value >>  0) & 0xFF) as u8,
            ],
        }
    }
}
impl fmt::Display for WindowsGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1, self.data2, self.data3, self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7],
        )
    }
}
impl From<u128> for WindowsGuid {
    fn from(value: u128) -> Self { Self::from_u128(value) }
}
impl TryFrom<&[u8]> for WindowsGuid {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err(());
        }

        Ok(Self {
            data1: u32::from_le_bytes(value[0..4].try_into().unwrap()),
            data2: u16::from_le_bytes(value[4..6].try_into().unwrap()),
            data3: u16::from_le_bytes(value[6..8].try_into().unwrap()),
            data4: value[8..16].try_into().unwrap(),
        })
    }
}

/// The zero GUID, {00000000-0000-0000-0000-000000000000}.
pub(crate) const ZERO_GUID: WindowsGuid = WindowsGuid {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0u8; 8],
};


/// Windows date and time information structure.
///
/// Reconstructed from [Microsoft's `SYSTEMTIME` documentation].
///
/// [Microsoft's `SYSTEMTIME` documentation](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime)
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub day_of_week: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
}
impl TryFrom<&[u8]> for SystemTime {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err(());
        }

        Ok(Self {
            year: u16::from_le_bytes(value[0..2].try_into().unwrap()),
            month: u16::from_le_bytes(value[2..4].try_into().unwrap()),
            day_of_week: u16::from_le_bytes(value[4..6].try_into().unwrap()),
            day: u16::from_le_bytes(value[6..8].try_into().unwrap()),
            hour: u16::from_le_bytes(value[8..10].try_into().unwrap()),
            minute: u16::from_le_bytes(value[10..12].try_into().unwrap()),
            second: u16::from_le_bytes(value[12..14].try_into().unwrap()),
            milliseconds: u16::from_le_bytes(value[14..16].try_into().unwrap()),
        })
    }
}


/// Windows time-zone information structure.
///
/// Reconstructed from [Microsoft's `TIME_ZONE_INFORMATION` documentation].
///
/// [Microsoft's `TIME_ZONE_INFORMATION` documentation](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information)
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TimeZoneInformation {
    pub bias: i32,
    pub standard_name: String, // up to 32 UTF-16 values
    pub standard_date: SystemTime,
    pub standard_bias: i32,
    pub daylight_name: String, // up to 32 UTF-16 values
    pub daylight_date: SystemTime,
    pub daylight_bias: i32,
}
impl TryFrom<&[u8]> for TimeZoneInformation {
    type Error = EtlError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 172 {
            return Err(EtlError::LengthMismatch { field_type: "TimeZoneInformation", expected: 172, obtained: value.len() });
        }

        Ok(Self {
            bias: i32::from_le_bytes(value[0..4].try_into().unwrap()),

            standard_name: read_nul_terminated_utf16_le(Cursor::new(&value[4..68]))?,
            standard_date: SystemTime::try_from(&value[68..84]).unwrap(),
            standard_bias: i32::from_le_bytes(value[84..88].try_into().unwrap()),

            daylight_name: read_nul_terminated_utf16_le(Cursor::new(&value[88..152]))?,
            daylight_date: SystemTime::try_from(&value[152..168]).unwrap(),
            daylight_bias: i32::from_le_bytes(value[168..172].try_into().unwrap()),
        })
    }
}


/// The system trace header. Describes basic metadata of the whole trace.
///
/// When serialized, the header has a size of 0x20 (full variant) or 0x18 (compact variant; missing
/// `kernel_time` and `user_time`) bytes.
///
/// Reconstructed from [Geoff Chappell's description of `SYSTEM_TRACE_HEADER`].
/// 
/// [Geoff Chappell's description of `SYSTEM_TRACE_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/system_trace_header.htm)
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SystemTraceHeader {
    pub version: u16,
    pub header_type: TraceHeaderType,
    pub flags: u8,
    pub size: u16,
    pub hook_id: u16,
    pub thread_id: u32,
    pub process_id: u32,
    pub system_time: i64,
    pub kernel_time: Option<u32>,
    pub user_time: Option<u32>,
}


/// A descriptor describing an event.
///
/// Reconstructed from [Microsoft's `EVENT_DESCRIPTOR` documentation].
///
/// [Microsoft's `EVENT_DESCRIPTOR` documentation](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor)
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventDescriptor {
    pub id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
}


/// The event header. Describes basic metadata of a set of events.
///
/// Reconstructed from [Geoff Chappell's description of `EVENT_HEADER`].
/// 
/// [Geoff Chappell's description of `EVENT_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/event_header.htm)
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventHeader {
    pub size: u16,
    pub header_type: TraceHeaderType,
    pub marker_flags: u8, // not part of the official definition, but used as such
    pub flags: u16,
    pub event_property: u16,
    pub thread_id: u32,
    pub process_id: u32,
    pub time_stamp: i64,
    pub provider_id: WindowsGuid,
    pub event_descriptor: EventDescriptor,
    pub kernel_time: u32,
    pub user_time: u32,
    pub activity_id: WindowsGuid,
}


/// The event trace header. Describes basic metadata of a set of events.
///
/// Reconstructed from [Geoff Chappell's description of `EVENT_TRACE_HEADER`].
/// 
/// [Geoff Chappell's description of `EVENT_TRACE_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/event_trace_header.htm)
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventTraceHeader {
    pub size: u16,
    pub header_type: TraceHeaderType,
    pub marker_flags: u8,
    pub class_type: u8,
    pub class_level: u8,
    pub class_version: u16,
    pub thread_id: u32,
    pub process_id: u32,
    pub time_stamp: i64,
    pub guid: WindowsGuid,
    pub kernel_time: u32,
    pub user_time: u32,
}


/// The trace logfile header. Describes more detailed metadata of the whole trace.
///
/// Reconstructed from [Geoff Chappell's description of `TRACE_LOGFILE_HEADER`].
/// 
/// [Geoff Chappell's description of `TRACE_LOGFILE_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/trace_logfile_header.htm)
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TraceLogfileHeader {
    pub buffer_size: u32,
    pub version: [u8; 4],
    pub provider_version: u32,
    pub num_processors: u32,
    pub end_time: i64,
    pub timer_resolution: u32,
    pub max_file_size: u32,
    pub log_file_mode: u32,
    pub buffers_written: u32,

    // union
    //   variant
    pub log_instance_guid: WindowsGuid,
    //   variant
    pub start_buffers: u32,
    pub pointer_size: u32,
    pub events_lost: u32,
    pub cpu_speed_mhz: u32,

    pub logger_name_ptr: u64, // u32 in 32-bit logs
    pub log_file_name_ptr: u64, // u32 in 32-bit logs
    pub time_zone: TimeZoneInformation,
    pub boot_time: i64,
    pub perf_freq: i64,
    pub start_time: i64,
    pub reserved_flags: u32,
    pub buffers_lost: u32,
}
impl TraceLogfileHeader {
    /// Obtains the scaling factor for the relative timestamps contained in each event's header.
    ///
    /// Reconstructed from [Microsoft's `WNODE_HEADER` documentation], specifically the Remarks
    /// section.
    ///
    /// [Microsoft's `WNODE_HEADER` documentation](https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header)
    pub fn time_stamp_scale(&self) -> f64 {
        match self.reserved_flags {
            1 => {
                // QueryPerformanceCounter
                10_000_000.0 / (self.perf_freq as f64)
            },
            2 => {
                // system time
                1.0
            },
            3 => {
                // CPU cycle counter
                10.0 / f64::from(self.cpu_speed_mhz)
            },
            _ => 0.0,
        }
    }
}

/// A trace logfile header event.
///
/// Reconstructed from [Geoff Chappell's description of `TRACE_LOGFILE_HEADER`].
/// 
/// [Geoff Chappell's description of `TRACE_LOGFILE_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/trace_logfile_header.htm)
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TraceLogfileHeaderEvent {
    pub system_header: SystemTraceHeader,
    pub logfile_header: TraceLogfileHeader,
    pub logger_name: String,
    pub log_file_name: String,
}

/// Unknown system trace event with hook ID 0x0050.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Unknown50Event {
    pub system_header: SystemTraceHeader,
    pub full_payload: Vec<u8>,
}

/// An event from the event log.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Event {
    pub header: EventHeader,
    pub payload: Vec<u8>,
}

/// An entry describing an event trace.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventTrace {
    pub header: EventTraceHeader,
    pub payload: Vec<u8>,
}


/// Any kind of trace event.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TraceEvent {
    TraceLogfileHeader(TraceLogfileHeaderEvent),
    Unknown50(Unknown50Event),
    Event(Event),
    EventTrace(EventTrace),
}
impl TraceEvent {
    pub fn guid(&self) -> Option<&WindowsGuid> {
        match self {
            Self::TraceLogfileHeader(lh) => Some(&lh.logfile_header.log_instance_guid),
            Self::Unknown50(_evt) => None,
            Self::Event(evt) => Some(&evt.header.activity_id),
            Self::EventTrace(trc) => Some(&trc.header.guid),
        }
    }
}


/// Reads a NUL-terminated UTF-16 little-endian string and returns it (without the NUL terminator).
fn read_nul_terminated_utf16_le<R: Read>(mut reader: R) -> Result<String, EtlError> {
    let mut utf16_values = Vec::new();
    let mut value_bytes = [0u8; 2];
    loop {
        reader.read_exact(&mut value_bytes)?;
        let value = u16::from_le_bytes(value_bytes);
        if value == 0x0000 {
            break;
        }
        utf16_values.push(value);
    }
    String::from_utf16(&utf16_values)
        .map_err(|e| e.into())
}


/// Reads the bytes of the next WMI buffer structure in an ETL file.
pub(crate) fn read_wmi_buffer<R: BufRead>(mut etl_reader: R, store_padding: bool) -> Result<WmiBuffer, EtlError> {
    let mut header_buf = [0u8; 72];
    etl_reader.read_exact(&mut header_buf)?;

    let header = WmiBufferHeader {
        buffer_size: u32::from_le_bytes(header_buf[0..4].try_into().unwrap()),
        saved_offset: u32::from_le_bytes(header_buf[4..8].try_into().unwrap()),
        current_offset: u32::from_le_bytes(header_buf[8..12].try_into().unwrap()),
        reference_count: i32::from_le_bytes(header_buf[12..16].try_into().unwrap()),
        time_stamp: i64::from_le_bytes(header_buf[16..24].try_into().unwrap()),
        sequence_number: i64::from_le_bytes(header_buf[24..32].try_into().unwrap()),
        clock_type_and_frequency: u64::from_le_bytes(header_buf[32..40].try_into().unwrap()),
        context: EtwBufferContext {
            processor_index: u16::from_le_bytes(header_buf[40..42].try_into().unwrap()),
            logger_id: u16::from_le_bytes(header_buf[42..44].try_into().unwrap()),
        },
        padding0: u32::from_le_bytes(header_buf[44..48].try_into().unwrap()),
        offset: u32::from_le_bytes(header_buf[48..52].try_into().unwrap()),
        buffer_flag: u16::from_le_bytes(header_buf[52..54].try_into().unwrap()),
        buffer_type: u16::from_le_bytes(header_buf[54..56].try_into().unwrap()),
        union_of_pretty_much_everything: header_buf[56..72].try_into().unwrap(),
    };
    let offset_usize = usize::try_from(header.offset).unwrap();
    let payload_size = offset_usize - header_buf.len();

    let mut payload = vec![0u8; payload_size];
    etl_reader.read_exact(&mut payload)?;

    let buffer_size: usize = header.buffer_size.try_into().unwrap();
    let padding_size = buffer_size - offset_usize;
    let mut padding_vec = vec![0u8; padding_size];
    etl_reader.read_exact(&mut padding_vec)?;

    let padding = if store_padding {
        PossiblePadding::Stored(padding_vec)
    } else {
        PossiblePadding::DroppedSize(padding_vec.len())
    };

    Ok(WmiBuffer {
        header,
        payload,
        padding,
    })
}


pub(crate) fn read_event<R: BufRead>(mut buffer_reader: R) -> Result<TraceEvent, EtlError> {
    let mut buffer_bytes_read = 0;

    let event = internal_read_event(&mut buffer_reader, &mut buffer_bytes_read)?;

    // skip padding
    let padding = 8 - buffer_bytes_read % 8;
    // if padding == 8, we're already on an 8-byte boundary
    if padding < 8 {
        let mut nevermind = vec![0u8; padding];
        buffer_reader.read_exact(&mut nevermind)?;
    }

    Ok(event)
}


fn internal_read_event<R: BufRead>(mut buffer_reader: R, buffer_bytes_read: &mut usize) -> Result<TraceEvent, EtlError> {
    // read 4 header bytes
    let mut header_bytes = [0u8; 4];
    buffer_reader.read_exact(&mut header_bytes)?;
    *buffer_bytes_read += header_bytes.len();

    let trace_header_type: TraceHeaderType = header_bytes[2].into();
    if trace_header_type.is_system() {
        let mut more_header_bytes = [0u8; 28];
        let more_header_slice = if trace_header_type.is_system_compact() {
            buffer_reader.read_exact(&mut more_header_bytes[0..20])?;
            &more_header_bytes[0..20]
        } else {
            buffer_reader.read_exact(&mut more_header_bytes)?;
            &more_header_bytes
        };
        *buffer_bytes_read += more_header_slice.len();

        let size = u16::from_le_bytes(more_header_slice[0..2].try_into().unwrap());
        let logfile_header_and_payload_size = usize::from(size) - (header_bytes.len() + more_header_slice.len());

        let system_header = SystemTraceHeader {
            version: u16::from_le_bytes(header_bytes[0..2].try_into().unwrap()),
            header_type: header_bytes[2].into(),
            flags: header_bytes[3],
            size,
            hook_id: u16::from_le_bytes(more_header_slice[2..4].try_into().unwrap()),
            thread_id: u32::from_le_bytes(more_header_slice[4..8].try_into().unwrap()),
            process_id: u32::from_le_bytes(more_header_slice[8..12].try_into().unwrap()),
            system_time: i64::from_le_bytes(more_header_slice[12..20].try_into().unwrap()),

            // these two are missing from the compact header:
            kernel_time: (more_header_slice.len() >= 24).then(|| u32::from_le_bytes(more_header_slice[20..24].try_into().unwrap())),
            user_time: (more_header_slice.len() >= 28).then(|| u32::from_le_bytes(more_header_slice[24..28].try_into().unwrap())),
        };

        if system_header.hook_id == HOOK_WMI_LOG_TYPE_HEADER {
            // read bytes for the logfile header
            let mut logfile_header_bytes = [0u8; 280];
            let (logfile_header_slice, logger_name_ptr, log_file_name_ptr, time_zone_offset) = if trace_header_type.is_64_bit() {
                buffer_reader.read_exact(&mut logfile_header_bytes)?;
                let logger_name_ptr = u64::from_le_bytes(logfile_header_bytes[56..64].try_into().unwrap());
                let log_file_name_ptr = u64::from_le_bytes(logfile_header_bytes[64..72].try_into().unwrap());
                (&logfile_header_bytes[..], logger_name_ptr, log_file_name_ptr, 72)
            } else {
                buffer_reader.read_exact(&mut logfile_header_bytes[0..272])?;
                let logger_name_ptr = u32::from_le_bytes(logfile_header_bytes[56..60].try_into().unwrap()).into();
                let log_file_name_ptr = u32::from_le_bytes(logfile_header_bytes[60..64].try_into().unwrap()).into();
                (&logfile_header_bytes[..272], logger_name_ptr, log_file_name_ptr, 64)
            };
            *buffer_bytes_read += logfile_header_slice.len();
            let payload_size = logfile_header_and_payload_size - logfile_header_slice.len();

            // deconstruct the logfile header
            let logfile_header = TraceLogfileHeader {
                buffer_size: u32::from_le_bytes(logfile_header_slice[0..4].try_into().unwrap()),
                version: logfile_header_slice[4..8].try_into().unwrap(),
                provider_version: u32::from_le_bytes(logfile_header_slice[8..12].try_into().unwrap()),
                num_processors: u32::from_le_bytes(logfile_header_slice[12..16].try_into().unwrap()),
                end_time: i64::from_be_bytes(logfile_header_slice[16..24].try_into().unwrap()),
                timer_resolution: u32::from_le_bytes(logfile_header_slice[24..28].try_into().unwrap()),
                max_file_size: u32::from_le_bytes(logfile_header_slice[28..32].try_into().unwrap()),
                log_file_mode: u32::from_le_bytes(logfile_header_slice[32..36].try_into().unwrap()),
                buffers_written: u32::from_le_bytes(logfile_header_slice[36..40].try_into().unwrap()),

                // union
                //   variant
                log_instance_guid: WindowsGuid::try_from(&logfile_header_slice[40..56]).unwrap(),
                //   variant
                start_buffers: u32::from_le_bytes(logfile_header_slice[40..44].try_into().unwrap()),
                pointer_size: u32::from_le_bytes(logfile_header_slice[44..48].try_into().unwrap()),
                events_lost: u32::from_le_bytes(logfile_header_slice[48..52].try_into().unwrap()),
                cpu_speed_mhz: u32::from_le_bytes(logfile_header_slice[52..56].try_into().unwrap()),

                logger_name_ptr,
                log_file_name_ptr,

                time_zone: TimeZoneInformation::try_from(&logfile_header_slice[time_zone_offset..time_zone_offset+172]).unwrap(),
                // 4 bytes of padding
                boot_time: i64::from_le_bytes(logfile_header_slice[time_zone_offset+176..time_zone_offset+184].try_into().unwrap()),
                perf_freq: i64::from_le_bytes(logfile_header_slice[time_zone_offset+184..time_zone_offset+192].try_into().unwrap()),
                start_time: i64::from_le_bytes(logfile_header_slice[time_zone_offset+192..time_zone_offset+200].try_into().unwrap()),
                reserved_flags: u32::from_le_bytes(logfile_header_slice[time_zone_offset+200..time_zone_offset+204].try_into().unwrap()),
                buffers_lost: u32::from_le_bytes(logfile_header_slice[time_zone_offset+204..time_zone_offset+208].try_into().unwrap()),
            };

            // the payload contains the logger and log file names
            let mut payload_buf = vec![0u8; payload_size];
            buffer_reader.read_exact(payload_buf.as_mut_slice())?;
            *buffer_bytes_read += payload_buf.len();

            let mut payload_reader = Cursor::new(&payload_buf);
            let logger_name = read_nul_terminated_utf16_le(&mut payload_reader)?;
            let log_file_name = read_nul_terminated_utf16_le(&mut payload_reader)?;

            return Ok(TraceEvent::TraceLogfileHeader(TraceLogfileHeaderEvent {
                system_header,
                logfile_header,
                logger_name,
                log_file_name,
            }));
        } else if system_header.hook_id == 0x0050 {
            // no idea what happens here
            let mut full_payload = vec![0u8; logfile_header_and_payload_size.try_into().unwrap()];
            buffer_reader.read_exact(&mut full_payload)?;
            *buffer_bytes_read += full_payload.len();

            return Ok(TraceEvent::Unknown50(Unknown50Event {
                system_header,
                full_payload,
            }));
        } else {
            return Err(EtlError::UnknownSystemHeaderType(system_header.hook_id));
        }
    } else if trace_header_type.is_event_trace_header() {
        let mut more_header_bytes = [0u8; 44];
        buffer_reader.read_exact(&mut more_header_bytes)?;
        *buffer_bytes_read += more_header_bytes.len();

        let size = u16::from_le_bytes(header_bytes[0..2].try_into().unwrap());
        let payload_size = usize::from(size) - (header_bytes.len() + more_header_bytes.len());

        let event_trace_header = EventTraceHeader {
            size,
            header_type: header_bytes[2].into(),
            marker_flags: header_bytes[3],
            class_type: more_header_bytes[0],
            class_level: more_header_bytes[1],
            class_version: u16::from_le_bytes(more_header_bytes[2..4].try_into().unwrap()),
            thread_id: u32::from_le_bytes(more_header_bytes[4..8].try_into().unwrap()),
            process_id: u32::from_le_bytes(more_header_bytes[8..12].try_into().unwrap()),
            time_stamp: i64::from_le_bytes(more_header_bytes[12..20].try_into().unwrap()),
            guid: WindowsGuid::try_from(&more_header_bytes[20..36]).unwrap(),
            kernel_time: u32::from_le_bytes(more_header_bytes[36..40].try_into().unwrap()),
            user_time: u32::from_le_bytes(more_header_bytes[40..44].try_into().unwrap()),
        };

        let mut payload = vec![0u8; payload_size];
        buffer_reader.read_exact(&mut payload)?;
        *buffer_bytes_read += payload.len();

        return Ok(TraceEvent::EventTrace(EventTrace {
            header: event_trace_header,
            payload,
        }));
    } else if trace_header_type.is_event_header() {
        let mut more_header_bytes = [0u8; 76];
        buffer_reader.read_exact(&mut more_header_bytes)?;
        *buffer_bytes_read += more_header_bytes.len();

        let size = u16::from_le_bytes(header_bytes[0..2].try_into().unwrap());
        let payload_size = usize::from(size) - (header_bytes.len() + more_header_bytes.len());

        let event_header = EventHeader {
            size,
            header_type: header_bytes[2].into(),
            marker_flags: header_bytes[3],
            flags: u16::from_le_bytes(more_header_bytes[0..2].try_into().unwrap()),
            event_property: u16::from_le_bytes(more_header_bytes[2..4].try_into().unwrap()),
            thread_id: u32::from_le_bytes(more_header_bytes[4..8].try_into().unwrap()),
            process_id: u32::from_le_bytes(more_header_bytes[8..12].try_into().unwrap()),
            time_stamp: i64::from_le_bytes(more_header_bytes[12..20].try_into().unwrap()),
            provider_id: WindowsGuid::try_from(&more_header_bytes[20..36]).unwrap(),
            event_descriptor: EventDescriptor {
                id: u16::from_le_bytes(more_header_bytes[36..38].try_into().unwrap()),
                version: more_header_bytes[38],
                channel: more_header_bytes[39],
                level: more_header_bytes[40],
                opcode: more_header_bytes[41],
                task: u16::from_le_bytes(more_header_bytes[42..44].try_into().unwrap()),
                keyword: u64::from_le_bytes(more_header_bytes[44..52].try_into().unwrap()),
            },
            kernel_time: u32::from_le_bytes(more_header_bytes[52..56].try_into().unwrap()),
            user_time: u32::from_le_bytes(more_header_bytes[56..60].try_into().unwrap()),
            activity_id: WindowsGuid::try_from(&more_header_bytes[60..76]).unwrap(),
        };

        let mut payload = vec![0u8; payload_size];
        buffer_reader.read_exact(&mut payload)?;
        *buffer_bytes_read += payload.len();

        return Ok(TraceEvent::Event(Event {
            header: event_header,
            payload,
        }));
    }

    Err(EtlError::UnknownHeaderType(trace_header_type))
}


/// Decodes an ETW timestamp as a duration.
pub(crate) fn decode_timestamp_duration(etw_timestamp: i64) -> Duration {
    // 1 unit is 100ns
    // obtain the absolute value to escape any stupid behavior regarding % with negative numbers
    let (abs_timestamp, negate) = if etw_timestamp < 0 {
        (-etw_timestamp, true)
    } else {
        (etw_timestamp, false)
    };
    let abs_duration_since_epoch =
        Duration::microseconds(abs_timestamp / 10)
        + Duration::nanoseconds((abs_timestamp % 10) * 100)
    ;
    if negate {
        -abs_duration_since_epoch
    } else {
        abs_duration_since_epoch
    }
}


/// Decodes an ETW timestamp.
pub(crate) fn decode_timestamp(etw_timestamp: i64) -> DateTime<Utc> {
    // timestamp: 100ns units since 1601-01-01 00:00:00 UTC
    let base_date_time_naive = NaiveDate::from_ymd_opt(1601, 1, 1).unwrap()
        .and_hms_opt(0, 0, 0).unwrap();
    let base_date_time = Utc.from_utc_datetime(&base_date_time_naive);

    let duration = decode_timestamp_duration(etw_timestamp);
    base_date_time + duration
}


#[cfg(test)]
mod tests {
    use super::WindowsGuid;

    #[test]
    fn test_guid_from_u128() {
        assert_eq!(WindowsGuid::from(0x01234567_89AB_CDEF_0123_456789ABCDEFu128).to_string(), "01234567-89AB-CDEF-0123-456789ABCDEF");
    }
}
