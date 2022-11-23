//! Functionality for reading ETL tracing files.
//!
//! To read an ETL file, call the following functions in sequence:
//!
//! 1. [read_wmi_buffer_header]
//! 2. [read_event] (obtaining a TRACE_LOGFILE_HEADER)


use std::fmt;
use std::io::{self, Cursor, Read};
use std::string::FromUtf16Error;

use from_to_repr::from_to_other;


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
impl fmt::Display for WindowsGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1, self.data2, self.data3, self.data4[0], self.data4[1], self.data4[2], self.data4[3], self.data4[4], self.data4[5], self.data4[6], self.data4[7],
        )
    }
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

/// A complete system trace event.
///
/// Reconstructed from [Geoff Chappell's description of `TRACE_LOGFILE_HEADER`].
/// 
/// [Geoff Chappell's description of `TRACE_LOGFILE_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/trace_logfile_header.htm)
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SystemTraceEvent {
    pub system_header: SystemTraceHeader,
    pub logfile_header: TraceLogfileHeader,
    pub logger_name: String,
    pub log_file_name: String,
}


/// Any kind of trace event.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TraceEvent {
    System(SystemTraceEvent),
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


/// Reads the bytes of the `WMI_BUFFER_HEADER` structure at the beginning of an ETL file.
///
/// Geoff Chappell has [some documentation on `WMI_BUFFER_HEADER`] on this format; since its content
/// isn't very useful to us and changed dramatically between Windows versions, we simply return it
/// uninterpreted.
///
/// [some documentation on `WMI_BUFFER_HEADER`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/wmi_buffer_header.htm)
pub(crate) fn read_wmi_buffer_header<R: Read>(mut reader: R) -> Result<[u8; 72], EtlError> {
    let mut buf = [0u8; 72];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}


pub(crate) fn read_event<R: Read>(mut reader: R) -> Result<TraceEvent, EtlError> {
    // read 4 header bytes
    let mut header_bytes = [0u8; 4];
    reader.read_exact(&mut header_bytes)?;

    let trace_header_type: TraceHeaderType = header_bytes[2].into();
    if trace_header_type.is_system() {
        let mut more_header_bytes = [0u8; 28];
        let more_header_slice = if trace_header_type.is_system_compact() {
            reader.read_exact(&mut more_header_bytes[0..20])?;
            &more_header_bytes[0..20]
        } else {
            reader.read_exact(&mut more_header_bytes)?;
            &more_header_bytes
        };

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

        // read bytes for the logfile header
        let mut logfile_header_bytes = [0u8; 280];
        let (logfile_header_slice, logger_name_ptr, log_file_name_ptr, time_zone_offset) = if trace_header_type.is_64_bit() {
            reader.read_exact(&mut logfile_header_bytes)?;
            let logger_name_ptr = u64::from_le_bytes(logfile_header_bytes[56..64].try_into().unwrap());
            let log_file_name_ptr = u64::from_le_bytes(logfile_header_bytes[64..72].try_into().unwrap());
            (&logfile_header_bytes[..], logger_name_ptr, log_file_name_ptr, 72)
        } else {
            reader.read_exact(&mut logfile_header_bytes[0..272])?;
            let logger_name_ptr = u32::from_le_bytes(logfile_header_bytes[56..60].try_into().unwrap()).into();
            let log_file_name_ptr = u32::from_le_bytes(logfile_header_bytes[60..64].try_into().unwrap()).into();
            (&logfile_header_bytes[..272], logger_name_ptr, log_file_name_ptr, 64)
        };
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
            reserved_flags: u32::from_le_bytes(logfile_header_slice[time_zone_offset+192..time_zone_offset+196].try_into().unwrap()),
            buffers_lost: u32::from_le_bytes(logfile_header_slice[time_zone_offset+196..time_zone_offset+200].try_into().unwrap()),
        };

        // the payload contains the logger and log file names
        let mut payload_buf = vec![0u8; payload_size];
        reader.read_exact(payload_buf.as_mut_slice())?;

        let mut payload_reader = Cursor::new(&payload_buf);
        let logger_name = read_nul_terminated_utf16_le(&mut payload_reader)?;
        let log_file_name = read_nul_terminated_utf16_le(&mut payload_reader)?;

        return Ok(TraceEvent::System(SystemTraceEvent {
            system_header,
            logfile_header,
            logger_name,
            log_file_name,
        }));
    }

    Err(EtlError::UnknownHeaderType(trace_header_type))
}
