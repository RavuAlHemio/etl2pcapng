use core::fmt;


/// Windows chaotic-endian GUID encoding.
///
/// Reconstructed from [Microsoft's GUID documentation](https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid).
///
/// [Raymond Chen explains](https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221) how that used to make sense for version-1 GUIDs.
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


/// WMI Node Header for Windows 5.0 (Windows 2000).
///
/// Reconstructed from [Geoff Chappell's article on WMI_BUFFER_HEADER](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/wmi_buffer_header.htm).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct WNodeHeader50 {
    pub reserved1: u64,
    pub reserved2: u64,
    pub reserved3: u64,

    // TODO
    //pub list_entry
    pub buffer_size: u32,
    pub provider_id: u32,

    // union:
    //   variant:
    pub historical_context: u64,
    //   variant:
    pub version: u32,
    pub linkage: u32,

    // union:
    //   variant:
    pub kernel_handle: u64,
    //   variant:
    pub timestamp: u64,

    pub guid: WindowsGuid,
    pub client_context: u32,
    pub flags: u32,
}


/// WMI Buffer Header for Windows 5.0 (Windows 2000).
///
/// Reconstructed from [Geoff Chappell's article on WMI_BUFFER_HEADER](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/wmi_buffer_header.htm).
#[derive(Clone, Copy)]
pub(crate) struct WmiBufferHeader50 {
    pub wnode_header: WNodeHeader50,

}
