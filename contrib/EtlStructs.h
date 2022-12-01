typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef long int32_t;    
typedef unsigned long uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

public struct WindowsGuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

struct EtwBufferContext {
    uint16_t processor_index;
    uint16_t logger_id;
};

public struct WmiBufferHeader {
    uint32_t buffer_size;
    uint32_t saved_offset;
    uint32_t current_offset;
    int32_t reference_count;
    int64_t time_stamp;
    int64_t sequence_number;
    uint64_t clock_type : 3;
    uint64_t frequency : 61;
    EtwBufferContext context;
    uint32_t padding0;
    uint32_t offset;
    uint16_t buffer_flag;
    uint16_t buffer_type;
    uint8_t union_of_pretty_much_everything[16];
};

public struct EventInstanceGuidHeader {
    uint16_t size;
    uint16_t field_type_flags;
    uint32_t version;
    uint32_t thread_id;
    uint32_t process_id;
    int64_t time_stamp;
    WindowsGuid guid;
};

public struct SystemTraceHeaderCompact
{
    uint16_t version;
    uint8_t trace_header_type;
    uint8_t flags;
    uint16_t size;
    uint16_t hook_id;
    uint32_t thread_id;
    uint32_t process_id;
    int64_t system_time;
};

public struct SystemTraceHeader
{
    SystemTraceHeaderCompact compact_header;
    uint32_t kernel_time;
    uint32_t user_time;
};

struct EventDescriptor
{
    uint16_t id;
    uint8_t version;
    uint8_t channel;
    uint8_t level;
    uint8_t opcode;
    uint16_t task;
    uint64_t keyword;
};

public struct EventHeader
{
    uint16_t size;
    uint16_t header_type;
    uint16_t flags;
    uint16_t event_property;
    uint32_t thread_id;
    uint32_t process_id;
    int64_t time_stamp;
    WindowsGuid provider_id;
    EventDescriptor event_descriptor;
    uint32_t kernel_time;
    uint32_t user_time;
    WindowsGuid activity_id;
};

struct SystemTime {
    uint16_t year;
    uint16_t month;
    uint16_t day_of_week;
    uint16_t day;
    uint16_t hour;
    uint16_t minute;
    uint16_t second;
    uint16_t milliseconds;
};

struct TimeZoneInformation {
    int32_t bias;
    wchar_t standard_name[32];
    SystemTime standard_date;
    int32_t standard_bias;
    wchar_t daylight_name[32];
    SystemTime daylight_date;
    int32_t daylight_bias;
};

public struct TraceLogfileHeader {
    uint32_t buffer_size;
    uint8_t version[4];
    uint32_t provider_version;
    uint32_t num_processors;
    int64_t end_time;
    uint32_t timer_resolution;
    uint32_t max_file_size;
    uint32_t log_file_mode;
    uint32_t buffers_written;

    uint32_t start_buffers;
    uint32_t pointer_size;
    uint32_t events_lost;
    uint32_t cpu_speed_mhz;

    uint64_t logger_name_ptr;
    uint64_t log_file_name_ptr;

    TimeZoneInformation time_zone;
    uint32_t padding0;
    int64_t boot_time;
    int64_t perf_freq;
    int64_t start_time;
    uint32_t reserved_flags;
    uint32_t buffers_lost;
};

public struct EventTraceHeader
{
    uint16_t size;
    uint8_t header_type;
    uint8_t marker_flags;
    uint8_t class_type;
    uint8_t class_level;
    uint16_t class_version;
    uint32_t thread_id;
    uint32_t process_id;
    int64_t time_stamp;
    WindowsGuid guid;
    uint32_t kernel_time;
    uint32_t user_time;
};
