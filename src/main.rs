mod etl;
mod ndiscap;


use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::path::PathBuf;

use clap::Parser;

use crate::etl::{decode_timestamp, read_wmi_buffer, read_event, TraceEvent};
use crate::ndiscap::{decode_event, NdisCaptureEvent};


#[derive(Parser)]
struct Opts {
    pub etl_file: PathBuf,
}


fn main() {
    let opts = Opts::parse();

    let file = File::open(&opts.etl_file)
        .expect("failed to open ETL file");
    let mut file_reader = BufReader::new(file);

    // read ETL file
    let mut start_time_value = 0;
    let mut timestamp_scale = 1.0;
    let mut base_time = None;
    let mut packets = Vec::new();
    loop {
        let inner_buf = file_reader.fill_buf()
            .expect("failed to obtain contents of inner buffer");
        if inner_buf.len() == 0 {
            break;
        }

        let buffer = read_wmi_buffer(&mut file_reader, false)
            .expect("failed to read WMI buffer");
        eprintln!("new buffer with {} bytes of payload and {} bytes of padding", buffer.payload.len(), buffer.padding.len());
        let mut buffer_cursor = Cursor::new(&buffer.payload);

        loop {
            let event = read_event(&mut buffer_cursor)
                .expect("failed to read event");
            match &event {
                TraceEvent::TraceLogfileHeader(tlh) => {
                    start_time_value = tlh.logfile_header.start_time;
                    timestamp_scale = tlh.logfile_header.time_stamp_scale();
                },
                TraceEvent::Event(evt) => {
                    // base time calculation is outlined in the "Remarks" section of Microsoft's WNODE_HEADER docs
                    if !base_time.is_some() {
                        base_time = Some(decode_timestamp(
                            start_time_value - ((timestamp_scale * (evt.header.time_stamp as f64)) as i64)
                        ));
                    }

                    let decoded = decode_event(evt, base_time.unwrap(), timestamp_scale)
                        .expect("failed to decode event");
                    if let NdisCaptureEvent::PacketData(data_event) = decoded {
                        packets.push(data_event);
                    }
                },
                _ => {},
            }
            if buffer_cursor.position() == u64::try_from(buffer.payload.len()).unwrap() {
                break;
            }
        }
    }

    packets.sort_unstable_by_key(|p| p.event_metadata.timestamp);
}
