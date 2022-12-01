mod etl;


use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::path::PathBuf;

use clap::Parser;

use crate::etl::{read_wmi_buffer, read_event, TraceEvent};


#[derive(Parser)]
struct Opts {
    pub etl_file: PathBuf,
}


fn main() {
    let opts = Opts::parse();

    let file = File::open(&opts.etl_file)
        .expect("failed to open ETL file");
    let mut file_reader = BufReader::new(file);

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
                TraceEvent::Event(hdr, _payload) => {
                    eprintln!("event with header: {:#?}", hdr);
                },
                _ => {},
            }
            if buffer_cursor.position() == u64::try_from(buffer.payload.len()).unwrap() {
                break;
            }
        }
    }
}
