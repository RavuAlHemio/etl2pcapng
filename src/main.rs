mod etl;


use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use clap::Parser;

use crate::etl::{read_wmi_buffer_header, read_event};


#[derive(Parser)]
struct Opts {
    pub etl_file: PathBuf,
}


fn main() {
    let opts = Opts::parse();

    let file = File::open(&opts.etl_file)
        .expect("failed to open ETL file");
    let mut file_reader = BufReader::new(file);

    read_wmi_buffer_header(&mut file_reader)
        .expect("failed to read ETL header");
    let header_event = read_event(&mut file_reader)
        .expect("failed to read header event");
    eprintln!("{:#?}", header_event);
}
