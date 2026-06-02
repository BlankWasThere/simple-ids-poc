use std::{
    fmt, fs,
    io::{self, BufRead, BufReader, Write},
    sync::Barrier,
    thread,
};

use pcap::{Active, Capture, Device, Error::TimeoutExpired, Packet};

fn main() {
    let signatures = read_signatures();
    let devices = Device::list()
        .expect("unable to list network interfaces")
        .into_iter()
        .filter(|device| !device.addresses.is_empty())
        // .filter(|device| device.name.contains("Loopback"))
        .collect::<Vec<_>>();

    let barrier = Barrier::new(devices.len() + 1);

    thread::scope(|s| {
        for device in devices {
            let capture = Capture::from_device(device)
                .unwrap()
                .immediate_mode(true)
                .open()
                .unwrap();

            s.spawn(|| process_capture(capture, &signatures, &barrier));
        }

        barrier.wait();

        println!("Listening for known signatures...")
    })
}

fn read_signatures() -> Vec<String> {
    const SIGNATURES_FILE_NAME: &str = "signatures.sig";

    let file = fs::File::open(SIGNATURES_FILE_NAME)
        .unwrap_or_else(|err| panic!("unable to open file: {SIGNATURES_FILE_NAME:?} ({err:?})"));
    let reader = BufReader::new(file);

    let lines = reader
        .lines()
        .collect::<std::io::Result<Vec<String>>>()
        .unwrap();

    lines
        .into_iter()
        .filter_map(|s| {
            let s = s.trim();
            (!s.is_empty()).then(|| s.to_owned())
        })
        .collect()
}

fn process_capture(mut cap: Capture<Active>, signatures: &[String], barrier: &Barrier) {
    barrier.wait();

    loop {
        match cap.next_packet() {
            Ok(packet) => process_packet(&packet, signatures),
            Err(TimeoutExpired) => continue,
            Err(e) => {
                panic!("{}", e);
            }
        };
    }
}

fn process_packet(packet: &Packet, signatures: &[String]) {
    let data = packet.data;
    for sig in signatures {
        let sig_bytes = sig.as_bytes();

        if data
            .windows(sig_bytes.len())
            .any(|window| window == sig_bytes)
        {
            alert(sig);
        }
    }
}

fn alert(signature: impl fmt::Debug) {
    io::stdout().write_all(&[0x07]).unwrap(); // Bell character \a
    println!("[ALERT] Known signature found!: {signature:?}")
}
