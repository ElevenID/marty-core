use std::io::{self, Read};

use marty_offline_chain_headless::{process_request, Response, MAX_REQUEST_BYTES};

fn main() {
    let mut input = Vec::new();
    // Read one bounded JSON document, with one extra byte to detect overflow.
    let read_result = io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input);
    let (response, exit) = if read_result.is_ok() {
        process_request(&input)
    } else {
        (Response::input_error("failed to read stdin"), 2)
    };
    // Response is made only from fixed messages or verifier diagnostics.
    serde_json::to_writer(io::stdout().lock(), &response).expect("serialize response");
    println!();
    std::process::exit(exit.into());
}
