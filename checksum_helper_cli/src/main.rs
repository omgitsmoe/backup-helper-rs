use checksum_helper;

use std::path::Path;

use std::io::prelude::*;

fn pause() {
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}

fn main() {
    use std::time::Instant;
    let now = Instant::now();

    let _gathered =
        checksum_helper::gather::gather(&Path::new("L:\\"), |_| true)
        .unwrap();

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
    println!("Items {}", _gathered.file_tree.len());
    let mem_overhead =
        std::mem::size_of::<checksum_helper::file_tree::Entry>()
        * (_gathered.file_tree.cap() - _gathered.file_tree.len());
    println!("MemOverhead {}", mem_overhead);
    println!("{}", _gathered.file_tree);
    // pause();
    // vec 61 mb = 64126K - 1468192
    // FT add 22 mb = 25664K - 2757744
}
