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
    // use std::time::Instant;
    // let now = Instant::now();

    // let _gathered =
    //     checksum_helper::gather::gather(&Path::new("L:\\"), |_| true)
    //     .unwrap();

    // let elapsed = now.elapsed();
    // println!("Elapsed: {:.2?}", elapsed);
    // println!("Items {}", _gathered.file_tree.len());
    // let mem_overhead =
    //     std::mem::size_of::<checksum_helper::file_tree::Entry>()
    //     * (_gathered.file_tree.cap() - _gathered.file_tree.len());
    // println!("MemOverhead {}", mem_overhead);
    // println!("{}", _gathered.file_tree);
    // // pause();
    // // vec 61 mb = 64126K - 1468192
    // // FT add 22 mb = 25664K - 2757744

    // let mut ch = checksum_helper::ChecksumHelper::new(
    //     std::env::current_dir().as_ref().unwrap());
    // let discover = ch.discover_hash_files(None).unwrap();
    // for p in discover.hash_file_paths {
    //     println!("Found {:?}", p);
    // }
    // for e in discover.errors {
    //     println!("ERR: {:?}", e);
    // }
    // let inc = ch.incremental();
    // inc.write(&Path::new("hash.cshd"));
    // let ser = std::fs::read_to_string("obsidian_2024-09-28.cshd").unwrap();
    // let sorted = checksum_helper::collection::sort_serialized(&ser).unwrap();
    // println!("{}", sorted);
    // std::hint::black_box(sorted);

    // Get first CLI argument as the path
    let arg_path = std::env::args().nth(1).expect("Usage: program <path>");
    let abs_path = Path::new(&arg_path)
        .canonicalize()
        .unwrap();

    let mut ch = checksum_helper::ChecksumHelper::new(&abs_path)
        .expect("Failed to create ChecksumHelper");

    ch.build_most_current(|p| {
        println!("{:?}", p);
    }).expect("Failed to build most current");
}
