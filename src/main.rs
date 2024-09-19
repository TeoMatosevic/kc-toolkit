use std::env;

use kc_toolkit::{error, parse_args};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("No command provided. Use 'help' for more information.");
        return;
    }

    let args = &args[1..];

    match parse_args(args.to_vec()) {
        Ok(res) => {
            if res.ends_with("\n") {
                print!("{}", res);
            } else {
                println!("{}", res);
            }
        }
        Err(e) => {
            if e.ends_with("\n") {
                print!("{}", error(&e));
            } else {
                println!("{}", error(&e));
            }
        }
    }
}
