use std::process;
use vcs::*;

fn main() {
    if let Err(err) = setup_dir_structure() {
        println!("{}", err);
        process::exit(1)
    }

    let command = match Cmd::new() {
        Ok(cmd) => cmd,
        Err(err) => {
            println!("{}", err);
            process::exit(1);
        }
    };

    if let Err(err) = command.execute() {
        println!("{}", err);
        process::exit(1)
    }
}
