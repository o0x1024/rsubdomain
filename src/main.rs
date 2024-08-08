
use clap::Parser;
use rsubdomain::input::Opts;

#[tokio::main]
async  fn main() {

    let opts = Opts::parse();

    println!("{}",opts.domain);
    
}