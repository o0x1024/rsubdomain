use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rsubdomain")]
#[command(author = "gelenlen")]
#[command(version = "1.0")]
#[command(about = "A tool for brute-forcing subdomains", long_about = None,arg_required_else_help = true)]
pub struct Opts {
    /// Name of the person to greet
    #[arg(short, long)]
    pub domain: String,

}
