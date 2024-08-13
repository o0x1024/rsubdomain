use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rsubdomain")]
#[command(author = "gelenlen")]
#[command(version = "1.0")]
#[command(about = "A tool for brute-forcing subdomains", long_about = None,arg_required_else_help = true)]
pub struct Opts {
    /// need scan domain
    #[arg(short, long)]
    pub domain: Vec<String>,

    /// list network 
    #[arg(short, long)]
    pub list_network: bool,


    /// resolvers path,use default dns on default 
    #[arg(short, long)]
    pub resolvers: Vec<String>,

    

}
