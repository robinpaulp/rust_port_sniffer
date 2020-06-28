use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

// Usage:
// ip_sniffer -h
// ip_sniffer -j <thread_count> <ip address>
// ip_sniffer <ip address>

const MAX_PORTS: u16 = 65535;

struct Arguments {
    flag: String,
    ipaddr: IpAddr,
    threads: u16,
}
impl Arguments {
    fn new(args: &Vec<String>) -> Result<Arguments, &str> {
        if args.len() > 4 {
            return Err("Too many arguments!!");
        }
        if args.len() < 2 {
            return Err("Too few arguments!!");
        }
        if let Ok(ipaddr) = IpAddr::from_str(&args[1]) {
            return Ok(Arguments {
                flag: String::from(""),
                ipaddr,
                threads: 4,
            });
        } else {
            let flag = &args[1];
            if flag.eq("-j") && args.len() > 3 {
                if let Ok(threads) = u16::from_str(&args[2]) {
                    if let Ok(ipaddr) = IpAddr::from_str(&args[3]) {
                        return Ok(Arguments {
                            flag: flag.clone(),
                            ipaddr,
                            threads,
                        });
                    } else {
                        return Err("Not a valid IP address!!");
                    }
                } else {
                    return Err("Argument for -j option should be an integer!!");
                }
            }
        }

        println!("Usage:");
        println!("\tip_sniffer -h");
        println!("\tip_sniffer -j <thread_count> <ip address>");
        println!("\tip_sniffer <ip address>");
        return Err("This is the help!!");
    }
}
fn main() {
    println!("Hello, world!");
    let args: Vec<String> = env::args().collect();

    // let program = &args[0];
    let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        println!("{}", err);
        process::exit(0);
    });

    let num_threads = arguments.threads;
    let (tx, rx) = channel();
    for i in 0..num_threads {
        let tx = tx.clone();
        let ipaddr = arguments.ipaddr;
        thread::spawn(move || {
            scan(tx, ipaddr, i, num_threads);
        });
    }

    drop(tx);
    let mut open_ports = vec![];
    for p in rx {
        open_ports.push(p);
    }

    open_ports.sort();
    println!("Open ports are:");
    println!("{:?}", open_ports);
}

fn scan(tx: Sender<u16>, ipaddr: IpAddr, thread_index: u16, num_threads: u16) {
    let mut cur_port = thread_index + 1;
    loop {
        if let Ok(_) = TcpStream::connect_timeout(
            &SocketAddr::from((ipaddr, cur_port)),
            Duration::from_millis(1000),
        ) {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(cur_port).unwrap();
        }
        if (MAX_PORTS - cur_port) <= num_threads {
            // println!("Exiting thread {}", thread_index);
            // io::stdout().flush().unwrap();
            break;
        }
        cur_port += num_threads;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arg_parsing() {
        let arg = Arguments::new(&vec![
            "name".to_string(),
            "-j".to_string(),
            "10".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        assert_eq!(arg.flag, "-j");
        assert_eq!(arg.threads, 10);
        assert_eq!(arg.ipaddr, IpAddr::from_str("127.0.0.1").unwrap());
    }
}
