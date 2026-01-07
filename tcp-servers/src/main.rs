use std::{net::TcpListener, thread};

fn main() -> std::io::Result<()> {
    let socket = TcpListener::bind("127.0.0.1:8000").unwrap();
    let mut connections = vec![];
    while let Some(Ok(conn)) = socket.incoming().next() {
        let connection_handler = thread::spawn(move || {
            let _ = handle_connection(conn);
        });

        connections.push(connection_handler);
    }

    for handle in connections {
        let _ = handle.join();
    }
    Ok(())
}

fn handle_connection(mut stream: std::net::TcpStream) -> std::io::Result<()> {
    use std::io::Read;
    let mut buffer = [0; 30];

    loop {
        let n = stream.read(&mut buffer[..])?;
        println!("The bytes: {:?}", &buffer[..n]);
        if n == 0 {
            break Ok(());
        }
    }
}
