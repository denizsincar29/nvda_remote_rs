# nvda_remote_rs
An NVDA remote client library written in Rust.

## Current status
Currently, the library simply does not work, since i used rustls from ground up, and realized that it doesn't support tls 1.0 / 1.1, which is not supported by rustls.
The project is currently on hold, but I will be more than happy to accept PRs.

## Usage
```rust
use nvda_remote::{ConnectionType, NVDARemote, NVDARemoteError};

#[tokio::main]
async fn main() -> Result<(), NVDARemoteError> {
    // read key from environment variable
    let key = std::env::var("NVDAREMOTE_KEY").expect("NVDAREMOTE_KEY not set");
    let mut nvda_remote = NVDARemote::new("nvdaremote.com", &key, ConnectionType::Slave, 6837).await?;
    
    nvda_remote.join().await;

    loop {
        if let Some(event) = nvda_remote.update().await {
            println!("Processed event: {:?}", event);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
```

