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
