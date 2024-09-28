use rustls::{client::danger::{DangerousClientConfigBuilder, ServerCertVerifier}, ConfigBuilder, RootCertStore};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use serde_json::json;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            intermediates: &[rustls::pki_types::CertificateDer<'_>],
            server_name: &rustls::pki_types::ServerName<'_>,
            ocsp_response: &[u8],
            now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![]
    }

    fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    
        
    }

    fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
}




#[derive(Error, Debug)]
pub enum NVDARemoteError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(#[from] tokio_rustls::rustls::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub enum ConnectionType {
    Master,
    Slave,
}

impl ConnectionType {
    pub fn to_string(&self) -> String {
        match self {
            ConnectionType::Master => "master".to_string(),
            ConnectionType::Slave => "slave".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventType {
    Motd(String),
    ChannelJoined(i32),
    ChannelLeft,
    ChannelMessage(String, i32),
    ClientJoined(i32, String),
    ClientLeft(i32),
    Beep(i32, i32, i32, i32),
    Invalid(String),
}

pub struct NVDARemote {
    pub host: String,
    pub port: u16,
    pub channel: String,
    pub connection_type: String,
    soc: tokio_rustls::client::TlsStream<TcpStream>,
    pressed_keys: HashSet<(i32, i32, bool)>,
    uid: i32,
    event_callback: Option<Box<dyn Fn(EventType) + Send>>,
}

impl NVDARemote {
    pub async fn new(
        host: &str,
        key: &str,
        connection_type: ConnectionType,
        port: u16,
    ) -> Result<Self, NVDARemoteError> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(addr).await?;

        // Create the TLS connector, bypassing certificate validation
        let config = std::sync::Arc::new(rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(NoCertificateVerification)).with_no_client_auth()
        );
        let tls_connector = tokio_rustls::TlsConnector::from(config);
        let domain = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let soc = tls_connector.connect(domain, stream).await?;  // Here is the error!

        Ok(Self {
            host: host.to_string(),
            port,
            channel: key.to_string(),
            connection_type: connection_type.to_string(),
            soc,
            pressed_keys: HashSet::new(),
            uid: 0,
            event_callback: None,
        })
    }
    
    pub async fn join(&mut self) {
        self.send(json!({"type": "protocol_version", "version": 2})).await;
        self.send(json!({"type": "join", "channel": self.channel, "connection_type": self.connection_type})).await;
    }

    pub async fn send(&mut self, message: serde_json::Value) {
        let msg = message.to_string() + "\n";
        self.soc.write_all(msg.as_bytes()).await.unwrap();
    }

    pub async fn update(&mut self) -> Option<EventType> {
        let mut buf = String::new();
        let mut reader = BufReader::new(&mut self.soc);

        if let Ok(bytes_read) = reader.read_line(&mut buf).await {
            if bytes_read == 0 {
                return None; // Disconnected
            }

            let event = self.parse(buf).await;
            if let Some(callback) = &self.event_callback {
                callback(event.clone());
            }

            Some(event)
        } else {
            None
        }
    }

    pub async fn parse(&mut self, data: String) -> EventType {
        let j: serde_json::Value = serde_json::from_str(&data).unwrap();
        match j["type"].as_str() {
            Some("motd") => EventType::Motd(j["motd"].as_str().unwrap().to_string()),
            Some("channel_joined") => {
                self.uid = j["origin"].as_i64().unwrap() as i32;
                EventType::ChannelJoined(self.uid)
            }
            Some("channel_left") => {
                self.uid = 0;
                EventType::ChannelLeft
            }
            Some("tone") => EventType::Beep(
                j["hz"].as_i64().unwrap() as i32,
                j["length"].as_i64().unwrap() as i32,
                j["left"].as_i64().unwrap() as i32,
                j["right"].as_i64().unwrap() as i32,
            ),
            _ => EventType::Invalid(data),
        }
    }

    pub fn set_event_callback<F>(&mut self, callback: F)
    where
        F: Fn(EventType) + Send + 'static,
    {
        self.event_callback = Some(Box::new(callback));
    }
}

// This struct implements a dummy verifier that disables certificate validation.


