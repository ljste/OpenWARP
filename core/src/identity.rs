use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use boring::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    ssl::{SslAlert, SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode},
    x509::X509,
};
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Identity {
    key: String,
    peer: String,
    #[serde(rename = "IPv4")]
    pub ipv4: Ipv4Addr,
    #[serde(rename = "IPv6")]
    pub ipv6: Ipv6Addr,
    pub endpoint4: Ipv4Addr,
    pub endpoint6: Ipv6Addr,
}

impl Identity {
    pub fn validate(&self) -> Result<()> {
        let client = self.ipv4.octets();
        ensure!(
            client[0] == 172 && (16..32).contains(&client[1]),
            "Unexpected WARP IPv4 address"
        );
        ensure!(
            self.ipv6.segments()[..2] == [0x2606, 0x4700],
            "Unexpected WARP IPv6 address"
        );
        let edge = self.endpoint4.octets();
        ensure!(
            edge[..2] == [162, 159] && (192..208).contains(&edge[2]),
            "Unexpected WARP IPv4 endpoint"
        );
        ensure!(
            self.endpoint6.segments()[..2] == [0x2606, 0x4700],
            "Unexpected WARP IPv6 endpoint"
        );
        Ok(())
    }

    pub fn transport_config(&self) -> Result<quiche::Config> {
        self.validate()?;
        let key = PKey::private_key_from_der(&STANDARD.decode(&self.key)?)?;
        let pin = STANDARD.decode(&self.peer)?;
        PKey::public_key_from_der(&pin).context("Invalid enrollment pin")?;
        let mut cert = X509::builder()?;
        let number = BigNum::from_u32(1)?;
        let serial = Asn1Integer::from_bn(&number)?;
        cert.set_serial_number(&serial)?;
        cert.set_pubkey(&key)?;
        let start = Asn1Time::days_from_now(0)?;
        let end = Asn1Time::days_from_now(1)?;
        cert.set_not_before(&start)?;
        cert.set_not_after(&end)?;
        cert.sign(&key, MessageDigest::sha256())?;

        let mut tls = SslContextBuilder::new(SslMethod::tls())?;
        tls.set_curves_list("P256Kyber768Draft00")?;
        tls.set_private_key(&key)?;
        tls.set_certificate(&cert.build())?;
        tls.check_private_key()?;
        tls.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let received = ssl
                .peer_cert_chain()
                .and_then(|chain| chain.get(0))
                .and_then(|cert| cert.public_key().ok())
                .and_then(|key| key.public_key_to_der().ok());
            if received.as_deref() == Some(pin.as_slice()) {
                Ok(())
            } else {
                Err(SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))
            }
        });
        let mut config =
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls)?;
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(60_000);
        config.set_max_recv_udp_payload_size(1400);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(512 * 1024);
        config.set_initial_max_stream_data_bidi_local(64 * 1024);
        config.set_initial_max_stream_data_uni(64 * 1024);
        config.set_initial_max_streams_bidi(8);
        config.set_initial_max_streams_uni(8);
        config.enable_dgram(true, 128, 128);
        Ok(config)
    }
}
