use chrono::prelude::*;
use mbedtls::hash::Type::Sha256;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use mbedtls::x509::certificate::{Builder};
use mbedtls::x509::Time;

use std::time::{SystemTime, UNIX_EPOCH};

macro_rules! ALPN_H1 {
    () => {
        "http/1.1"
    };
}
macro_rules! ALPN_H2 {
    () => {
        "h2"
    };
}

pub const ALPN_LIST: &[&str] = &[concat!(ALPN_H2!(), "\0"), concat!(ALPN_H1!(), "\0")];

const RSA_KEY_SIZE: u32 = 2048;
const RSA_KEY_EXP: u32 = 0x3;
const DAYS_TO_SECS: u64 = 86400;
const CERT_VAL_SECS: u64 = 365 * DAYS_TO_SECS;

trait ToTime {
    fn to_time(&self) -> Time;
}

impl ToTime for chrono::DateTime<Utc> {
    fn to_time(&self) -> Time {
        Time::new(
            self.year() as _,
            self.month() as _,
            self.day() as _,
            self.hour() as _,
            self.minute() as _,
            self.second() as _,
        )
        .unwrap()
    }
}

fn get_validity() -> (Time, Time) {
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let end = start + CERT_VAL_SECS;
    let not_before = Utc.timestamp(start as _, 0);
    let not_after = Utc.timestamp(end as _, 0);
    (not_before.to_time(), not_after.to_time())
}

pub fn get_key_and_cert() -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, RSA_KEY_SIZE, RSA_KEY_EXP).unwrap();
    let key_der = key.write_private_der_vec().unwrap();
    let mut issuer_key = Pk::from_private_key(&key_der, None).unwrap();
    let (not_before, not_after) = get_validity();

    let cert_der = Builder::new()
        .subject_key(&mut key)
        .subject_with_nul("CN=localhost\0")
        .unwrap()
        .issuer_key(&mut issuer_key)
        .issuer_with_nul("CN=localhost\0")
        .unwrap()
        .validity(not_before, not_after)
        .unwrap()
        .serial(&[5])
        .unwrap()
        .signature_hash(Sha256)
        .write_der_vec(&mut rng)
        .unwrap();

    let chain = vec![cert_der];
    (key_der, chain)
}
