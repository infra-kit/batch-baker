use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use crate::destroy::{deadline_reached, delete_instance, Retry, TtlConfig};

fn serve(status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 2048];
        let _ = sock.read(&mut buf);
        let body = format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\nok");
        let _ = sock.write_all(body.as_bytes());
    });
    format!("http://{addr}")
}

fn config(api: &str) -> TtlConfig {
    TtlConfig {
        provider: "digitalocean".into(),
        instance_id: "42".into(),
        deadline: "2000-01-01T00:00:00Z".into(),
        api: api.into(),
        token: "secret-token".into(),
    }
}

#[test]
fn past_deadline_is_reached() {
    assert!(deadline_reached("2000-01-01T00:00:00Z").unwrap());
}

#[test]
fn future_deadline_is_not_reached() {
    assert!(!deadline_reached("2999-01-01T00:00:00Z").unwrap());
}

#[test]
fn delete_treats_404_as_success() {
    let api = serve(404);
    delete_instance(
        &config(&api),
        Retry {
            attempts: 1,
            delay: Duration::from_millis(1),
        },
    )
    .unwrap();
}

#[test]
fn delete_retries_then_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf);
            let body = "HTTP/1.1 500 X\r\nContent-Length: 4\r\nConnection: close\r\n\nfail";
            let _ = sock.write_all(body.as_bytes());
        }
    });
    let err = delete_instance(
        &config(&format!("http://{addr}")),
        Retry {
            attempts: 2,
            delay: Duration::from_millis(1),
        },
    )
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("500"), "{message}");
    assert!(!message.contains("secret-token"));
}

#[test]
fn unknown_provider_is_rejected() {
    let mut cfg = config("http://127.0.0.1:1");
    cfg.provider = "gcp".into();
    let err = delete_instance(
        &cfg,
        Retry {
            attempts: 1,
            delay: Duration::from_millis(1),
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("gcp"));
}
