//! Native messaging host: браузер запускает его и говорит по stdio
//! (4 байта длины little-endian + JSON). Host ничего не расшифровывает: сообщения расширения
//! (keywarden-ext::protocol::Outer, внутри crypto_box) уходят в keywardend как есть.

use anyhow::Result;
use keywarden_core::ipc::{self, Request, Response};
use std::io::{self, Read, Write};

/// Chrome ограничивает сообщение от хоста 1 МБ, входящие до 64 МБ; нам хватит 1 МБ.
const MAX_MSG: usize = 1 << 20;

fn main() -> Result<()> {
    let (mut stdin, mut stdout) = (io::stdin().lock(), io::stdout().lock());
    while let Some(msg) = read_msg(&mut stdin)? {
        let reply = match serde_json::from_slice::<serde_json::Value>(&msg) {
            Ok(message) => match ipc::call(&Request::Browser { message }) {
                Ok(Response::Browser { reply }) => reply,
                Ok(Response::Error { message, .. }) => error("daemon", &message),
                Ok(_) => error("daemon", "неожиданный ответ демона"),
                Err(e) => error("daemon", &format!("keywardend недоступен: {e}")),
            },
            Err(e) => error("invalid", &format!("не JSON: {e}")),
        };
        write_msg(&mut stdout, &serde_json::to_vec(&reply)?)?;
    }
    Ok(())
}

fn error(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "type": "error", "code": code, "message": message })
}

fn read_msg(r: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        res => res?,
    }
    let len = u32::from_le_bytes(len) as usize;
    anyhow::ensure!(len <= MAX_MSG, "message too large: {len}");
    let mut buf = vec![0; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_msg(w: &mut impl Write, body: &[u8]) -> Result<()> {
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrip_and_limits() {
        let mut buf = Vec::new();
        write_msg(&mut buf, br#"{"cmd":"ping"}"#).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_msg(&mut r).unwrap().unwrap(), br#"{"cmd":"ping"}"#);
        assert!(read_msg(&mut r).unwrap().is_none());

        let huge = ((MAX_MSG + 1) as u32).to_le_bytes();
        assert!(read_msg(&mut &huge[..]).is_err());
    }
}
