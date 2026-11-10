//! YubiKey HMAC-SHA1 challenge-response через системный HID (Windows, macOS), как в KeePassXC.
//! В Linux ключ работает через USB (`keepass` с фичей `yubikey_usb`), см. `vault.rs`.
//!
//! Протокол OTP-интерфейса: кадр 70 байт (данные 64, команда, CRC16, 3 нуля) уходит пачками
//! по 7 байт в feature-report из 8 байт; последний байт отчёта: флаги и номер пачки.
//! Ответ читается теми же отчётами, пока ключ держит флаг RESP_PENDING.
//! Дополнение challenge совпадает с прежним USB-путём, поэтому база открывается на любой ОС.

// в Linux работает только разбор кадров (тесты), сам HID-путь собирается для Windows и macOS
#![cfg_attr(target_os = "linux", allow(dead_code))]

use std::time::Duration;

const VENDOR_YUBICO: u16 = 0x1050;
const SLOT_WRITE: u8 = 0x80;
const RESP_PENDING: u8 = 0x40;
const SEQ_MASK: u8 = 0x1f;
const CMD_SERIAL: u8 = 0x10;
const CMD_HMAC1: u8 = 0x30;
const CMD_HMAC2: u8 = 0x38;
const CRC_OK: u16 = 0xf0b8;
/// с запасом на ключ, который ждёт касания
const TIMEOUT: Duration = Duration::from_secs(20);

/// CRC-16 ISO 13239, как в прошивке YubiKey.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            let low = crc & 1;
            crc >>= 1;
            if low != 0 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// Challenge переменной длины в 64 байта: нули, или 0xff, если сам challenge кончается нулём
/// (ключ отрезает хвост из одинаковых байт).
pub fn pad(challenge: &[u8]) -> Result<[u8; 64], String> {
    if challenge.len() >= 64 {
        return Err("challenge > 63".into());
    }
    let mut out = if challenge.last() == Some(&0) {
        [0xff; 64]
    } else {
        [0; 64]
    };
    out[..challenge.len()].copy_from_slice(challenge);
    Ok(out)
}

pub fn frame(payload: &[u8; 64], cmd: u8) -> [u8; 70] {
    let mut f = [0u8; 70];
    f[..64].copy_from_slice(payload);
    f[64] = cmd;
    f[65..67].copy_from_slice(&crc16(payload).to_le_bytes());
    f
}

/// Windows: hidapi (родной бэкенд, без C).
#[cfg(windows)]
mod transport {
    use hidapi::{HidApi, HidDevice};

    pub struct Dev(HidDevice);

    impl Dev {
        pub fn get(&self) -> Result<[u8; 8], String> {
            let mut buf = [0u8; 9];
            let n = self
                .0
                .get_feature_report(&mut buf)
                .map_err(|e| e.to_string())?;
            if n < 8 {
                return Err(crate::tr!("YubiKey: короткий ответ").into());
            }
            // первый байт: номер отчёта (0), если система его вернула
            let mut r = [0u8; 8];
            r.copy_from_slice(&buf[n - 8..n]);
            Ok(r)
        }

        pub fn set(&self, report: &[u8; 8]) -> Result<(), String> {
            let mut buf = [0u8; 9];
            buf[1..].copy_from_slice(report);
            self.0.send_feature_report(&buf).map_err(|e| e.to_string())
        }
    }

    /// OTP-интерфейсы YubiKey: для системы это клавиатура (usage page 1, usage 6).
    pub fn open_all() -> Result<Vec<(Dev, Option<String>)>, String> {
        let api = HidApi::new().map_err(|e| e.to_string())?;
        Ok(api
            .device_list()
            .filter(|d| {
                d.vendor_id() == super::VENDOR_YUBICO && d.usage_page() == 1 && d.usage() == 6
            })
            .filter_map(|d| {
                let dev = d.open_device(&api).ok()?;
                Some((Dev(dev), d.product_string().map(str::to_string)))
            })
            .collect())
    }
}

/// macOS: IOKit напрямую, нужны только feature-report-ы.
#[cfg(target_os = "macos")]
mod transport {
    use objc2_core_foundation::{CFNumber, CFRetained, CFString};
    use objc2_io_kit::{IOHIDDevice, IOHIDManager, IOHIDReportType, kIOReturnSuccess};
    use std::ptr::NonNull;

    pub struct Dev(CFRetained<IOHIDDevice>);

    fn number(d: &IOHIDDevice, key: &'static str) -> Option<i32> {
        d.property(&CFString::from_static_str(key))?
            .downcast_ref::<CFNumber>()?
            .as_i32()
    }

    impl Dev {
        pub fn get(&self) -> Result<[u8; 8], String> {
            let mut buf = [0u8; 8];
            let mut len: isize = 8;
            let r = unsafe {
                self.0.report(
                    IOHIDReportType::Feature,
                    0,
                    NonNull::from(&mut buf).cast(),
                    NonNull::from(&mut len),
                )
            };
            if r != kIOReturnSuccess || len < 8 {
                return Err(crate::tr!("YubiKey: короткий ответ").into());
            }
            Ok(buf)
        }

        pub fn set(&self, report: &[u8; 8]) -> Result<(), String> {
            let mut buf = *report;
            let r = unsafe {
                self.0.set_report(
                    IOHIDReportType::Feature,
                    0,
                    NonNull::from(&mut buf).cast(),
                    8,
                )
            };
            if r == kIOReturnSuccess {
                Ok(())
            } else {
                Err(format!("IOHIDDeviceSetReport: {r:#x}"))
            }
        }
    }

    pub fn open_all() -> Result<Vec<(Dev, Option<String>)>, String> {
        let manager = IOHIDManager::new(None, 0);
        unsafe { manager.set_device_matching(None) };
        let Some(set) = manager.devices() else {
            return Ok(vec![]);
        };
        let mut ptrs = vec![std::ptr::null(); set.count() as usize];
        unsafe { set.values(ptrs.as_mut_ptr()) };
        let mut out = vec![];
        for p in ptrs {
            let Some(p) = NonNull::new(p as *mut IOHIDDevice) else {
                continue;
            };
            // множество держит устройство, пока жив manager: берём свою ссылку
            let d = unsafe { CFRetained::retain(p) };
            let ours = number(&d, "VendorID") == Some(super::VENDOR_YUBICO as i32)
                && number(&d, "PrimaryUsagePage") == Some(1)
                && number(&d, "PrimaryUsage") == Some(6);
            if !ours || d.open(0) != kIOReturnSuccess {
                continue;
            }
            let name = d
                .property(&CFString::from_static_str("Product"))
                .and_then(|v| v.downcast_ref::<CFString>().map(|s| s.to_string()));
            out.push((Dev(d), name));
        }
        Ok(out)
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod hid {
    use super::*;
    use std::time::Instant;

    pub struct Key(transport::Dev);

    impl Key {
        fn read(&self) -> Result<[u8; 8], String> {
            self.0.get()
        }

        fn write(&self, report: &[u8; 8]) -> Result<(), String> {
            self.0.set(report)
        }

        fn wait(&self, ok: impl Fn(u8) -> bool) -> Result<[u8; 8], String> {
            let start = Instant::now();
            loop {
                let r = self.read()?;
                if ok(r[7]) {
                    return Ok(r);
                }
                if start.elapsed() > TIMEOUT {
                    return Err(crate::tr!("YubiKey не ответил: коснитесь ключа").into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        fn write_frame(&self, frame: &[u8; 70]) -> Result<(), String> {
            for (seq, chunk) in frame.chunks(7).enumerate() {
                // пустые пачки в середине ключ дополняет сам
                if seq != 0 && seq != 9 && chunk.iter().all(|&b| b == 0) {
                    continue;
                }
                let mut report = [0u8; 8];
                report[..7].copy_from_slice(chunk);
                report[7] = SLOT_WRITE | seq as u8;
                self.wait(|f| f & SLOT_WRITE == 0)?;
                self.write(&report)?;
            }
            Ok(())
        }

        fn read_response(&self) -> Result<Vec<u8>, String> {
            let first = self.wait(|f| f & RESP_PENDING != 0)?;
            let mut resp = first[..7].to_vec();
            loop {
                let r = self.read()?;
                if r[7] & RESP_PENDING == 0 || r[7] & SEQ_MASK == 0 {
                    break;
                }
                resp.extend_from_slice(&r[..7]);
            }
            // сброс состояния записи
            let mut reset = [0u8; 8];
            reset[7] = 0x8f;
            self.write(&reset)?;
            self.wait(|f| f & SLOT_WRITE == 0)?;
            Ok(resp)
        }

        pub fn command(&self, cmd: u8, payload: &[u8; 64], len: usize) -> Result<Vec<u8>, String> {
            self.wait(|f| f & SLOT_WRITE == 0)?;
            self.write_frame(&frame(payload, cmd))?;
            let resp = self.read_response()?;
            if resp.len() < len + 2 || crc16(&resp[..len + 2]) != CRC_OK {
                return Err(crate::tr!("YubiKey: ошибка CRC в ответе").into());
            }
            Ok(resp[..len].to_vec())
        }

        pub fn serial(&self) -> Option<u32> {
            let r = self.command(CMD_SERIAL, &[0; 64], 4).ok()?;
            Some(u32::from_be_bytes([r[0], r[1], r[2], r[3]]))
        }
    }

    pub fn keys() -> Result<Vec<(Key, Option<String>)>, String> {
        Ok(transport::open_all()?
            .into_iter()
            .map(|(d, name)| (Key(d), name))
            .collect())
    }
}

/// Подключённые YubiKey: серийный номер (0, если ключ его не показывает) и имя.
#[cfg(any(windows, target_os = "macos"))]
pub fn list() -> Result<Vec<(u32, Option<String>)>, String> {
    Ok(hid::keys()?
        .into_iter()
        .map(|(k, name)| (k.serial().unwrap_or(0), name))
        .collect())
}

/// HMAC-SHA1 от challenge на ключе с этим серийным номером (или на единственном).
#[cfg(any(windows, target_os = "macos"))]
pub fn challenge(serial: Option<u32>, slot: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    let cmd = match slot {
        1 => CMD_HMAC1,
        2 => CMD_HMAC2,
        _ => return Err(crate::tr!("слот YubiKey: 1 или 2").into()),
    };
    // 0: ключ не показывает серийный номер, берём первый
    let serial = serial.filter(|&s| s != 0);
    let mut keys = hid::keys()?;
    let key = match serial {
        Some(s) => keys
            .into_iter()
            .find(|(k, _)| k.serial() == Some(s))
            .map(|(k, _)| k),
        None => (!keys.is_empty()).then(|| keys.swap_remove(0).0),
    }
    .ok_or_else(|| crate::tr!("YubiKey не найден: вставьте ключ").to_string())?;
    key.command(cmd, &pad(data)?, 20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_and_crc() {
        let p = pad(b"seed").unwrap();
        let f = frame(&p, CMD_HMAC2);
        assert_eq!(&f[..64], &p[..]);
        assert_eq!(f[64], 0x38);
        // в кадр идёт прямой CRC (как в ykpers), в ответ ключ кладёт инвертированный
        assert_eq!(f[65..67], crc16(&p).to_le_bytes());
        assert_eq!(&f[67..], &[0, 0, 0]);
        let mut reply = vec![7u8; 20];
        reply.extend_from_slice(&(!crc16(&reply)).to_le_bytes());
        assert_eq!(crc16(&reply), CRC_OK);
    }

    /// База, сохранённая через `External` (путь Windows и macOS), открывается прежним
    /// `LocalChallenge` с тем же секретом, то есть ответ ключа идёт в ключ базы так же.
    #[test]
    fn external_challenge_is_compatible() {
        use hmac::{Hmac, KeyInit, Mac};
        use keepass::{ChallengeResponseKey, Database, DatabaseKey, ExternalChallenge};
        let secret = [0x42u8; 20];
        let ext = ExternalChallenge(std::sync::Arc::new(move |c: &[u8]| {
            let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&secret).unwrap();
            m.update(c);
            Ok(m.finalize().into_bytes().to_vec())
        }));
        let key = |cr| {
            DatabaseKey::new()
                .with_password("pw")
                .with_challenge_response_key(cr)
        };
        let mut buf = vec![];
        Database::new()
            .save(&mut buf, key(ChallengeResponseKey::External(ext.clone())))
            .unwrap();
        let local = ChallengeResponseKey::LocalChallenge("42".repeat(20));
        Database::open(&mut buf.as_slice(), key(local)).unwrap();
        Database::open(
            &mut buf.as_slice(),
            key(ChallengeResponseKey::External(ext)),
        )
        .unwrap();
        let wrong = ChallengeResponseKey::LocalChallenge("01".repeat(20));
        assert!(Database::open(&mut buf.as_slice(), key(wrong)).is_err());
    }

    #[test]
    fn padding_matches_usb_path() {
        assert_eq!(pad(&[1, 2]).unwrap()[2..], [0; 62]);
        assert_eq!(pad(&[1, 0]).unwrap()[2..], [0xff; 62]);
        assert!(pad(&[0; 64]).is_err());
    }
}
