//! crispus.rs — stratum HTTP et interfacies crispus
//!
//! Praebet CrispusFacilis (manubrium facile), CrispusMulti (manubrium multiplex),
//! et CrispusSlist (index capitum).
//!
//! Multi implementatur per fila (std::thread) loco fork()+pipe().
//!
//! Sine dependentiis externis.

use crate::velum::Velum;
use std::net::TcpStream;
use std::time::Duration;

// ================================================================
//  Codices exitus
// ================================================================

pub const CRISPUSE_OK: i32 = 0;
pub const CRISPUSE_ERRATUM: i32 = 1;
pub const CRISPUSE_CONIUNCTIO: i32 = 7;
pub const CRISPUSE_MEMORIA: i32 = 27;
pub const CRISPUSE_TEMPUS: i32 = 28;

pub const CRISPUSM_OK: i32 = 0;
pub const CRISPUSM_ERRATUM: i32 = -1;

pub const CRISPUSMSG_PERFECTUM: i32 = 1;

// ================================================================
//  Index capitum (slist)
// ================================================================

/// Index capitum — catena coniuncta ut crispus_slist in C
pub struct CrispusSlist {
    pub data: String,
    pub proximus: Option<Box<CrispusSlist>>,
}

/// Adde chordam ad finem indicis. Reddit indicem novum.
pub fn crispus_slist_adde(
    index: Option<Box<CrispusSlist>>,
    chorda: &str,
) -> Option<Box<CrispusSlist>> {
    let novum = Box::new(CrispusSlist {
        data: chorda.to_string(),
        proximus: None,
    });

    match index {
        None => Some(novum),
        Some(mut caput) => {
            // quaere ultimum nodum
            let mut cursor = &mut caput;
            while cursor.proximus.is_some() {
                cursor = cursor.proximus.as_mut().unwrap();
            }
            cursor.proximus = Some(novum);
            Some(caput)
        }
    }
}

// ================================================================
//  Resolutio URL
// ================================================================

struct UrlPartes {
    hospes: String,
    via: String,
    portus: u16,
}

/// Resolve URL in partes (hospes, via, portus)
fn resolve_url(url: &str) -> Option<UrlPartes> {
    let mut s = url;
    let mut portus: u16 = 443;

    // praetermitte schema
    if let Some(post) = s.strip_prefix("https://") {
        s = post;
    } else if let Some(post) = s.strip_prefix("http://") {
        s = post;
        portus = 80;
    }

    // quaere obliquum et duobus punctis
    let obliquus = s.find('/');
    let duobus = s.find(':');

    let hospes_mag;
    if let Some(dp) = duobus {
        if obliquus.is_none() || dp < obliquus.unwrap() {
            hospes_mag = dp;
            let finis = obliquus.unwrap_or(s.len());
            if let Ok(p) = s[dp + 1..finis].parse::<u16>() {
                portus = p;
            }
        } else {
            hospes_mag = obliquus.unwrap();
        }
    } else if let Some(ob) = obliquus {
        hospes_mag = ob;
    } else {
        hospes_mag = s.len();
    }

    let hospes = s[..hospes_mag].to_string();

    let mut via = if let Some(ob) = obliquus {
        s[ob..].to_string()
    } else {
        "/".to_string()
    };

    // remove fragmentum (#...)
    if let Some(idx) = via.find('#') {
        via.truncate(idx);
    }

    Some(UrlPartes {
        hospes,
        via,
        portus,
    })
}

// ================================================================
//  Rogatum HTTP (age_rogatum)
// ================================================================

/// Age rogatum HTTP plenum. Reddit codicem crispus et ponit codex_responsi.
fn age_rogatum(f: &mut CrispusFacilis) -> i32 {
    let url_str = match &f.url {
        Some(u) => u.clone(),
        None => return CRISPUSE_ERRATUM,
    };

    let url = match resolve_url(&url_str) {
        Some(u) => u,
        None => return CRISPUSE_ERRATUM,
    };

    // coniunge per TCP
    let flumen = match TcpStream::connect(format!("{}:{}", url.hospes, url.portus)) {
        Ok(f) => f,
        Err(_) => return CRISPUSE_CONIUNCTIO,
    };

    // tempus maximum
    if f.tempus_maximum > 0 {
        let duratio = Duration::from_secs(f.tempus_maximum);
        let _ = flumen.set_read_timeout(Some(duratio));
        let _ = flumen.set_write_timeout(Some(duratio));
    }

    // TLS per Velum
    let mut vel = Velum::crea(flumen, &url.hospes);

    if vel.saluta() < 0 {
        vel.claude();
        return CRISPUSE_CONIUNCTIO;
    }

    // construi rogatum HTTP
    let methodus = if f.campi_postae.is_some() {
        "POST"
    } else {
        "GET"
    };
    let corpus_mag = f.campi_postae.as_ref().map(|c| c.len()).unwrap_or(0);

    let mut caput = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        methodus, url.via, url.hospes
    );

    // capita usoris
    for c in &f.capita {
        caput.push_str(c);
        caput.push_str("\r\n");
    }

    if f.campi_postae.is_some() {
        caput.push_str(&format!("Content-Length: {}\r\n", corpus_mag));
    }

    caput.push_str("\r\n");

    // mitte caput
    if vel.scribe(caput.as_bytes()) < 0 {
        vel.claude();
        return CRISPUSE_ERRATUM;
    }

    // mitte corpus
    if let Some(ref corpus) = f.campi_postae {
        if !corpus.is_empty() {
            if vel.scribe(corpus.as_bytes()) < 0 {
                vel.claude();
                return CRISPUSE_ERRATUM;
            }
        }
    }

    // lege responsum HTTP — accumula totum
    let mut resp: Vec<u8> = Vec::new();
    let mut alveus = [0u8; 8192];

    loop {
        let lectum = vel.lege(&mut alveus);
        if lectum <= 0 {
            break;
        }
        resp.extend_from_slice(&alveus[..lectum as usize]);
    }

    vel.claude();

    if resp.is_empty() {
        return CRISPUSE_ERRATUM;
    }

    // quaere finem capitum (\r\n\r\n)
    f.codex_responsi = 0;

    let finis_capitum = resp.windows(4).position(|w| w == b"\r\n\r\n");

    let finis_idx = match finis_capitum {
        Some(i) => i + 4,
        None => {
            // nulla capita inventa — trade totum
            if let Some(ref mut functio) = f.scribe_fn {
                functio(&resp);
            }
            return CRISPUSE_OK;
        }
    };

    // lege codicem status: "HTTP/1.1 200 OK\r\n"
    let caput_bytes = &resp[..finis_idx];
    if resp.len() >= 12 && caput_bytes.starts_with(b"HTTP/") {
        if let Some(sp_pos) = caput_bytes.iter().position(|&b| b == b' ') {
            let post_sp = &caput_bytes[sp_pos + 1..];
            // lege numerum
            let mut codex: i64 = 0;
            for &b in post_sp {
                if b >= b'0' && b <= b'9' {
                    codex = codex * 10 + (b - b'0') as i64;
                } else {
                    break;
                }
            }
            f.codex_responsi = codex;
        }
    }

    let corpus = &resp[finis_idx..];

    // quaere Transfer-Encoding: chunked
    let mut chunked = false;
    {
        // converte capita in chordam ad quaerendum
        if let Ok(capita_str) = std::str::from_utf8(caput_bytes) {
            for linea in capita_str.split("\r\n") {
                let linea_min = linea.to_ascii_lowercase();
                if linea_min.starts_with("transfer-encoding:") {
                    if linea_min.contains("chunked") {
                        chunked = true;
                    }
                    break;
                }
            }
        }
    }

    if chunked {
        // resolve chunked encoding
        let src = corpus;
        let src_mag = src.len();
        let mut i: usize = 0;

        while i < src_mag {
            // lege magnitudinem chunk (hex)
            let mut chunk_mag: usize = 0;
            while i < src_mag && src[i] != b'\r' {
                let c = src[i];
                if c >= b'0' && c <= b'9' {
                    chunk_mag = chunk_mag * 16 + (c - b'0') as usize;
                } else if c >= b'a' && c <= b'f' {
                    chunk_mag = chunk_mag * 16 + 10 + (c - b'a') as usize;
                } else if c >= b'A' && c <= b'F' {
                    chunk_mag = chunk_mag * 16 + 10 + (c - b'A') as usize;
                }
                i += 1;
            }
            // praetermitte \r\n
            if i + 1 < src_mag {
                i += 2;
            }
            if chunk_mag == 0 {
                break;
            }
            if i + chunk_mag > src_mag {
                chunk_mag = src_mag - i;
            }
            if let Some(ref mut functio) = f.scribe_fn {
                functio(&src[i..i + chunk_mag]);
            }
            i += chunk_mag;
            if i + 1 < src_mag {
                i += 2; // \r\n post chunk
            }
        }
    } else {
        // corpus simplex
        if let Some(ref mut functio) = f.scribe_fn {
            if !corpus.is_empty() {
                functio(corpus);
            }
        }
    }

    CRISPUSE_OK
}

// ================================================================
//  Interfacies facilis (manubrium facile)
// ================================================================

/// Manubrium facile — simile CRISPUS in C
pub struct CrispusFacilis {
    url: Option<String>,
    campi_postae: Option<String>,
    capita: Vec<String>,
    scribe_fn: Option<Box<dyn FnMut(&[u8]) -> usize>>,
    tempus_maximum: u64,
    codex_responsi: i64,
    exitus: i32,
}

impl CrispusFacilis {
    /// Initia manubrium novum
    pub fn initia() -> Self {
        CrispusFacilis {
            url: None,
            campi_postae: None,
            capita: Vec::new(),
            scribe_fn: None,
            tempus_maximum: 60,
            codex_responsi: 0,
            exitus: 0,
        }
    }

    /// Pone URL petitionis
    pub fn pone_url(&mut self, url: &str) {
        self.url = Some(url.to_string());
    }

    /// Pone corpus petitionis (methodus POST)
    pub fn pone_campi_postae(&mut self, data: &str) {
        self.campi_postae = Some(data.to_string());
    }

    /// Pone capita HTTP
    pub fn pone_capita(&mut self, capita: Vec<String>) {
        self.capita = capita;
    }

    /// Pone functionem scribendi (callback)
    pub fn pone_functio_scribendi(&mut self, f: Box<dyn FnMut(&[u8]) -> usize>) {
        self.scribe_fn = Some(f);
    }

    /// Pone tempus maximum (in secundis)
    pub fn pone_tempus(&mut self, secunda: u64) {
        self.tempus_maximum = secunda;
    }

    /// Age petitionem HTTP. Reddit codicem crispus.
    pub fn age(&mut self) -> i32 {
        if self.url.is_none() {
            return CRISPUSE_ERRATUM;
        }
        self.exitus = age_rogatum(self);
        self.exitus
    }

    /// Redde codicem responsi HTTP
    pub fn codex_responsi(&self) -> i64 {
        self.codex_responsi
    }

    /// Redde nuntium erroris pro codice dato
    pub fn error_nuntius(codex: i32) -> &'static str {
        match codex {
            CRISPUSE_OK => "OK",
            CRISPUSE_CONIUNCTIO => "coniunctio defecit",
            CRISPUSE_MEMORIA => "memoria defecit",
            CRISPUSE_TEMPUS => "tempus excessum",
            _ => "erratum ignotum",
        }
    }
}

// ================================================================
//  Nuntius multi
// ================================================================

/// Nuntius perfecti — simile CRISPUSMsg in C
pub struct CrispusMsg {
    pub msg: i32,
    pub exitus: i32,
    pub codex_responsi: i64,
    /// Corpus responsi (octi recepti)
    pub corpus: Vec<u8>,
}

// ================================================================
//  Interfacies multi (per fila)
// ================================================================

/// Manubrium multiplex — simile CRISPUSM in C.
/// Utitur filis (std::thread) loco fork()+pipe().
pub struct CrispusMulti {
    opera: Vec<OpusMulti>,
    nuntii: Vec<CrispusMsg>,
    nuntii_idx: usize,
}

/// Opus singulum in multi — filum et status
struct OpusMulti {
    filum: Option<std::thread::JoinHandle<(i32, i64, Vec<u8>)>>,
    perfectum: bool,
}

impl CrispusMulti {
    /// Initia manubrium multiplex novum
    pub fn initia() -> Self {
        CrispusMulti {
            opera: Vec::new(),
            nuntii: Vec::new(),
            nuntii_idx: 0,
        }
    }

    /// Adde petitionem. URL et optiones debent iam in CrispusFacilis positae esse.
    /// Consumit CrispusFacilis quia filum novum creatur.
    pub fn adde(&mut self, mut facilis: CrispusFacilis) -> i32 {
        // mitte opus ad filum
        // NB: scribe_fn non est Send, ergo in filio proprium callback creamus
        //     quod corpus accumulat, et postea corpus in nuntio reddimus.
        let url = facilis.url.take();
        let campi = facilis.campi_postae.take();
        let capita = std::mem::take(&mut facilis.capita);
        let tempus = facilis.tempus_maximum;

        let filum = std::thread::spawn(move || {
            let mut f = CrispusFacilis::initia();
            if let Some(u) = url {
                f.pone_url(&u);
            }
            if let Some(c) = campi {
                f.pone_campi_postae(&c);
            }
            f.pone_capita(capita);
            f.pone_tempus(tempus);

            // accumulator corporis
            let corpus: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let corpus_ref = corpus.clone();
            f.pone_functio_scribendi(Box::new(move |data: &[u8]| {
                corpus_ref.lock().unwrap().extend_from_slice(data);
                data.len()
            }));

            let rc = f.age();
            let codex = f.codex_responsi();
            let corp = corpus.lock().unwrap().clone();
            (rc, codex, corp)
        });

        self.opera.push(OpusMulti {
            filum: Some(filum),
            perfectum: false,
        });

        CRISPUSM_OK
    }

    /// Remove opus (non implementatur plene — fila non possunt occidi facile)
    pub fn remove(&mut self, index: usize) -> i32 {
        if index >= self.opera.len() {
            return CRISPUSM_ERRATUM;
        }
        self.opera.remove(index);
        CRISPUSM_OK
    }

    /// Age: inspice fila perfecta, collige nuntios. Reddit numerum currentium.
    pub fn age(&mut self) -> i32 {
        self.nuntii.clear();
        self.nuntii_idx = 0;

        let mut vivi = 0i32;

        for opus in &mut self.opera {
            if opus.perfectum {
                continue;
            }

            let perfectum = opus.filum.as_ref().map(|f| f.is_finished()).unwrap_or(true);

            if perfectum {
                if let Some(filum) = opus.filum.take() {
                    match filum.join() {
                        Ok((rc, codex, corpus)) => {
                            self.nuntii.push(CrispusMsg {
                                msg: CRISPUSMSG_PERFECTUM,
                                exitus: rc,
                                codex_responsi: codex,
                                corpus,
                            });
                        }
                        Err(_) => {
                            self.nuntii.push(CrispusMsg {
                                msg: CRISPUSMSG_PERFECTUM,
                                exitus: CRISPUSE_ERRATUM,
                                codex_responsi: 0,
                                corpus: Vec::new(),
                            });
                        }
                    }
                }
                opus.perfectum = true;
            } else {
                vivi += 1;
            }
        }

        vivi
    }

    /// Lege proximum nuntium perfectum. Reddit None si nulla restant.
    pub fn lege(&mut self) -> Option<&CrispusMsg> {
        if self.nuntii_idx < self.nuntii.len() {
            let idx = self.nuntii_idx;
            self.nuntii_idx += 1;
            Some(&self.nuntii[idx])
        } else {
            None
        }
    }
}
