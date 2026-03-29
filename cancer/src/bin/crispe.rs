//! crispe — instrumentum lineae mandatorum ad petitiones HTTPS mittendas
//!
//! Usus: crispe [optiones] <url>
//!
//!   -s            silentium (nulla nuntia erroris)
//!   -v            modus verbosus
//!   -d <corpus>   corpus petitionis (methodus POST)
//!   -H <caput>    adde caput HTTP (iterabile)
//!   -o <lima>     scribe responsum in limam
//!   -X <methodus> methodus HTTP (GET, POST)
//!   -t <secunda>  tempus maximum (secunda)
//!   -h            hoc auxilium

use cancer::crispus::*;
use std::env;
use std::fs::File;
use std::io::Write;
use std::process;

/// Scribe auxilium ad stderr
fn scribe_auxilium(nomen: &str) {
    eprintln!(
        "Usus: {} [optiones] <url>\n\n\
         \x20 -s            silentium (nulla nuntia erroris)\n\
         \x20 -v            modus verbosus\n\
         \x20 -L            sequere redirectiones\n\
         \x20 -d <corpus>   corpus petitionis (methodus POST)\n\
         \x20 -H <caput>    adde caput HTTP (iterabile)\n\
         \x20 -o <lima>     scribe responsum in limam\n\
         \x20 -X <methodus> methodus HTTP (GET, POST)\n\
         \x20 -t <secunda>  tempus maximum (secunda)\n\
         \x20 -h            hoc auxilium",
        nomen
    );
}

fn main() {
    let argumenta: Vec<String> = env::args().collect();
    let nomen = &argumenta[0];

    let mut silentium = false;
    let mut verbosus = false;
    let mut sequere = false;
    let mut corpus_postae: Option<String> = None;
    let mut lima_exitus: Option<String> = None;
    let mut methodus: Option<String> = None;
    let mut tempus_max: u64 = 60;
    let mut capita: Option<Box<CrispusSlist>> = None;
    let mut url: Option<String> = None;

    // resolve argumenta manualiter (sine getopt)
    let mut i = 1;
    while i < argumenta.len() {
        let arg = &argumenta[i];

        if arg == "-h" {
            scribe_auxilium(nomen);
            process::exit(0);
        } else if arg == "-s" {
            silentium = true;
        } else if arg == "-v" {
            verbosus = true;
        } else if arg == "-L" {
            sequere = true;
        } else if arg == "-d" {
            i += 1;
            if i >= argumenta.len() {
                if !silentium {
                    eprintln!("crispe: -d requirit argumentum");
                }
                process::exit(1);
            }
            corpus_postae = Some(argumenta[i].clone());
        } else if arg == "-H" {
            i += 1;
            if i >= argumenta.len() {
                if !silentium {
                    eprintln!("crispe: -H requirit argumentum");
                }
                process::exit(1);
            }
            capita = crispus_slist_adde(capita, &argumenta[i]);
        } else if arg == "-o" {
            i += 1;
            if i >= argumenta.len() {
                if !silentium {
                    eprintln!("crispe: -o requirit argumentum");
                }
                process::exit(1);
            }
            lima_exitus = Some(argumenta[i].clone());
        } else if arg == "-X" {
            i += 1;
            if i >= argumenta.len() {
                if !silentium {
                    eprintln!("crispe: -X requirit argumentum");
                }
                process::exit(1);
            }
            methodus = Some(argumenta[i].clone());
        } else if arg == "-t" {
            i += 1;
            if i >= argumenta.len() {
                if !silentium {
                    eprintln!("crispe: -t requirit argumentum");
                }
                process::exit(1);
            }
            match argumenta[i].parse::<u64>() {
                Ok(t) if t > 0 => tempus_max = t,
                _ => {
                    if !silentium {
                        eprintln!("crispe: tempus invalidum: {}", argumenta[i]);
                    }
                    process::exit(1);
                }
            }
        } else if arg.starts_with('-') {
            if !silentium {
                eprintln!("crispe: optio ignota: {}", arg);
            }
            scribe_auxilium(nomen);
            process::exit(1);
        } else {
            // URL
            url = Some(arg.clone());
        }

        i += 1;
    }

    // URL debet adesse
    let url = match url {
        Some(u) => u,
        None => {
            if !silentium {
                eprintln!("crispe: URL deest");
            }
            scribe_auxilium(nomen);
            process::exit(1);
        }
    };

    // si -d datum est sed -X non, methodus est POST
    if corpus_postae.is_some() && methodus.is_none() {
        methodus = Some("POST".to_string());
    }

    // si methodus POST sed -d non datum, corpus vacuum
    if methodus.as_deref() == Some("POST") && corpus_postae.is_none() {
        corpus_postae = Some(String::new());
    }

    // para manubrium
    let mut manubrium = CrispusFacilis::initia();
    manubrium.pone_url(&url);
    manubrium.pone_tempus(tempus_max);
    if sequere {
        manubrium.pone_sequere(true);
    }

    if let Some(ref corpus) = corpus_postae {
        manubrium.pone_campi_postae(corpus);
    }

    // converte slist in Vec<String> pro capitibus
    {
        let mut capita_vec = Vec::new();
        let mut cursor = &capita;
        while let Some(ref nodus) = cursor {
            capita_vec.push(nodus.data.clone());
            cursor = &nodus.proximus;
        }
        if !capita_vec.is_empty() {
            manubrium.pone_capita(capita_vec);
        }
    }

    // accumulator responsi
    let resp_corpus = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let r = resp_corpus.clone();
    manubrium.pone_functio_scribendi(Box::new(move |data: &[u8]| {
        r.lock().unwrap().extend_from_slice(data);
        data.len()
    }));

    // modus verbosus: ostende petitionem
    if verbosus {
        let m = methodus.as_deref().unwrap_or("GET");
        eprintln!("> {} {}", m, url);
        if let Some(ref corpus) = corpus_postae {
            eprintln!("> Corpus: {}", corpus);
        }
        let mut cursor = &capita;
        while let Some(ref nodus) = cursor {
            eprintln!("> {}", nodus.data);
            cursor = &nodus.proximus;
        }
        eprintln!(">");
    }

    // mitte petitionem
    let rc = manubrium.age();

    if rc != CRISPUSE_OK {
        if !silentium {
            eprintln!(
                "crispe: petitio defecit: {}",
                CrispusFacilis::error_nuntius(rc)
            );
        }
        process::exit(1);
    }

    // codex responsi
    let codex_responsi = manubrium.codex_responsi();

    let resp_data = resp_corpus.lock().unwrap();

    if verbosus {
        eprintln!(
            "< HTTP codex: {}\n< Magnitudo: {} octeti",
            codex_responsi,
            resp_data.len()
        );
    }

    // scribe responsum
    let mut status = 0;

    if let Some(ref lima_nomen) = lima_exitus {
        match File::create(lima_nomen) {
            Ok(mut lima) => {
                if !resp_data.is_empty() {
                    if lima.write_all(&resp_data).is_err() {
                        if !silentium {
                            eprintln!("crispe: in limam scribere non potuit: {}", lima_nomen);
                        }
                        status = 1;
                    }
                }
            }
            Err(_) => {
                if !silentium {
                    eprintln!("crispe: limam aperire non potuit: {}", lima_nomen);
                }
                status = 1;
            }
        }
    } else if !resp_data.is_empty() {
        let stdout = std::io::stdout();
        let mut stdout_lock = stdout.lock();
        let _ = stdout_lock.write_all(&resp_data);
    }

    process::exit(status);
}
