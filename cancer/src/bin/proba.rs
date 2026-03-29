//! proba — probationes bibliothecae cancer
//!
//! Probat cryptographiam (SHA-256, HMAC-SHA-256, AES-128-GCM,
//! numerus magnus, EC P-256) et coniunctionem HTTPS.

use cancer::arca::*;
use cancer::crispus::*;
use cancer::numerus::*;
use cancer::summa::*;

use std::cell::RefCell;
use std::rc::Rc;

// ================================================================
//  Computator probationum
// ================================================================

static mut PROBATIONES_SUCCESSAE: i32 = 0;
static mut PROBATIONES_DEFECTAE: i32 = 0;

/// Macro probationis — imprimit ✓ vel ✗
macro_rules! proba {
    ($nomen:expr, $cond:expr) => {
        if $cond {
            #[allow(static_mut_refs)]
            unsafe {
                PROBATIONES_SUCCESSAE += 1;
            }
            println!("  \u{2713} {}", $nomen);
        } else {
            #[allow(static_mut_refs)]
            unsafe {
                PROBATIONES_DEFECTAE += 1;
            }
            println!("  \u{2717} {}", $nomen);
        }
    };
}

// ================================================================
//  Probatio SHA-256
// ================================================================

fn proba_summam() {
    println!("SHA-256:");

    // SHA-256("") = e3b0c442...
    {
        let digestum = summa256(b"");
        let expectatum: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        proba!("SHA-256(\"\")", digestum == expectatum);
    }

    // SHA-256("Gallia est omnis divisa in partes tres")
    {
        let gall = b"Gallia est omnis divisa in partes tres";
        let digestum = summa256(gall);
        let expectatum: [u8; 32] = [
            0x04, 0xaa, 0x0e, 0xfa, 0x57, 0x1a, 0x7e, 0xd6, 0xca, 0x18, 0x10, 0xf9, 0x35, 0xfb,
            0xda, 0x33, 0xa3, 0xe2, 0xc2, 0x96, 0xda, 0x4c, 0xca, 0xe8, 0x27, 0x25, 0x4c, 0xbf,
            0x57, 0x15, 0x07, 0x3a,
        ];
        proba!("SHA-256(Gallia)", digestum == expectatum);
    }

    // SHA-256 incrementalis
    {
        let nuntius = b"Ars conjectandi est fundamentum calculi probabilitatum";
        let digestum1 = summa256(nuntius);

        let mut ctx = Summa256Ctx::initia();
        ctx.adde(&nuntius[..10]);
        ctx.adde(&nuntius[10..]);
        let digestum2 = ctx.fini();
        proba!("SHA-256 incrementalis", digestum1 == digestum2);
    }
}

// ================================================================
//  Probatio HMAC-SHA-256
// ================================================================

fn proba_sigillum() {
    println!("HMAC-SHA-256:");

    // RFC 4231 vector 1
    {
        let clavis = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = sigillum256(&clavis, data);
        let expectatum: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        proba!("RFC 4231 vector 1", mac == expectatum);
    }
}

// ================================================================
//  Probatio AES-128-GCM
// ================================================================

fn proba_arcam() {
    println!("AES-128-GCM:");

    // NIST: clavis nulla, iv nulla, textus vacuus
    {
        let clavis = [0u8; 16];
        let iv = [0u8; 12];
        let mut sigillum = [0u8; 16];
        arca128_gcm_occulta(&clavis, &iv, &[], &[], &mut [], &mut sigillum);

        let sig_expectatum: [u8; 16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
            0x45, 0x5a,
        ];
        proba!("GCM tag (vacuus)", sigillum == sig_expectatum);
    }

    // occultatio et revelatio
    {
        let clavis: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let iv: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let textus = b"Salve Munde!";
        let mag = textus.len();

        let mut occultus = vec![0u8; mag];
        let mut sigillum = [0u8; 16];
        arca128_gcm_occulta(&clavis, &iv, textus, &[], &mut occultus, &mut sigillum);

        // textus occultus non debet esse idem ac clarus
        proba!("GCM occultat", occultus[..] != textus[..]);

        // revela
        let mut revelatus = vec![0u8; mag];
        let rc = arca128_gcm_revela(&clavis, &iv, &occultus, &[], &mut revelatus, &sigillum);
        proba!("GCM revelat (sigillum)", rc == 0);
        proba!("GCM revelat (textus)", revelatus[..] == textus[..]);

        // sigillum corruptum
        let mut sig_malus = sigillum;
        sig_malus[0] ^= 0xff;
        let rc = arca128_gcm_revela(&clavis, &iv, &occultus, &[], &mut revelatus, &sig_malus);
        proba!("GCM reicit sigillum malum", rc != 0);
    }
}

// ================================================================
//  Probatio Numeri Magni
// ================================================================

fn proba_numerum() {
    println!("Numerus Magnus:");

    // additio simplex: 0xFFFFFFFF + 1 = 0x100000000
    {
        let mut a = Nm::ex_nihilo();
        a.v[0] = 0xFFFFFFFF;
        let mut b = Nm::ex_nihilo();
        b.v[0] = 1;
        let mut r = Nm::ex_nihilo();
        nm_adde(&mut r, &a, &b);
        proba!("0xFFFFFFFF + 1 = 0x100000000", r.v[0] == 0 && r.v[1] == 1);
    }

    // multiplicatio: 1000 * 1000 = 1000000
    {
        let mut a = Nm::ex_nihilo();
        a.v[0] = 1000;
        let mut b = Nm::ex_nihilo();
        b.v[0] = 1000;
        let mut r = Nm::ex_nihilo();
        nm_multiplica(&mut r, &a, &b);
        proba!("1000 * 1000 = 1000000", r.v[0] == 1000000);
    }

    // divisio: 17 / 5 = 3 rem 2
    {
        let mut a = Nm::ex_nihilo();
        a.v[0] = 17;
        let mut b = Nm::ex_nihilo();
        b.v[0] = 5;
        let mut q = Nm::ex_nihilo();
        let mut rem = Nm::ex_nihilo();
        nm_divide(&mut q, &mut rem, &a, &b);
        proba!("17 / 5 = 3 rem 2", q.v[0] == 3 && rem.v[0] == 2);
    }

    // divisio maior: 2^32 / 7 = 613566756 rem 4
    {
        let mut a = Nm::ex_nihilo();
        a.v[0] = 0;
        a.v[1] = 1;
        a.n = 2;
        let mut b = Nm::ex_nihilo();
        b.v[0] = 7;
        let mut q = Nm::ex_nihilo();
        let mut rem = Nm::ex_nihilo();
        nm_divide(&mut q, &mut rem, &a, &b);
        proba!(
            "2^32 / 7 = 613566756 rem 4",
            q.v[0] == 613566756 && rem.v[0] == 4
        );
    }

    // modpot: 2^10 mod 1000 = 24
    {
        let mut basis = Nm::ex_nihilo();
        basis.v[0] = 2;
        let mut exp = Nm::ex_nihilo();
        exp.v[0] = 10;
        let mut modulus = Nm::ex_nihilo();
        modulus.v[0] = 1000;
        let mut r = Nm::ex_nihilo();
        nm_modpot(&mut r, &basis, &exp, &modulus);
        proba!("2^10 mod 1000 = 24", r.v[0] == 24);
    }

    // conversio octorum
    {
        let data: [u8; 5] = [0x01, 0x00, 0x00, 0x00, 0x01];
        let a = Nm::ex_octis(&data);
        // 0x0100000001 = 2^32 + 1
        proba!("nm_ex_octis(0x0100000001)", a.v[0] == 1 && a.v[1] == 1);

        let mut effectus = [0u8; 5];
        a.ad_octos(&mut effectus);
        proba!("nm_ad_octos round-trip", effectus == data);
    }
}

// ================================================================
//  Probatio EC P-256
// ================================================================

fn proba_ec() {
    println!("EC P-256:");

    let gen = ec_generator();
    let ordo = ec_ordo();

    // G non est in infinito
    proba!("G non infinitum", !gen.infinitum);

    // 1 * G = G
    {
        let mut unum = Nm::ex_nihilo();
        unum.v[0] = 1;
        let mut r = EcPunctum {
            x: Nm::ex_nihilo(),
            y: Nm::ex_nihilo(),
            infinitum: true,
        };
        ec_multiplica(&mut r, &unum, &gen);
        proba!(
            "1*G = G",
            r.x.compara(&gen.x) == 0 && r.y.compara(&gen.y) == 0
        );
    }

    // n * G = infinitum
    {
        let mut r = EcPunctum {
            x: Nm::ex_nihilo(),
            y: Nm::ex_nihilo(),
            infinitum: false,
        };
        ec_multiplica(&mut r, &ordo, &gen);
        proba!("n*G = O (infinitum)", r.infinitum);
    }

    // 2*G: non est G neque infinitum
    {
        let mut duo = Nm::ex_nihilo();
        duo.v[0] = 2;
        let mut r = EcPunctum {
            x: Nm::ex_nihilo(),
            y: Nm::ex_nihilo(),
            infinitum: true,
        };
        ec_multiplica(&mut r, &duo, &gen);
        proba!("2*G != G", r.x.compara(&gen.x) != 0);
        proba!("2*G != O", !r.infinitum);
    }
}

// ================================================================
//  Probatio HTTPS
// ================================================================

fn proba_https() {
    println!("HTTPS:");

    // GET https://www.google.com/
    {
        let mut c = CrispusFacilis::initia();
        let resp = Rc::new(RefCell::new(Vec::<u8>::new()));
        let r = resp.clone();
        c.pone_url("https://www.google.com/");
        c.pone_functio_scribendi(Box::new(move |data: &[u8]| {
            r.borrow_mut().extend_from_slice(data);
            data.len()
        }));
        c.pone_tempus(15);

        let rc = c.age();
        let codex = c.codex_responsi();
        let resp_data = resp.borrow();

        println!("    rc={} codex={} resp_mag={}", rc, codex, resp_data.len());

        proba!("google.com coniunctio", rc == CRISPUSE_OK);
        proba!(
            "google.com codex 200",
            codex == 200 || codex == 301 || codex == 302
        );
        proba!("google.com habet corpus", !resp_data.is_empty());
        if !resp_data.is_empty() {
            let textus = String::from_utf8_lossy(&resp_data);
            proba!("google.com HTML", textus.contains('<'));
        }
    }

    // GET https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/
    {
        let mut c = CrispusFacilis::initia();
        let resp = Rc::new(RefCell::new(Vec::<u8>::new()));
        let r = resp.clone();
        c.pone_url("https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/");
        c.pone_functio_scribendi(Box::new(move |data: &[u8]| {
            r.borrow_mut().extend_from_slice(data);
            data.len()
        }));
        c.pone_tempus(15);

        let rc = c.age();
        let codex = c.codex_responsi();
        let resp_data = resp.borrow();

        println!("    rc={} codex={} resp_mag={}", rc, codex, resp_data.len());

        proba!("exeter.ac.uk coniunctio", rc == CRISPUSE_OK);
        proba!("exeter.ac.uk codex 200", codex == 200);
        if !resp_data.is_empty() {
            let textus = String::from_utf8_lossy(&resp_data);
            proba!("exeter.ac.uk HTML", textus.contains('<'));
        }
    }

    // GET https://plato.stanford.edu/entries/logic-modal/#TwoD
    {
        let mut c = CrispusFacilis::initia();
        let resp = Rc::new(RefCell::new(Vec::<u8>::new()));
        let r = resp.clone();
        c.pone_url("https://plato.stanford.edu/entries/logic-modal/#TwoD");
        c.pone_functio_scribendi(Box::new(move |data: &[u8]| {
            r.borrow_mut().extend_from_slice(data);
            data.len()
        }));
        c.pone_tempus(15);

        let rc = c.age();
        let codex = c.codex_responsi();
        let resp_data = resp.borrow();

        println!("    rc={} codex={} resp_mag={}", rc, codex, resp_data.len());

        proba!("stanford.edu coniunctio", rc == CRISPUSE_OK);
        proba!("stanford.edu codex 200", codex == 200);
        if !resp_data.is_empty() {
            let textus = String::from_utf8_lossy(&resp_data);
            proba!("stanford.edu HTML", textus.contains("modal"));
        }
    }

    // GET https://www.fordcountychronicle.com/...
    {
        let mut c = CrispusFacilis::initia();
        let resp = Rc::new(RefCell::new(Vec::<u8>::new()));
        let r = resp.clone();
        c.pone_url(
            "https://www.fordcountychronicle.com/articles/featured/naked-gunman-70-still-not-located/",
        );
        c.pone_functio_scribendi(Box::new(move |data: &[u8]| {
            r.borrow_mut().extend_from_slice(data);
            data.len()
        }));
        c.pone_tempus(15);

        let rc = c.age();
        let codex = c.codex_responsi();
        let resp_data = resp.borrow();

        println!("    rc={} codex={} resp_mag={}", rc, codex, resp_data.len());

        proba!("fordcountychronicle coniunctio", rc == CRISPUSE_OK);
        proba!("fordcountychronicle codex", codex >= 200 && codex < 400);
        if !resp_data.is_empty() {
            let textus = String::from_utf8_lossy(&resp_data);
            proba!("fordcountychronicle HTML", textus.contains('<'));
        }
    }
}

// ================================================================
//  Functio principalis
// ================================================================

fn main() {
    #[allow(static_mut_refs)]
    unsafe {
        PROBATIONES_SUCCESSAE = 0;
        PROBATIONES_DEFECTAE = 0;
    }

    println!("=== PROBATIONES CRISPUS ===\n");

    proba_summam();
    println!();
    proba_sigillum();
    println!();
    proba_arcam();
    println!();
    proba_numerum();
    println!();
    proba_ec();
    println!();
    proba_https();

    #[allow(static_mut_refs)]
    let (successae, defectae) = unsafe { (PROBATIONES_SUCCESSAE, PROBATIONES_DEFECTAE) };

    println!(
        "\n=== EFFECTUS: {} successae, {} defectae ===",
        successae, defectae
    );

    std::process::exit(defectae);
}
