//! probationes integrationis bibliothecae cancer
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
//  SHA-256
// ================================================================

#[test]
fn summa256_vacua() {
    let digestum = summa256(b"");
    let expectatum: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(digestum, expectatum);
}

#[test]
fn summa256_gallia() {
    let gall = b"Gallia est omnis divisa in partes tres";
    let digestum = summa256(gall);
    let expectatum: [u8; 32] = [
        0x04, 0xaa, 0x0e, 0xfa, 0x57, 0x1a, 0x7e, 0xd6, 0xca, 0x18, 0x10, 0xf9, 0x35, 0xfb, 0xda,
        0x33, 0xa3, 0xe2, 0xc2, 0x96, 0xda, 0x4c, 0xca, 0xe8, 0x27, 0x25, 0x4c, 0xbf, 0x57, 0x15,
        0x07, 0x3a,
    ];
    assert_eq!(digestum, expectatum);
}

#[test]
fn summa256_incrementalis() {
    let nuntius = b"Ars conjectandi est fundamentum calculi probabilitatum";
    let digestum1 = summa256(nuntius);

    let mut ctx = Summa256Ctx::initia();
    ctx.adde(&nuntius[..10]);
    ctx.adde(&nuntius[10..]);
    let digestum2 = ctx.fini();
    assert_eq!(digestum1, digestum2);
}

// ================================================================
//  HMAC-SHA-256
// ================================================================

#[test]
fn sigillum256_rfc4231_vector1() {
    let clavis = [0x0bu8; 20];
    let data = b"Hi There";
    let mac = sigillum256(&clavis, data);
    let expectatum: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    assert_eq!(mac, expectatum);
}

// ================================================================
//  AES-128-GCM
// ================================================================

#[test]
fn gcm_sigillum_vacuum() {
    let clavis = [0u8; 16];
    let iv = [0u8; 12];
    let mut sigillum = [0u8; 16];
    arca128_gcm_occulta(&clavis, &iv, &[], &[], &mut [], &mut sigillum);

    let expectatum: [u8; 16] = [
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45,
        0x5a,
    ];
    assert_eq!(sigillum, expectatum);
}

#[test]
fn gcm_occultat_et_revelat() {
    let clavis: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let textus = b"Salve Munde!";
    let mag = textus.len();

    let mut occultus = vec![0u8; mag];
    let mut sigillum = [0u8; 16];
    arca128_gcm_occulta(&clavis, &iv, textus, &[], &mut occultus, &mut sigillum);

    assert_ne!(occultus[..], textus[..], "textus occultus idem ac clarus");

    let mut revelatus = vec![0u8; mag];
    let rc = arca128_gcm_revela(&clavis, &iv, &occultus, &[], &mut revelatus, &sigillum);
    assert_eq!(rc, 0, "revelatio defecit");
    assert_eq!(revelatus[..], textus[..], "textus revelatus non congruit");
}

#[test]
fn gcm_reicit_sigillum_malum() {
    let clavis: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let textus = b"Salve Munde!";
    let mag = textus.len();

    let mut occultus = vec![0u8; mag];
    let mut sigillum = [0u8; 16];
    arca128_gcm_occulta(&clavis, &iv, textus, &[], &mut occultus, &mut sigillum);

    let mut sig_malus = sigillum;
    sig_malus[0] ^= 0xff;
    let mut revelatus = vec![0u8; mag];
    let rc = arca128_gcm_revela(&clavis, &iv, &occultus, &[], &mut revelatus, &sig_malus);
    assert_ne!(rc, 0, "sigillum malum acceptum est");
}

// ================================================================
//  Numerus Magnus
// ================================================================

#[test]
fn nm_additio_simplex() {
    let mut a = Nm::ex_nihilo();
    a.v[0] = 0xFFFFFFFF;
    let mut b = Nm::ex_nihilo();
    b.v[0] = 1;
    let mut r = Nm::ex_nihilo();
    nm_adde(&mut r, &a, &b);
    assert_eq!(r.v[0], 0);
    assert_eq!(r.v[1], 1);
}

#[test]
fn nm_multiplicatio() {
    let mut a = Nm::ex_nihilo();
    a.v[0] = 1000;
    let mut b = Nm::ex_nihilo();
    b.v[0] = 1000;
    let mut r = Nm::ex_nihilo();
    nm_multiplica(&mut r, &a, &b);
    assert_eq!(r.v[0], 1_000_000);
}

#[test]
fn nm_divisio_simplex() {
    let mut a = Nm::ex_nihilo();
    a.v[0] = 17;
    let mut b = Nm::ex_nihilo();
    b.v[0] = 5;
    let mut q = Nm::ex_nihilo();
    let mut rem = Nm::ex_nihilo();
    nm_divide(&mut q, &mut rem, &a, &b);
    assert_eq!(q.v[0], 3);
    assert_eq!(rem.v[0], 2);
}

#[test]
fn nm_divisio_maior() {
    let mut a = Nm::ex_nihilo();
    a.v[1] = 1;
    a.n = 2; // 2^32
    let mut b = Nm::ex_nihilo();
    b.v[0] = 7;
    let mut q = Nm::ex_nihilo();
    let mut rem = Nm::ex_nihilo();
    nm_divide(&mut q, &mut rem, &a, &b);
    assert_eq!(q.v[0], 613_566_756);
    assert_eq!(rem.v[0], 4);
}

#[test]
fn nm_modpot_bernoulli() {
    // 2^10 mod 1000 = 24 — quod Bernoullius facile computat
    let mut basis = Nm::ex_nihilo();
    basis.v[0] = 2;
    let mut exp = Nm::ex_nihilo();
    exp.v[0] = 10;
    let mut modulus = Nm::ex_nihilo();
    modulus.v[0] = 1000;
    let mut r = Nm::ex_nihilo();
    nm_modpot(&mut r, &basis, &exp, &modulus);
    assert_eq!(r.v[0], 24);
}

#[test]
fn nm_conversio_octorum() {
    let data: [u8; 5] = [0x01, 0x00, 0x00, 0x00, 0x01];
    let a = Nm::ex_octis(&data);
    // 0x0100000001 = 2^32 + 1
    assert_eq!(a.v[0], 1);
    assert_eq!(a.v[1], 1);

    let mut effectus = [0u8; 5];
    a.ad_octos(&mut effectus);
    assert_eq!(effectus, data);
}

// ================================================================
//  EC P-256
// ================================================================

#[test]
fn ec_generator_non_infinitum() {
    let gen = ec_generator();
    assert!(!gen.infinitum);
}

#[test]
fn ec_unum_multiplicat_generator() {
    // 1 * G = G
    let gen = ec_generator();
    let mut unum = Nm::ex_nihilo();
    unum.v[0] = 1;
    let mut r = EcPunctum {
        x: Nm::ex_nihilo(),
        y: Nm::ex_nihilo(),
        infinitum: true,
    };
    ec_multiplica(&mut r, &unum, &gen);
    assert_eq!(r.x.compara(&gen.x), 0);
    assert_eq!(r.y.compara(&gen.y), 0);
}

#[test]
fn ec_ordo_ad_infinitum() {
    // n * G = O (punctum in infinito)
    let gen = ec_generator();
    let ordo = ec_ordo();
    let mut r = EcPunctum {
        x: Nm::ex_nihilo(),
        y: Nm::ex_nihilo(),
        infinitum: false,
    };
    ec_multiplica(&mut r, &ordo, &gen);
    assert!(r.infinitum, "n*G non est infinitum");
}

#[test]
fn ec_duo_multiplicat_generator() {
    // 2*G != G et 2*G != O
    let gen = ec_generator();
    let mut duo = Nm::ex_nihilo();
    duo.v[0] = 2;
    let mut r = EcPunctum {
        x: Nm::ex_nihilo(),
        y: Nm::ex_nihilo(),
        infinitum: true,
    };
    ec_multiplica(&mut r, &duo, &gen);
    assert_ne!(r.x.compara(&gen.x), 0, "2*G == G");
    assert!(!r.infinitum, "2*G == O");
}

// ================================================================
//  HTTPS (requirunt rete — #[ignore] per defectum)
// ================================================================

/// functio auxiliaris ad responsum colligendum
fn pete_https(url: &str) -> (i32, i64, Vec<u8>) {
    let mut c = CrispusFacilis::initia();
    let resp = Rc::new(RefCell::new(Vec::<u8>::new()));
    let r = resp.clone();
    c.pone_url(url);
    c.pone_functio_scribendi(Box::new(move |data: &[u8]| {
        r.borrow_mut().extend_from_slice(data);
        data.len()
    }));
    c.pone_tempus(15);
    let rc = c.age();
    let codex = c.codex_responsi();
    let corpus = resp.borrow().clone();
    (rc, codex, corpus)
}

#[test]
#[ignore] // curre cum: cargo test -- --ignored
fn https_google() {
    let (rc, codex, corpus) = pete_https("https://www.google.com/");
    assert_eq!(rc, CRISPUSE_OK, "coniunctio defecit");
    assert!(
        codex == 200 || codex == 301 || codex == 302,
        "codex inexpectatus: {}",
        codex
    );
    assert!(!corpus.is_empty(), "corpus vacuum");
    let textus = String::from_utf8_lossy(&corpus);
    assert!(textus.contains('<'), "HTML deest");
}

#[test]
#[ignore]
fn https_exeter() {
    let (rc, codex, corpus) = pete_https("https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/");
    assert_eq!(rc, CRISPUSE_OK, "coniunctio defecit");
    assert_eq!(codex, 200, "codex inexpectatus: {}", codex);
    let textus = String::from_utf8_lossy(&corpus);
    assert!(textus.contains('<'), "HTML deest");
}

#[test]
#[ignore]
fn https_stanford() {
    let (rc, codex, corpus) = pete_https("https://plato.stanford.edu/entries/logic-modal/#TwoD");
    assert_eq!(rc, CRISPUSE_OK, "coniunctio defecit");
    assert_eq!(codex, 200, "codex inexpectatus: {}", codex);
    let textus = String::from_utf8_lossy(&corpus);
    assert!(textus.contains("modal"), "verbum 'modal' deest");
}

#[test]
#[ignore]
fn https_fordcountychronicle() {
    let (rc, codex, corpus) = pete_https(
        "https://www.fordcountychronicle.com/articles/featured/naked-gunman-70-still-not-located/",
    );
    assert_eq!(rc, CRISPUSE_OK, "coniunctio defecit");
    assert!(codex >= 200 && codex < 400, "codex inexpectatus: {}", codex);
    let textus = String::from_utf8_lossy(&corpus);
    assert!(textus.contains('<'), "HTML deest");
}
