//! numerus — arithmetica numeri magni, curva elliptica P-256,
//!           verificatio RSA, resolutio ASN.1/X.509, alea
//!
//! Numerus magnus: tabulatum verborum u32, ordo minoris ponderis.
//!   v[0] = verbum minimi ponderis (least significant)
//!
//! Sine dependentiis externis.

use std::fs::File;
use std::io::Read;

// --- constantes ---

/// Verba in numero magno (260 * 32 = 8320 bits, sufficit productis RSA-4096)
pub const NM_VERBA: usize = 260;

// --- numerus magnus ---

/// Numerus magnus: tabulatum verborum u32, ordo minoris ponderis.
#[derive(Clone, Debug)]
pub struct Nm {
    pub v: [u32; NM_VERBA],
    pub n: usize,
}

impl Nm {
    /// Creat numerum vacuum (nihil).
    pub fn ex_nihilo() -> Self {
        Nm {
            v: [0u32; NM_VERBA],
            n: 1,
        }
    }

    /// Normaliza: remove verba nulla summa.
    fn normaliza(&mut self) {
        while self.n > 1 && self.v[self.n - 1] == 0 {
            self.n -= 1;
        }
    }

    /// Ex octis big-endian.
    pub fn ex_octis(data: &[u8]) -> Self {
        let mut a = Nm::ex_nihilo();
        if data.is_empty() {
            return a;
        }

        // praetermitte nulos ducentes
        let mut d = data;
        while !d.is_empty() && d[0] == 0 {
            d = &d[1..];
        }
        if d.is_empty() {
            return a;
        }

        let mag = d.len();
        let mut nv = (mag + 3) / 4;
        if nv > NM_VERBA {
            nv = NM_VERBA;
        }
        a.n = nv;

        for i in 0..mag {
            let vi = (mag - 1 - i) / 4;
            let bi = (mag - 1 - i) % 4;
            if vi < NM_VERBA {
                a.v[vi] |= (d[i] as u32) << (bi * 8);
            }
        }
        a.normaliza();
        a
    }

    /// Ad octos big-endian, complens cum nulis.
    pub fn ad_octos(&self, data: &mut [u8]) {
        let mag = data.len();
        for b in data.iter_mut() {
            *b = 0;
        }
        for i in 0..self.n {
            let w = self.v[i];
            for b in 0..4usize {
                let pos_val = i * 4 + b;
                if pos_val < mag {
                    let pos = mag - 1 - pos_val;
                    data[pos] = (w >> (b * 8)) as u8;
                }
            }
        }
    }

    /// Compara duos numeros: reddit 1 si self > b, -1 si self < b, 0 si aequales.
    pub fn compara(&self, b: &Nm) -> i32 {
        let m = if self.n > b.n { self.n } else { b.n };
        for i in (0..m).rev() {
            let av = if i < self.n { self.v[i] } else { 0 };
            let bv = if i < b.n { b.v[i] } else { 0 };
            if av > bv {
                return 1;
            }
            if av < bv {
                return -1;
            }
        }
        0
    }

    /// Verum si numerus est nihil.
    pub fn est_nihil(&self) -> bool {
        self.n == 1 && self.v[0] == 0
    }

    /// Reddit bitum i-esimum.
    pub fn bitus(&self, i: usize) -> u32 {
        let vi = i / 32;
        let bi = i % 32;
        if vi >= self.n {
            return 0;
        }
        (self.v[vi] >> bi) & 1
    }

    /// Reddit summam bitorum (numerus bitorum activorum).
    pub fn summa_bitorum(&self) -> usize {
        if self.est_nihil() {
            return 0;
        }
        let mut bits = (self.n - 1) * 32;
        let mut w = self.v[self.n - 1];
        while w != 0 {
            bits += 1;
            w >>= 1;
        }
        bits
    }
}

// --- operationes arithmeticae ---

/// r = a + b
pub fn nm_adde(r: &mut Nm, a: &Nm, b: &Nm) {
    let mut portatio: u64 = 0;
    let m = if a.n > b.n { a.n } else { b.n };
    let mut i = 0usize;
    while i < m || portatio != 0 {
        let mut summa = portatio;
        if i < a.n {
            summa += a.v[i] as u64;
        }
        if i < b.n {
            summa += b.v[i] as u64;
        }
        if i < NM_VERBA {
            r.v[i] = summa as u32;
        }
        portatio = summa >> 32;
        i += 1;
    }
    // nula verba superstantia
    while i < NM_VERBA {
        r.v[i] = 0;
        i += 1;
    }
    r.n = m + 1;
    if r.n > NM_VERBA {
        r.n = NM_VERBA;
    }
    r.normaliza();
}

/// r = a - b (praesumit a >= b)
pub fn nm_subtrahe(r: &mut Nm, a: &Nm, b: &Nm) {
    let mut mutuum: i64 = 0;
    let m = if a.n > b.n { a.n } else { b.n };
    let mut i = 0usize;
    while i < m {
        let mut diff = mutuum;
        if i < a.n {
            diff += a.v[i] as i64;
        }
        if i < b.n {
            diff -= b.v[i] as i64;
        }
        if i < NM_VERBA {
            r.v[i] = (diff & 0xFFFFFFFF) as u32;
        }
        mutuum = diff >> 32;
        i += 1;
    }
    while i < NM_VERBA {
        r.v[i] = 0;
        i += 1;
    }
    r.n = m;
    r.normaliza();
}

/// r = a * b
pub fn nm_multiplica(r: &mut Nm, a: &Nm, b: &Nm) {
    let mut temp = Nm::ex_nihilo();
    temp.n = a.n + b.n;
    if temp.n > NM_VERBA {
        temp.n = NM_VERBA;
    }

    for i in 0..a.n {
        let mut portatio: u64 = 0;
        for j in 0..b.n {
            if i + j >= NM_VERBA {
                break;
            }
            let prod = (a.v[i] as u64)
                .wrapping_mul(b.v[j] as u64)
                .wrapping_add(temp.v[i + j] as u64)
                .wrapping_add(portatio);
            temp.v[i + j] = prod as u32;
            portatio = prod >> 32;
        }
        if i + b.n < NM_VERBA {
            temp.v[i + b.n] = temp.v[i + b.n].wrapping_add(portatio as u32);
        }
    }
    temp.normaliza();
    *r = temp;
}

/// Divisio bitus-per-bitum: q = a / b, rem = a % b
pub fn nm_divide(q: &mut Nm, rem: &mut Nm, a: &Nm, b: &Nm) {
    if b.est_nihil() {
        *q = Nm::ex_nihilo();
        *rem = Nm::ex_nihilo();
        return;
    }
    if a.compara(b) < 0 {
        *q = Nm::ex_nihilo();
        *rem = a.clone();
        return;
    }

    *q = Nm::ex_nihilo();
    *rem = Nm::ex_nihilo();

    let nbits = a.summa_bitorum();
    for i in (0..nbits).rev() {
        // rem = rem * 2
        let mut c: u32 = 0;
        let nn = rem.n;
        for j in 0..=nn {
            if j >= NM_VERBA {
                break;
            }
            let novum = (rem.v[j] << 1) | c;
            c = rem.v[j] >> 31;
            rem.v[j] = novum;
        }
        // auge n si portatio excessit
        while rem.n < NM_VERBA && rem.v[rem.n] != 0 {
            rem.n += 1;
        }

        // inserere bitum
        rem.v[0] |= a.bitus(i);
        rem.normaliza();

        if rem.compara(b) >= 0 {
            // necessarium est copia temporaria quia rem est et fons et destinatio
            let rem_copia = rem.clone();
            nm_subtrahe(rem, &rem_copia, b);
            // pone bitum in q
            let vi = i / 32;
            if vi < NM_VERBA {
                q.v[vi] |= 1u32 << (i % 32);
                if vi >= q.n {
                    q.n = vi + 1;
                }
            }
        }
    }
    q.normaliza();
    rem.normaliza();
}

/// r = a mod m
pub fn nm_modulo(r: &mut Nm, a: &Nm, m: &Nm) {
    let mut q = Nm::ex_nihilo();
    nm_divide(&mut q, r, a, m);
}

/// r = (a * b) mod m
pub fn nm_modmul(r: &mut Nm, a: &Nm, b: &Nm, m: &Nm) {
    let mut prod = Nm::ex_nihilo();
    nm_multiplica(&mut prod, a, b);
    nm_modulo(r, &prod, m);
}

// --- Montgomery ---

/// Forma Montgomery pro multiplicatione modulari.
struct MontT {
    modulus: Nm,
    k: usize,        // verba in modulo
    m_inv: u32,      // -m^(-1) mod 2^32
    r_quadratum: Nm, // R^2 mod m, ubi R = 2^(k*32)
}

/// Computa -m^(-1) mod 2^32 per iterationem Newtoni.
fn mont_inv(m0: u32) -> u32 {
    let mut x: u32 = 1;
    for _ in 0..5 {
        x = x.wrapping_mul(2u32.wrapping_sub(m0.wrapping_mul(x)));
    }
    (-(x as i32)) as u32
}

/// Initia structuram Montgomery.
fn mont_initia(m: &Nm) -> MontT {
    let k = m.n;
    let m_inv = mont_inv(m.v[0]);

    // R^2 mod m: R = 2^(k*32)
    // methodus: initia r = 1, dupla k*64 vices cum reductione
    let mut r = Nm::ex_nihilo();
    r.v[0] = 1;
    for _ in 0..(k * 64) {
        let r_copia = r.clone();
        nm_adde(&mut r, &r_copia, &r_copia);
        if r.compara(m) >= 0 {
            let r_copia2 = r.clone();
            nm_subtrahe(&mut r, &r_copia2, m);
        }
    }

    MontT {
        modulus: m.clone(),
        k,
        m_inv,
        r_quadratum: r,
    }
}

/// REDC: T * R^(-1) mod m
fn mont_redc(mt: &MontT, t: &mut Nm) {
    let k = mt.k;
    for i in 0..k {
        let u = t.v[i].wrapping_mul(mt.m_inv);
        // T += u * m * 2^(32*i)
        let mut portatio: u64 = 0;
        for j in 0..k {
            let idx = i + j;
            if idx >= NM_VERBA {
                break;
            }
            let prod = (u as u64)
                .wrapping_mul(mt.modulus.v[j] as u64)
                .wrapping_add(t.v[idx] as u64)
                .wrapping_add(portatio);
            t.v[idx] = prod as u32;
            portatio = prod >> 32;
        }
        let mut j = i + k;
        while j < NM_VERBA && portatio != 0 {
            let s = (t.v[j] as u64).wrapping_add(portatio);
            t.v[j] = s as u32;
            portatio = s >> 32;
            j += 1;
        }
    }
    // T >>= k*32
    for i in 0..(NM_VERBA - k) {
        t.v[i] = t.v[i + k];
    }
    for i in (NM_VERBA - k)..NM_VERBA {
        t.v[i] = 0;
    }
    t.n = k + 1;
    if t.n > NM_VERBA {
        t.n = NM_VERBA;
    }
    t.normaliza();

    if t.compara(&mt.modulus) >= 0 {
        let t_copia = t.clone();
        nm_subtrahe(t, &t_copia, &mt.modulus);
    }
}

/// a -> a_bar = a * R mod m
fn mont_in(mt: &MontT, a: &Nm) -> Nm {
    let mut prod = Nm::ex_nihilo();
    nm_multiplica(&mut prod, a, &mt.r_quadratum);
    mont_redc(mt, &mut prod);
    prod
}

/// a_bar -> a = a_bar * R^(-1) mod m
fn mont_ex(mt: &MontT, ar: &Nm) -> Nm {
    let mut a = ar.clone();
    mont_redc(mt, &mut a);
    a
}

/// a_bar * b_bar * R^(-1) mod m
fn mont_mul(mt: &MontT, a: &Nm, b: &Nm) -> Nm {
    let mut prod = Nm::ex_nihilo();
    nm_multiplica(&mut prod, a, b);
    mont_redc(mt, &mut prod);
    prod
}

/// r = basis^exponens mod modulus (potentiatio modularis)
pub fn nm_modpot(r: &mut Nm, basis: &Nm, exponens: &Nm, modulus: &Nm) {
    // moduli parvi vel pares: recidunt ad methodum veterem
    if modulus.n < 2 || (modulus.v[0] & 1) == 0 {
        let mut base_mod = Nm::ex_nihilo();
        nm_modulo(&mut base_mod, basis, modulus);
        *r = Nm::ex_nihilo();
        r.v[0] = 1;
        let nbits = exponens.summa_bitorum();
        for i in (0..nbits).rev() {
            let r_copia = r.clone();
            nm_modmul(r, &r_copia, &r_copia, modulus);
            if exponens.bitus(i) != 0 {
                let r_copia2 = r.clone();
                nm_modmul(r, &r_copia2, &base_mod, modulus);
            }
        }
        return;
    }

    let mt = mont_initia(modulus);

    // converte in formam Montgomery
    let mut base_mod = Nm::ex_nihilo();
    nm_modulo(&mut base_mod, basis, modulus);
    let base_mont = mont_in(&mt, &base_mod);

    // acc = 1 in Montgomery = R mod m
    let mut unum = Nm::ex_nihilo();
    unum.v[0] = 1;
    let mut acc_mont = mont_in(&mt, &unum);

    let nbits = exponens.summa_bitorum();
    for i in (0..nbits).rev() {
        acc_mont = mont_mul(&mt, &acc_mont, &acc_mont);
        if exponens.bitus(i) != 0 {
            acc_mont = mont_mul(&mt, &acc_mont, &base_mont);
        }
    }

    // converte retro
    *r = mont_ex(&mt, &acc_mont);
}

// --- curva elliptica P-256 ---

/// Primus campi: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
fn ec_primus_constans() -> Nm {
    let mut p = Nm::ex_nihilo();
    p.v[0] = 0xFFFFFFFF;
    p.v[1] = 0xFFFFFFFF;
    p.v[2] = 0xFFFFFFFF;
    p.v[3] = 0x00000000;
    p.v[4] = 0x00000000;
    p.v[5] = 0x00000000;
    p.v[6] = 0x00000001;
    p.v[7] = 0xFFFFFFFF;
    p.n = 8;
    p
}

/// Ordo curvae n.
fn ec_ordo_constans() -> Nm {
    let mut n = Nm::ex_nihilo();
    n.v[0] = 0xFC632551;
    n.v[1] = 0xF3B9CAC2;
    n.v[2] = 0xA7179E84;
    n.v[3] = 0xBCE6FAAD;
    n.v[4] = 0xFFFFFFFF;
    n.v[5] = 0xFFFFFFFF;
    n.v[6] = 0x00000000;
    n.v[7] = 0xFFFFFFFF;
    n.n = 8;
    n
}

/// a = -3 mod p
fn ec_a_constans() -> Nm {
    let mut a = Nm::ex_nihilo();
    a.v[0] = 0xFFFFFFFC;
    a.v[1] = 0xFFFFFFFF;
    a.v[2] = 0xFFFFFFFF;
    a.v[3] = 0x00000000;
    a.v[4] = 0x00000000;
    a.v[5] = 0x00000000;
    a.v[6] = 0x00000001;
    a.v[7] = 0xFFFFFFFF;
    a.n = 8;
    a
}

/// Reddit primum campi P-256.
pub fn ec_primus() -> Nm {
    ec_primus_constans()
}

/// Reddit ordinem curvae P-256.
pub fn ec_ordo() -> Nm {
    ec_ordo_constans()
}

/// Reddit generatorem G curvae P-256.
pub fn ec_generator() -> EcPunctum {
    let mut gx = Nm::ex_nihilo();
    gx.v[0] = 0xD898C296;
    gx.v[1] = 0xF4A13945;
    gx.v[2] = 0x2DEB33A0;
    gx.v[3] = 0x77037D81;
    gx.v[4] = 0x63A440F2;
    gx.v[5] = 0xF8BCE6E5;
    gx.v[6] = 0xE12C4247;
    gx.v[7] = 0x6B17D1F2;
    gx.n = 8;

    let mut gy = Nm::ex_nihilo();
    gy.v[0] = 0x37BF51F5;
    gy.v[1] = 0xCBB64068;
    gy.v[2] = 0x6B315ECE;
    gy.v[3] = 0x2BCE3357;
    gy.v[4] = 0x7C0F9E16;
    gy.v[5] = 0x8EE7EB4A;
    gy.v[6] = 0xFE1A7F9B;
    gy.v[7] = 0x4FE342E2;
    gy.n = 8;

    EcPunctum {
        x: gx,
        y: gy,
        infinitum: false,
    }
}

// --- arithmetica campi Fp ---

/// Additio in campo Fp.
fn fp_adde(r: &mut Nm, a: &Nm, b: &Nm) {
    let p = ec_primus_constans();
    nm_adde(r, a, b);
    if r.compara(&p) >= 0 {
        let r_copia = r.clone();
        nm_subtrahe(r, &r_copia, &p);
    }
}

/// Subtractio in campo Fp.
fn fp_subtrahe(r: &mut Nm, a: &Nm, b: &Nm) {
    let p = ec_primus_constans();
    if a.compara(b) >= 0 {
        nm_subtrahe(r, a, b);
    } else {
        let mut temp = Nm::ex_nihilo();
        nm_adde(&mut temp, a, &p);
        nm_subtrahe(r, &temp, b);
    }
}

/// Multiplicatio in campo Fp.
fn fp_multiplica(r: &mut Nm, a: &Nm, b: &Nm) {
    let p = ec_primus_constans();
    nm_modmul(r, a, b, &p);
}

/// Inversio per theorema Fermati: a^(-1) = a^(p-2) mod p.
fn fp_inversa(r: &mut Nm, a: &Nm) {
    let p = ec_primus_constans();
    let mut exp = Nm::ex_nihilo();
    let mut duo = Nm::ex_nihilo();
    duo.v[0] = 2;
    nm_subtrahe(&mut exp, &p, &duo);
    nm_modpot(r, a, &exp, &p);
}

// --- punctum curvae ellipticae ---

/// Punctum in curva elliptica P-256.
#[derive(Clone)]
pub struct EcPunctum {
    pub x: Nm,
    pub y: Nm,
    pub infinitum: bool,
}

/// Additio duorum punctorum in curva elliptica.
pub fn ec_adde(r: &mut EcPunctum, p_pt: &EcPunctum, q_pt: &EcPunctum) {
    if p_pt.infinitum {
        *r = q_pt.clone();
        return;
    }
    if q_pt.infinitum {
        *r = p_pt.clone();
        return;
    }

    // si P == -Q, reddit infinitum
    let mut summa_y = Nm::ex_nihilo();
    fp_adde(&mut summa_y, &p_pt.y, &q_pt.y);
    if p_pt.x.compara(&q_pt.x) == 0 && summa_y.est_nihil() {
        r.x = Nm::ex_nihilo();
        r.y = Nm::ex_nihilo();
        r.infinitum = true;
        return;
    }

    let mut lambda = Nm::ex_nihilo();
    let mut temp = Nm::ex_nihilo();
    let mut temp2 = Nm::ex_nihilo();

    if p_pt.x.compara(&q_pt.x) == 0 && p_pt.y.compara(&q_pt.y) == 0 {
        // duplicatio: lambda = (3*x^2 + a) / (2*y)
        let ec_a = ec_a_constans();
        let mut x2 = Nm::ex_nihilo();
        fp_multiplica(&mut x2, &p_pt.x, &p_pt.x); // x^2
        fp_adde(&mut temp, &x2, &x2);
        let temp_copia = temp.clone();
        fp_adde(&mut temp, &temp_copia, &x2); // 3*x^2
        let temp_copia2 = temp.clone();
        fp_adde(&mut temp, &temp_copia2, &ec_a); // 3*x^2 + a

        let mut y2 = Nm::ex_nihilo();
        fp_adde(&mut y2, &p_pt.y, &p_pt.y); // 2*y
        fp_inversa(&mut temp2, &y2);
        fp_multiplica(&mut lambda, &temp, &temp2);
    } else {
        // additio: lambda = (y2 - y1) / (x2 - x1)
        fp_subtrahe(&mut temp, &q_pt.y, &p_pt.y);
        fp_subtrahe(&mut temp2, &q_pt.x, &p_pt.x);
        let mut inv = Nm::ex_nihilo();
        fp_inversa(&mut inv, &temp2);
        fp_multiplica(&mut lambda, &temp, &inv);
    }

    // x3 = lambda^2 - x1 - x2
    let mut l2 = Nm::ex_nihilo();
    fp_multiplica(&mut l2, &lambda, &lambda);
    fp_subtrahe(&mut temp, &l2, &p_pt.x);
    let mut rx = Nm::ex_nihilo();
    fp_subtrahe(&mut rx, &temp, &q_pt.x);

    // y3 = lambda * (x1 - x3) - y1
    fp_subtrahe(&mut temp, &p_pt.x, &rx);
    fp_multiplica(&mut temp2, &lambda, &temp);
    let mut ry = Nm::ex_nihilo();
    fp_subtrahe(&mut ry, &temp2, &p_pt.y);

    r.x = rx;
    r.y = ry;
    r.infinitum = false;
}

/// Multiplicatio scalaris: R = k * P (methodus duplica-et-adde).
pub fn ec_multiplica(r: &mut EcPunctum, k: &Nm, p_pt: &EcPunctum) {
    let mut acc = EcPunctum {
        x: Nm::ex_nihilo(),
        y: Nm::ex_nihilo(),
        infinitum: true,
    };

    let nbits = k.summa_bitorum();
    for i in (0..nbits).rev() {
        let mut duplex = EcPunctum {
            x: Nm::ex_nihilo(),
            y: Nm::ex_nihilo(),
            infinitum: true,
        };
        ec_adde(&mut duplex, &acc, &acc);
        if k.bitus(i) != 0 {
            ec_adde(&mut acc, &duplex, p_pt);
        } else {
            acc = duplex;
        }
    }
    *r = acc;
}

// --- RSA ---

/// DigestInfo pro SHA-256 (DER)
const DIGESTINFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Clavis publica RSA.
pub struct RsaClavis {
    pub modulus: Vec<u8>,
    pub exponens: Vec<u8>,
}

/// Verificatio signaturae RSA PKCS#1 v1.5.
/// Reddit 0 si signatura valida, -1 aliter.
pub fn rsa_verifica(clavis: &RsaClavis, signatura: &[u8], digestum: &[u8; 32]) -> i32 {
    let s = Nm::ex_octis(signatura);
    let n = Nm::ex_octis(&clavis.modulus);
    let e = Nm::ex_octis(&clavis.exponens);

    // m = s^e mod n
    let mut m = Nm::ex_nihilo();
    nm_modpot(&mut m, &s, &e, &n);

    // converte ad octos
    let mag = clavis.modulus.len();
    let mut effectus = vec![0u8; mag];
    m.ad_octos(&mut effectus);

    // verifica PKCS#1 v1.5: 00 01 FF...FF 00 DigestInfo Hash
    if mag < DIGESTINFO_SHA256.len() + 32 + 11 {
        return -1;
    }
    if effectus[0] != 0x00 || effectus[1] != 0x01 {
        return -1;
    }

    let mut i = 2usize;
    while i < mag && effectus[i] == 0xFF {
        i += 1;
    }
    if i < 10 || i >= mag || effectus[i] != 0x00 {
        return -1;
    }
    i += 1;

    if i + DIGESTINFO_SHA256.len() + 32 != mag {
        return -1;
    }
    if effectus[i..i + DIGESTINFO_SHA256.len()] != DIGESTINFO_SHA256[..] {
        return -1;
    }
    if effectus[i + DIGESTINFO_SHA256.len()..i + DIGESTINFO_SHA256.len() + 32] != digestum[..] {
        return -1;
    }

    0
}

// --- ASN.1 / X.509 ---

/// Structura interna pro resolutione ASN.1.
struct Asn1Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Asn1Cursor<'a> {
    fn nova(data: &'a [u8]) -> Self {
        Asn1Cursor { data, pos: 0 }
    }

    /// Lege caput ASN.1 DER (signum + longitudo).
    fn lege_caput(&mut self) -> Option<(u8, usize)> {
        if self.pos >= self.data.len() {
            return None;
        }
        let signum = self.data[self.pos];
        self.pos += 1;
        if self.pos >= self.data.len() {
            return None;
        }
        let prim = self.data[self.pos];
        self.pos += 1;

        let longitudo = if prim < 0x80 {
            prim as usize
        } else {
            let nb = (prim & 0x7f) as usize;
            if nb > 4 || self.pos + nb > self.data.len() {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..nb {
                l = (l << 8) | self.data[self.pos] as usize;
                self.pos += 1;
            }
            l
        };

        Some((signum, longitudo))
    }

    /// Praetermitte elementum ASN.1.
    fn praetermitte(&mut self) -> Option<()> {
        let (_signum, longitudo) = self.lege_caput()?;
        if self.pos + longitudo > self.data.len() {
            return None;
        }
        self.pos += longitudo;
        Some(())
    }

    /// Reddit octetos a positione currenti per longitudinem datam.
    fn lege_octos(&self, longitudo: usize) -> Option<&'a [u8]> {
        if self.pos + longitudo > self.data.len() {
            return None;
        }
        Some(&self.data[self.pos..self.pos + longitudo])
    }
}

/// Extrahe clavem publicam RSA ex certificato X.509 DER.
pub fn asn1_extrahe_rsa(cert: &[u8]) -> Option<RsaClavis> {
    let mut c = Asn1Cursor::nova(cert);

    // SEQUENCE exterior (Certificate)
    let (signum, _longitudo) = c.lege_caput()?;
    if signum != 0x30 {
        return None;
    }

    // TBSCertificate SEQUENCE
    let (signum, longitudo) = c.lege_caput()?;
    if signum != 0x30 {
        return None;
    }
    let tbs_finis = c.pos + longitudo;

    // versio [0] EXPLICIT (optionalis)
    let salvatum = c.pos;
    let (signum, longitudo_v) = c.lege_caput()?;
    if (signum & 0xe0) == 0xa0 {
        c.pos += longitudo_v;
    } else {
        c.pos = salvatum;
    }

    // praetermitte: numerusSerialis, algorithmus, emittens, validitas, subiectum
    for _ in 0..5 {
        if c.pos >= tbs_finis {
            return None;
        }
        c.praetermitte()?;
    }

    // SubjectPublicKeyInfo SEQUENCE
    let (signum, longitudo) = c.lege_caput()?;
    if signum != 0x30 {
        return None;
    }
    let spki_finis = c.pos + longitudo;

    // AlgorithmIdentifier SEQUENCE — praetermitte
    if c.pos >= spki_finis {
        return None;
    }
    c.praetermitte()?;

    // subjectPublicKey BIT STRING
    let (signum, longitudo) = c.lege_caput()?;
    if signum != 0x03 {
        return None;
    }
    if longitudo < 1 {
        return None;
    }
    c.pos += 1; // praetermitte bitos non usitatos
    let bit_longitudo = longitudo - 1;

    // RSAPublicKey SEQUENCE interna
    let rsa_finis = c.pos + bit_longitudo;
    let (signum, _longitudo) = c.lege_caput()?;
    if signum != 0x30 {
        return None;
    }

    // modulus INTEGER
    let (signum, longitudo) = c.lege_caput()?;
    if signum != 0x02 {
        return None;
    }
    let mut mod_data = c.lege_octos(longitudo)?;
    let mut mod_mag = longitudo;
    // praetermitte nulum ducens
    if mod_mag > 0 && mod_data[0] == 0x00 {
        mod_data = &mod_data[1..];
        mod_mag -= 1;
    }
    c.pos += longitudo;

    // exponens INTEGER
    if c.pos >= rsa_finis {
        return None;
    }
    let (signum, longitudo) = c.lege_caput()?;
    if signum != 0x02 {
        return None;
    }
    let mut exp_data = c.lege_octos(longitudo)?;
    let mut exp_mag = longitudo;
    if exp_mag > 0 && exp_data[0] == 0x00 {
        exp_data = &exp_data[1..];
        exp_mag -= 1;
    }

    Some(RsaClavis {
        modulus: mod_data[..mod_mag].to_vec(),
        exponens: exp_data[..exp_mag].to_vec(),
    })
}

// --- alea ---

/// Imple alveum cum octis aleatoriis ex /dev/urandom.
/// Reddit 0 si successum, -1 si error.
pub fn alea_imple(alveus: &mut [u8]) -> i32 {
    match File::open("/dev/urandom") {
        Ok(mut f) => {
            let mut lectum = 0usize;
            while lectum < alveus.len() {
                match f.read(&mut alveus[lectum..]) {
                    Ok(0) => return -1,
                    Ok(r) => lectum += r,
                    Err(_) => return -1,
                }
            }
            0
        }
        Err(_) => -1,
    }
}
