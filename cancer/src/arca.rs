// arca.rs — AES-128 et modus GCM
//
// Implementatio FIPS 197 (AES) et NIST SP 800-38D (GCM).
// Sine dependentiis externis.

// --- Tabula S (SubBytes) ---

static TABULA_S: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// --- Constantiae rotundae (Rcon) ---

static RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// --- Expansio clavis ---

/// Substitue singulos octos verbi per tabulam S.
fn verbum_sub(w: u32) -> u32 {
    (TABULA_S[((w >> 24) & 0xff) as usize] as u32) << 24
        | (TABULA_S[((w >> 16) & 0xff) as usize] as u32) << 16
        | (TABULA_S[((w >> 8) & 0xff) as usize] as u32) << 8
        | TABULA_S[(w & 0xff) as usize] as u32
}

/// Rota verbum sinistram per 8 bitos.
fn verbum_rota(w: u32) -> u32 {
    (w << 8) | (w >> 24)
}

/// Contextus AES-128 cum clavibus expansis.
pub struct Arca128Ctx {
    claves_expansae: [u32; 44],
}

impl Arca128Ctx {
    /// Expande clavem 128-bitium in 44 verba scheduli clavium.
    pub fn expande(clavis: &[u8; 16]) -> Self {
        let mut claves_expansae = [0u32; 44];

        for i in 0..4 {
            claves_expansae[i] = (clavis[4 * i] as u32) << 24
                | (clavis[4 * i + 1] as u32) << 16
                | (clavis[4 * i + 2] as u32) << 8
                | clavis[4 * i + 3] as u32;
        }

        for i in 4..44 {
            let mut temp = claves_expansae[i - 1];
            if i % 4 == 0 {
                temp = verbum_sub(verbum_rota(temp)) ^ ((RCON[i / 4 - 1] as u32) << 24);
            }
            claves_expansae[i] = claves_expansae[i - 4] ^ temp;
        }

        Self { claves_expansae }
    }

    /// Occulta unum truncum 128-bitium (AES block encrypt).
    pub fn occulta_truncum(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut status = *input;

        adde_clavem(&mut status, &self.claves_expansae[0..4]);

        for rotunda in 1..10 {
            sub_octos(&mut status);
            move_ordines(&mut status);
            misce_columnas(&mut status);
            adde_clavem(
                &mut status,
                &self.claves_expansae[4 * rotunda..4 * rotunda + 4],
            );
        }

        sub_octos(&mut status);
        move_ordines(&mut status);
        adde_clavem(&mut status, &self.claves_expansae[40..44]);

        status
    }
}

// --- Functiones internae AES ---

/// Adde clavem rotundam ad statum (AddRoundKey).
fn adde_clavem(status: &mut [u8; 16], clavis: &[u32]) {
    for i in 0..4 {
        status[4 * i] ^= (clavis[i] >> 24) as u8;
        status[4 * i + 1] ^= (clavis[i] >> 16) as u8;
        status[4 * i + 2] ^= (clavis[i] >> 8) as u8;
        status[4 * i + 3] ^= clavis[i] as u8;
    }
}

/// Substitue omnes octos status per tabulam S (SubBytes).
fn sub_octos(s: &mut [u8; 16]) {
    for i in 0..16 {
        s[i] = TABULA_S[s[i] as usize];
    }
}

/// Move ordines status (ShiftRows).
fn move_ordines(s: &mut [u8; 16]) {
    // ordo 1: move sinistram 1
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // ordo 2: move sinistram 2
    let t = s[2];
    s[2] = s[10];
    s[10] = t;
    let t = s[6];
    s[6] = s[14];
    s[14] = t;
    // ordo 3: move sinistram 3
    let t = s[3];
    s[3] = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = t;
}

/// Multiplicatio per x in GF(2^8) cum polynomio reducente.
fn xtime(a: u8) -> u8 {
    (a << 1) ^ (((a >> 7) & 1) * 0x1b)
}

/// Misce columnas status (MixColumns).
fn misce_columnas(s: &mut [u8; 16]) {
    for i in 0..4 {
        let a = s[4 * i];
        let b = s[4 * i + 1];
        let c = s[4 * i + 2];
        let d = s[4 * i + 3];
        let e = a ^ b ^ c ^ d;
        s[4 * i] ^= e ^ xtime(a ^ b);
        s[4 * i + 1] ^= e ^ xtime(b ^ c);
        s[4 * i + 2] ^= e ^ xtime(c ^ d);
        s[4 * i + 3] ^= e ^ xtime(d ^ a);
    }
}

// --- GCM ---

/// Multiplicatio in GF(2^128) cum polynomio reducente x^128 + x^7 + x^2 + x + 1.
fn gf128_multiplica(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut v = *y;
    let mut z = [0u8; 16];

    for i in 0..128 {
        if x[i / 8] & (1 << (7 - i % 8)) != 0 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        // v = v * x mod P(x)
        let portatio = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if portatio != 0 {
            v[0] ^= 0xe1;
        }
    }
    z
}

/// Incrementa numeratorem (ultimos 4 octos, big-endian).
fn incrementa(truncus: &mut [u8; 16]) {
    for i in (12..=15).rev() {
        truncus[i] = truncus[i].wrapping_add(1);
        if truncus[i] != 0 {
            break;
        }
    }
}

/// GHASH: processus AAD et textus occultus cum clave H.
fn ghash(h: &[u8; 16], aad: &[u8], occultus: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];

    // processus AAD
    let aad_mag = aad.len();
    let mut i = 0;
    while i + 16 <= aad_mag {
        for j in 0..16 {
            x[j] ^= aad[i + j];
        }
        x = gf128_multiplica(&x, h);
        i += 16;
    }
    if i < aad_mag {
        let mut truncus = [0u8; 16];
        truncus[..aad_mag - i].copy_from_slice(&aad[i..aad_mag]);
        for j in 0..16 {
            x[j] ^= truncus[j];
        }
        x = gf128_multiplica(&x, h);
    }

    // processus textus occultus
    let occ_mag = occultus.len();
    i = 0;
    while i + 16 <= occ_mag {
        for j in 0..16 {
            x[j] ^= occultus[i + j];
        }
        x = gf128_multiplica(&x, h);
        i += 16;
    }
    if i < occ_mag {
        let mut truncus = [0u8; 16];
        truncus[..occ_mag - i].copy_from_slice(&occultus[i..occ_mag]);
        for j in 0..16 {
            x[j] ^= truncus[j];
        }
        x = gf128_multiplica(&x, h);
    }

    // longitudines (in bitibus, big-endian 64 bit quisque)
    let aad_bits = (aad_mag as u64) * 8;
    let occ_bits = (occ_mag as u64) * 8;
    let mut longitudines = [0u8; 16];
    for j in 0..8 {
        longitudines[j] = (aad_bits >> (56 - j * 8)) as u8;
        longitudines[8 + j] = (occ_bits >> (56 - j * 8)) as u8;
    }
    for j in 0..16 {
        x[j] ^= longitudines[j];
    }
    gf128_multiplica(&x, h)
}

// --- AES-128-GCM occultatio ---

/// Occulta data cum AES-128-GCM. Alveus occultus debet eandem longitudinem habere ac clarus.
pub fn arca128_gcm_occulta(
    clavis: &[u8; 16],
    iv: &[u8; 12],
    clarus: &[u8],
    aad: &[u8],
    occultus: &mut [u8],
    sigillum: &mut [u8; 16],
) {
    let ctx = Arca128Ctx::expande(clavis);

    // H = AES(K, 0^128)
    let nul = [0u8; 16];
    let h = ctx.occulta_truncum(&nul);

    // J0 = IV || 00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    // occulta cum CTR (initium a J0 + 1)
    let mut numerator = j0;
    let clarus_mag = clarus.len();

    let mut i = 0;
    while i < clarus_mag {
        incrementa(&mut numerator);
        let fluxus = ctx.occulta_truncum(&numerator);
        let n = core::cmp::min(16, clarus_mag - i);
        for j in 0..n {
            occultus[i + j] = clarus[i + j] ^ fluxus[j];
        }
        i += 16;
    }

    // sigillum = GHASH(H, AAD, C) XOR AES(K, J0)
    let s = ghash(&h, aad, &occultus[..clarus_mag]);
    let e_j0 = ctx.occulta_truncum(&j0);
    for j in 0..16 {
        sigillum[j] = s[j] ^ e_j0[j];
    }
}

// --- AES-128-GCM revelatio ---

/// Revela data cum AES-128-GCM. Reddit 0 si sigillum convenit, -1 aliter.
/// Alveus clarus debet eandem longitudinem habere ac occultus.
pub fn arca128_gcm_revela(
    clavis: &[u8; 16],
    iv: &[u8; 12],
    occultus: &[u8],
    aad: &[u8],
    clarus: &mut [u8],
    sigillum: &[u8; 16],
) -> i32 {
    let ctx = Arca128Ctx::expande(clavis);

    let nul = [0u8; 16];
    let h = ctx.occulta_truncum(&nul);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    // verifica sigillum ante revelationem
    let s = ghash(&h, aad, occultus);
    let e_j0 = ctx.occulta_truncum(&j0);
    let mut sigillum_computatum = [0u8; 16];
    for j in 0..16 {
        sigillum_computatum[j] = s[j] ^ e_j0[j];
    }

    // comparatio temporis constantis
    let mut diff: u8 = 0;
    for j in 0..16 {
        diff |= sigillum_computatum[j] ^ sigillum[j];
    }
    if diff != 0 {
        return -1;
    }

    // revela cum CTR
    let mut numerator = j0;
    let occultus_mag = occultus.len();

    let mut i = 0;
    while i < occultus_mag {
        incrementa(&mut numerator);
        let fluxus = ctx.occulta_truncum(&numerator);
        let n = core::cmp::min(16, occultus_mag - i);
        for j in 0..n {
            clarus[i + j] = occultus[i + j] ^ fluxus[j];
        }
        i += 16;
    }

    0
}

#[cfg(test)]
mod probationes {
    use super::*;

    /// Probatio: occultatio et revelatio cum AES-128-GCM debent esse inversae.
    #[test]
    fn proba_gcm_circuitu() {
        let clavis = [0x01u8; 16];
        let iv = [0x02u8; 12];
        let clarus = b"Salve, munde! Haec est probatio.";
        let aad = b"data addita";

        let mut occultus = vec![0u8; clarus.len()];
        let mut sigillum = [0u8; 16];
        arca128_gcm_occulta(&clavis, &iv, clarus, aad, &mut occultus, &mut sigillum);

        let mut revelatus = vec![0u8; clarus.len()];
        let res = arca128_gcm_revela(&clavis, &iv, &occultus, aad, &mut revelatus, &sigillum);
        assert_eq!(res, 0);
        assert_eq!(&revelatus[..], &clarus[..]);
    }

    /// Probatio: sigillum mutatum debet revelationem impedire.
    #[test]
    fn proba_gcm_sigillum_falsum() {
        let clavis = [0x03u8; 16];
        let iv = [0x04u8; 12];
        let clarus = b"Textus secretus";
        let aad = b"";

        let mut occultus = vec![0u8; clarus.len()];
        let mut sigillum = [0u8; 16];
        arca128_gcm_occulta(&clavis, &iv, clarus, aad, &mut occultus, &mut sigillum);

        // muta sigillum
        sigillum[0] ^= 0xff;

        let mut revelatus = vec![0u8; clarus.len()];
        let res = arca128_gcm_revela(&clavis, &iv, &occultus, aad, &mut revelatus, &sigillum);
        assert_eq!(res, -1);
    }
}
