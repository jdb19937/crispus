// velum.rs — TLS 1.2 (RFC 5246)
//
// Solum cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
// Curva: secp256r1 (P-256)
//
// Sine dependentiis externis. Jacobus Bernoulli fecit.

#![allow(unused_imports)]

use crate::arca::{arca128_gcm_occulta, arca128_gcm_revela};
use crate::numerus::{
    alea_imple, asn1_extrahe_rsa, ec_generator, ec_multiplica, rsa_verifica, EcPunctum, Nm,
    RsaClavis,
};
use crate::summa::{sigillum256, Summa256Ctx};
use crate::utilia::{leg16, leg24, lege_plene, mitte_plene, scr16, scr24};
use std::io::{Read, Write};
use std::net::TcpStream;

/* --- constantiae --- */

const VERSIO_TLS12: u16 = 0x0303;
const VERSIO_TLS10: u16 = 0x0301;

const TABELLA_MUTATIO: u8 = 20; // ChangeCipherSpec
const TABELLA_SALUTATIO: u8 = 22; // Handshake
const TABELLA_APPLICATIO: u8 = 23; // Application Data

const SAL_SALVE_CLIENTIS: u8 = 1;
const SAL_SALVE_SERVITORIS: u8 = 2;
const SAL_TESTIMONIUM: u8 = 11;
const SAL_CLAVIS_SERVITORIS: u8 = 12;
const SAL_SALVE_FACTUM: u8 = 14;
const SAL_CLAVIS_CLIENTIS: u8 = 16;
const SAL_FINITUM: u8 = 20;

// cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
const CIPHER_ECDHE: u16 = 0xc02f;

/* --- structura veli --- */

/// Velum — involucrum TLS 1.2 super TcpStream.
pub struct Velum {
    stream: TcpStream,
    hospes: String,

    // aleae
    clientis_alea: [u8; 32],
    servitoris_alea: [u8; 32],

    // ECDHE
    ec_privata: Nm,
    ec_publica_servitoris: EcPunctum,

    // claves derivatae
    clavis_scr_c: [u8; 16], // clavis scribendi clientis
    clavis_scr_s: [u8; 16], // clavis scribendi servitoris
    iv_c: [u8; 4],          // IV implicita clientis
    iv_s: [u8; 4],          // IV implicita servitoris

    // numeri ordinis pro nonce GCM
    seq_c: u64,
    seq_s: u64,

    // transcriptum salutationis (SHA-256 currentis)
    transcriptum: Summa256Ctx,

    // secretum dominale
    secretum_dom: [u8; 48],

    // versio record layer (0x0301 initio, 0x0303 post ServerHello)
    versio_tabellae: u16,

    // status: occultans/revelans post mutationem cipher
    occultans: bool,
    revelans: bool,

    // alveus salutationis (accumulat nuntios trans tabellas)
    alveus_sal: Vec<u8>,
    sal_pos: usize,
    sal_mag: usize,

    // alveus applicationis (data revelata)
    alveus_app: Vec<u8>,
    app_pos: usize,
    app_mag: usize,
}

/* --- TLS PRF (SHA-256) --- */

/// PRF TLS 1.2 fundata in HMAC-SHA-256.
fn prf(secretum: &[u8], titulus: &str, semen: &[u8], effectus: &mut [u8]) {
    let tit_oct = titulus.as_bytes();

    // semen completum = titulus || semen
    let mut sc = Vec::with_capacity(tit_oct.len() + semen.len());
    sc.extend_from_slice(tit_oct);
    sc.extend_from_slice(semen);

    // A(0) = sc, A(i) = HMAC(secretum, A(i-1))
    let mut a = sigillum256(secretum, &sc);

    let eff_mag = effectus.len();
    let mut scriptum: usize = 0;
    while scriptum < eff_mag {
        // P(i) = HMAC(secretum, A(i) || sc)
        let mut concatenatio = Vec::with_capacity(32 + sc.len());
        concatenatio.extend_from_slice(&a);
        concatenatio.extend_from_slice(&sc);

        let p = sigillum256(secretum, &concatenatio);

        let mut n = eff_mag - scriptum;
        if n > 32 {
            n = 32;
        }
        effectus[scriptum..scriptum + n].copy_from_slice(&p[..n]);
        scriptum += n;

        // A(i+1) = HMAC(secretum, A(i))
        a = sigillum256(secretum, &a);
    }
}

impl Velum {
    /// Crea novum velum ex TcpStream et nomine hospitis.
    pub fn crea(stream: TcpStream, hospes: &str) -> Self {
        Velum {
            stream,
            hospes: hospes.to_string(),
            clientis_alea: [0u8; 32],
            servitoris_alea: [0u8; 32],
            ec_privata: Nm::ex_nihilo(),
            ec_publica_servitoris: EcPunctum {
                x: Nm::ex_nihilo(),
                y: Nm::ex_nihilo(),
                infinitum: false,
            },
            clavis_scr_c: [0u8; 16],
            clavis_scr_s: [0u8; 16],
            iv_c: [0u8; 4],
            iv_s: [0u8; 4],
            seq_c: 0,
            seq_s: 0,
            transcriptum: Summa256Ctx::initia(),
            secretum_dom: [0u8; 48],
            versio_tabellae: VERSIO_TLS10,
            occultans: false,
            revelans: false,
            alveus_sal: vec![0u8; 32768],
            sal_pos: 0,
            sal_mag: 0,
            alveus_app: vec![0u8; 16640], // 16384 + 256
            app_pos: 0,
            app_mag: 0,
        }
    }

    /* --- adde ad transcriptum salutationis --- */

    fn transcribe(&mut self, data: &[u8]) {
        self.transcriptum.adde(data);
    }

    /* --- TLS record mittere --- */

    fn mitte_tabellam(&mut self, genus: u8, data: &[u8]) -> i32 {
        let mag = data.len();
        let mut caput = [0u8; 5];
        caput[0] = genus;
        scr16(&mut caput[1..3], self.versio_tabellae);
        scr16(&mut caput[3..5], mag as u16);
        if mitte_plene(&mut self.stream, &caput).is_err() {
            return -1;
        }
        if mag > 0 && mitte_plene(&mut self.stream, data).is_err() {
            return -1;
        }
        0
    }

    /// Mitte tabellam occultam (AES-128-GCM).
    fn mitte_tabellam_occultam(&mut self, genus: u8, data: &[u8]) -> i32 {
        let mag = data.len();

        // nonce = iv_c (4) || explicit_nonce (8)
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.iv_c);
        for i in 0..8usize {
            nonce[4 + i] = (self.seq_c >> ((7 - i) * 8)) as u8;
        }

        // AAD: seq (8) || genus (1) || versio (2) || longitudo (2)
        let mut aad = [0u8; 13];
        for i in 0..8usize {
            aad[i] = (self.seq_c >> ((7 - i) * 8)) as u8;
        }
        aad[8] = genus;
        scr16(&mut aad[9..11], VERSIO_TLS12);
        scr16(&mut aad[11..13], mag as u16);

        // occulta
        let mut occultus = vec![0u8; 8 + mag + 16];

        // explicit nonce (8 octorum)
        occultus[..8].copy_from_slice(&nonce[4..12]);

        let mut sigillum_buf = [0u8; 16];
        arca128_gcm_occulta(
            &self.clavis_scr_c,
            &nonce,
            data,
            &aad,
            &mut occultus[8..8 + mag],
            &mut sigillum_buf,
        );
        occultus[8 + mag..8 + mag + 16].copy_from_slice(&sigillum_buf);

        let rc = self.mitte_tabellam(genus, &occultus);
        self.seq_c += 1;
        rc
    }

    /* --- TLS record legere --- */

    fn lege_tabellam(&mut self, data: &mut [u8]) -> Result<(u8, usize), i32> {
        let mut caput = [0u8; 5];
        if lege_plene(&mut self.stream, &mut caput).is_err() {
            return Err(-1);
        }
        let genus = caput[0];
        let mag = leg16(&caput[3..5]) as usize;
        if mag > 16384 + 256 {
            return Err(-1);
        }
        if lege_plene(&mut self.stream, &mut data[..mag]).is_err() {
            return Err(-1);
        }
        Ok((genus, mag))
    }

    /// Lege et revela tabellam.
    fn lege_tabellam_revelam(&mut self, data: &mut [u8]) -> Result<(u8, usize), i32> {
        let mut alveus = vec![0u8; 16640];
        let (genus, alveus_mag) = self.lege_tabellam(&mut alveus)?;

        if !self.revelans {
            data[..alveus_mag].copy_from_slice(&alveus[..alveus_mag]);
            return Ok((genus, alveus_mag));
        }

        // revelatio GCM: alveus = explicit_nonce(8) || ciphertext || tag(16)
        if alveus_mag < 24 {
            return Err(-1);
        }

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.iv_s);
        nonce[4..12].copy_from_slice(&alveus[..8]);

        let tc_mag = alveus_mag - 8 - 16;

        // AAD
        let mut aad = [0u8; 13];
        for i in 0..8usize {
            aad[i] = (self.seq_s >> ((7 - i) * 8)) as u8;
        }
        aad[8] = genus;
        scr16(&mut aad[9..11], VERSIO_TLS12);
        scr16(&mut aad[11..13], tc_mag as u16);

        let mut sigillum_buf = [0u8; 16];
        sigillum_buf.copy_from_slice(&alveus[8 + tc_mag..8 + tc_mag + 16]);

        if arca128_gcm_revela(
            &self.clavis_scr_s,
            &nonce,
            &alveus[8..8 + tc_mag],
            &aad,
            &mut data[..tc_mag],
            &sigillum_buf,
        ) < 0
        {
            return Err(-1);
        }

        self.seq_s += 1;
        Ok((genus, tc_mag))
    }

    /* --- legere nuntios salutationis a servitore --- */

    /// Imple alveum salutationis donec habeamus 'opus' octos disponibiles.
    fn sal_imple(&mut self, opus: usize) -> i32 {
        while self.sal_mag - self.sal_pos < opus {
            let mut alveus = vec![0u8; 16640];
            let (gen_tab, alveus_mag) = match self.lege_tabellam(&mut alveus) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            if gen_tab != TABELLA_SALUTATIO {
                return -1;
            }
            // compacta si opus est
            if self.sal_pos > 0 && self.sal_mag + alveus_mag > self.alveus_sal.len() {
                let restans = self.sal_mag - self.sal_pos;
                for i in 0..restans {
                    self.alveus_sal[i] = self.alveus_sal[self.sal_pos + i];
                }
                self.sal_mag = restans;
                self.sal_pos = 0;
            }
            if self.sal_mag + alveus_mag > self.alveus_sal.len() {
                return -1;
            }
            self.alveus_sal[self.sal_mag..self.sal_mag + alveus_mag]
                .copy_from_slice(&alveus[..alveus_mag]);
            self.sal_mag += alveus_mag;
        }
        0
    }

    /// Lege unum nuntium salutationis (potest legere plures tabellas).
    fn lege_nuntium_sal(&mut self, data: &mut [u8]) -> Result<(u8, usize), i32> {
        // assure caput salutationis (4 octorum)
        if self.sal_imple(4) < 0 {
            return Err(-1);
        }

        let genus = self.alveus_sal[self.sal_pos];
        let lon = leg24(&self.alveus_sal[self.sal_pos + 1..self.sal_pos + 4]) as usize;

        // assure corpus integrum
        if self.sal_imple(4 + lon) < 0 {
            return Err(-1);
        }

        let pos = self.sal_pos;
        data[..lon].copy_from_slice(&self.alveus_sal[pos + 4..pos + 4 + lon]);

        // adde ad transcriptum — copiam facimus ne borrow confliciat
        let nuntius = self.alveus_sal[pos..pos + 4 + lon].to_vec();
        self.transcribe(&nuntius);

        self.sal_pos += 4 + lon;
        if self.sal_pos == self.sal_mag {
            self.sal_pos = 0;
            self.sal_mag = 0;
        }

        Ok((genus, lon))
    }

    /* --- constructio ClientHello --- */

    fn mitte_salve_clientis(&mut self) -> i32 {
        alea_imple(&mut self.clientis_alea);

        // extensiones
        let hospes_oct = self.hospes.as_bytes().to_vec();
        let hospes_mag = hospes_oct.len();

        // SNI
        let mut ext_sni = Vec::new();
        let mut tmp2 = [0u8; 2];
        scr16(&mut tmp2, 0x0000); // genus: server_name
        ext_sni.extend_from_slice(&tmp2);
        let sni_data_mag = 2 + 1 + 2 + hospes_mag;
        scr16(&mut tmp2, sni_data_mag as u16);
        ext_sni.extend_from_slice(&tmp2);
        scr16(&mut tmp2, (sni_data_mag - 2) as u16);
        ext_sni.extend_from_slice(&tmp2);
        ext_sni.push(0x00); // genus: host_name
        scr16(&mut tmp2, hospes_mag as u16);
        ext_sni.extend_from_slice(&tmp2);
        ext_sni.extend_from_slice(&hospes_oct);

        // supported_groups: secp256r1
        let ext_groups: [u8; 8] = [
            0x00, 0x0a, // genus
            0x00, 0x04, // longitudo
            0x00, 0x02, // index longitudo
            0x00, 0x17, // secp256r1
        ];

        // ec_point_formats: uncompressed
        let ext_ecf: [u8; 6] = [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00];

        // signature_algorithms: rsa_pkcs1_sha256 solum
        let ext_sig: [u8; 8] = [0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01];

        // renegotiation_info (vacua)
        let ext_reneg: [u8; 5] = [0xff, 0x01, 0x00, 0x01, 0x00];

        let ext_totalis =
            ext_sni.len() + ext_groups.len() + ext_ecf.len() + ext_sig.len() + ext_reneg.len();

        // corpus ClientHello
        // 2(versio) + 32(alea) + 1(sid_mag) + 2(cs_mag) + 4(cs) +
        // 1(comp_mag) + 1(comp) + 2(ext_mag) + extensiones
        let corpus_mag = 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2 + ext_totalis;

        // nuntius salutationis = genus(1) + longitudo(3) + corpus
        let nuntius_mag = 4 + corpus_mag;
        let mut nuntius = vec![0u8; nuntius_mag];

        let mut p: usize = 0;

        // caput salutationis
        nuntius[p] = SAL_SALVE_CLIENTIS;
        p += 1;
        scr24(&mut nuntius[p..p + 3], corpus_mag as u32);
        p += 3;

        // versio clientis
        scr16(&mut nuntius[p..p + 2], VERSIO_TLS12);
        p += 2;

        // alea clientis
        nuntius[p..p + 32].copy_from_slice(&self.clientis_alea);
        p += 32;

        // sessio ID (vacua)
        nuntius[p] = 0;
        p += 1;

        // cipher suites
        scr16(&mut nuntius[p..p + 2], 4); // 2 cipher suites * 2 octorum
        p += 2;
        scr16(&mut nuntius[p..p + 2], CIPHER_ECDHE);
        p += 2;
        scr16(&mut nuntius[p..p + 2], 0x00ff); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        p += 2;

        // compressio: nulla
        nuntius[p] = 1;
        p += 1;
        nuntius[p] = 0;
        p += 1;

        // extensiones
        scr16(&mut nuntius[p..p + 2], ext_totalis as u16);
        p += 2;
        nuntius[p..p + ext_sni.len()].copy_from_slice(&ext_sni);
        p += ext_sni.len();
        nuntius[p..p + ext_groups.len()].copy_from_slice(&ext_groups);
        p += ext_groups.len();
        nuntius[p..p + ext_ecf.len()].copy_from_slice(&ext_ecf);
        p += ext_ecf.len();
        nuntius[p..p + ext_sig.len()].copy_from_slice(&ext_sig);
        p += ext_sig.len();
        nuntius[p..p + ext_reneg.len()].copy_from_slice(&ext_reneg);
        let _ = p + ext_reneg.len(); // consummatum est

        // adde ad transcriptum
        self.transcribe(&nuntius);

        // involve in tabella TLS
        self.mitte_tabellam(TABELLA_SALUTATIO, &nuntius)
    }

    /* --- processus salutationis --- */

    /// Exsequitur salutationem TLS 1.2 completam.
    /// Redit 0 si succedit, -1 si fallit.
    pub fn saluta(&mut self) -> i32 {
        let mut data = vec![0u8; 32768];

        // 1. mitte ClientHello
        if self.mitte_salve_clientis() < 0 {
            return -1;
        }

        // 2. accipe ServerHello
        let (genus, mag) = match self.lege_nuntium_sal(&mut data) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if genus != SAL_SALVE_SERVITORIS {
            return -1;
        }
        if mag < 38 {
            return -1;
        }
        // versio (2) + alea (32) + sessio_id_mag (1) ...
        self.servitoris_alea.copy_from_slice(&data[2..34]);
        let sid_mag = data[34] as usize;
        let pos = 35 + sid_mag;
        if pos + 3 > mag {
            return -1;
        }
        let cipher = leg16(&data[pos..pos + 2]);
        if cipher != CIPHER_ECDHE {
            return -1;
        }
        self.versio_tabellae = VERSIO_TLS12;

        // 3. accipe Certificate
        let (genus, mag) = match self.lege_nuntium_sal(&mut data) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if genus != SAL_TESTIMONIUM {
            return -1;
        }
        // processus catena testimoniorum
        if mag < 3 {
            return -1;
        }
        let catena_mag = leg24(&data[0..3]) as usize;
        if catena_mag + 3 > mag {
            return -1;
        }
        // primum testimonium
        if catena_mag < 3 {
            return -1;
        }
        let test_mag = leg24(&data[3..6]) as usize;
        if test_mag + 6 > mag {
            return -1;
        }
        // extrahe clavem RSA
        let clavis_rsa = match asn1_extrahe_rsa(&data[6..6 + test_mag]) {
            Some(c) => c,
            None => return -1,
        };

        // 4. accipe ServerKeyExchange
        let (genus, mag) = match self.lege_nuntium_sal(&mut data) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if genus != SAL_CLAVIS_SERVITORIS {
            return -1;
        }
        // parsamus parametra EC
        if mag < 4 {
            return -1;
        }
        if data[0] != 0x03 {
            return -1; // named_curve
        }
        if leg16(&data[1..3]) != 0x0017 {
            return -1; // secp256r1
        }
        let pub_mag = data[3] as usize;
        if pub_mag != 65 || mag < 4 + 65 {
            return -1;
        }
        if data[4] != 0x04 {
            return -1; // uncompressed
        }
        self.ec_publica_servitoris.x = Nm::ex_octis(&data[5..37]);
        self.ec_publica_servitoris.y = Nm::ex_octis(&data[37..69]);
        self.ec_publica_servitoris.infinitum = false;

        // verifica signaturam
        let params_mag = 4 + pub_mag;
        let mut sig_offset = params_mag;
        if sig_offset + 4 > mag {
            return -1;
        }
        // algorithmus signaturae (2 octorum) — praetermittimus valores
        sig_offset += 2;
        let sig_mag = leg16(&data[sig_offset..sig_offset + 2]) as usize;
        sig_offset += 2;
        if sig_offset + sig_mag > mag {
            return -1;
        }

        // digestum: SHA256(clientis_alea || servitoris_alea || params)
        {
            let mut ctx = Summa256Ctx::initia();
            ctx.adde(&self.clientis_alea);
            ctx.adde(&self.servitoris_alea);
            ctx.adde(&data[..params_mag]);
            let dig = ctx.fini();

            if rsa_verifica(&clavis_rsa, &data[sig_offset..sig_offset + sig_mag], &dig) < 0 {
                return -1;
            }
        }

        // 5. accipe ServerHelloDone
        let (genus, _mag) = match self.lege_nuntium_sal(&mut data) {
            Ok(v) => v,
            Err(_) => return -1,
        };
        if genus != SAL_SALVE_FACTUM {
            return -1;
        }

        // 6. genera clavis ECDHE clientis
        let mut privata_octis = [0u8; 32];
        alea_imple(&mut privata_octis);
        self.ec_privata = Nm::ex_octis(&privata_octis);

        // clavis publica clientis = ec_privata * G
        let mut publica_clientis = EcPunctum {
            x: Nm::ex_nihilo(),
            y: Nm::ex_nihilo(),
            infinitum: true,
        };
        let gen = ec_generator();
        ec_multiplica(&mut publica_clientis, &self.ec_privata, &gen);

        // 7. mitte ClientKeyExchange
        {
            let mut cke = [0u8; 70];
            cke[0] = SAL_CLAVIS_CLIENTIS;
            scr24(&mut cke[1..4], 66); // longitudo: 1 + 65
            cke[4] = 65; // longitudo puncti
            cke[5] = 0x04; // uncompressed
            let mut xbuf = [0u8; 32];
            let mut ybuf = [0u8; 32];
            publica_clientis.x.ad_octos(&mut xbuf);
            publica_clientis.y.ad_octos(&mut ybuf);
            cke[6..38].copy_from_slice(&xbuf);
            cke[38..70].copy_from_slice(&ybuf);

            self.transcribe(&cke);
            if self.mitte_tabellam(TABELLA_SALUTATIO, &cke) < 0 {
                return -1;
            }
        }

        // 8. computa secretum commune
        let mut punctum_commune = EcPunctum {
            x: Nm::ex_nihilo(),
            y: Nm::ex_nihilo(),
            infinitum: true,
        };
        let serv_pub = self.ec_publica_servitoris.clone();
        ec_multiplica(&mut punctum_commune, &self.ec_privata, &serv_pub);
        let mut praedominus = [0u8; 32];
        punctum_commune.x.ad_octos(&mut praedominus);

        // 9. computa secretum dominale
        let mut semen = [0u8; 64];
        semen[..32].copy_from_slice(&self.clientis_alea);
        semen[32..64].copy_from_slice(&self.servitoris_alea);
        prf(
            &praedominus,
            "master secret",
            &semen,
            &mut self.secretum_dom,
        );

        // 10. deriva claves
        let mut semen_exp = [0u8; 64];
        semen_exp[..32].copy_from_slice(&self.servitoris_alea);
        semen_exp[32..64].copy_from_slice(&self.clientis_alea);

        let mut materia = [0u8; 40]; // 16+16+4+4 = 40
        prf(
            &self.secretum_dom,
            "key expansion",
            &semen_exp,
            &mut materia,
        );

        self.clavis_scr_c.copy_from_slice(&materia[..16]);
        self.clavis_scr_s.copy_from_slice(&materia[16..32]);
        self.iv_c.copy_from_slice(&materia[32..36]);
        self.iv_s.copy_from_slice(&materia[36..40]);

        // 11. mitte ChangeCipherSpec
        {
            let ccs: [u8; 1] = [1];
            if self.mitte_tabellam(TABELLA_MUTATIO, &ccs) < 0 {
                return -1;
            }
            self.occultans = true;
        }

        // 12. mitte Finished (occultum)
        {
            // verify_data = PRF(master_secret, "client finished",
            //                   Hash(transcriptum))[0..11]
            let mut copia = self.transcriptum.clone();
            let digestum = copia.fini();

            let mut verify_data = [0u8; 12];
            prf(
                &self.secretum_dom,
                "client finished",
                &digestum,
                &mut verify_data,
            );

            let mut finitum = [0u8; 16];
            finitum[0] = SAL_FINITUM;
            scr24(&mut finitum[1..4], 12);
            finitum[4..16].copy_from_slice(&verify_data);

            // adde ad transcriptum ANTE occultationem
            self.transcribe(&finitum);

            // mitte occultum
            if self.mitte_tabellam_occultam(TABELLA_SALUTATIO, &finitum) < 0 {
                return -1;
            }
        }

        // 13. accipe ChangeCipherSpec servitoris
        {
            let mut alveus = [0u8; 16];
            let (gen_tab, _) = match self.lege_tabellam(&mut alveus) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            if gen_tab != TABELLA_MUTATIO {
                return -1;
            }
            self.revelans = true;
        }

        // 14. accipe Finished servitoris (occultum)
        {
            let mut alveus = [0u8; 256];
            let (gen_tab, alveus_mag) = match self.lege_tabellam_revelam(&mut alveus) {
                Ok(v) => v,
                Err(_) => return -1,
            };
            if gen_tab != TABELLA_SALUTATIO {
                return -1;
            }
            if alveus_mag < 16 {
                return -1;
            }
            if alveus[0] != SAL_FINITUM {
                return -1;
            }
            // verificamus verify_data servitoris
            let mut copia = self.transcriptum.clone();
            let digestum = copia.fini();

            let mut verify_expectatum = [0u8; 12];
            prf(
                &self.secretum_dom,
                "server finished",
                &digestum,
                &mut verify_expectatum,
            );

            if alveus[4..16] != verify_expectatum[..] {
                return -1;
            }
        }

        self.app_pos = 0;
        self.app_mag = 0;
        0
    }

    /* --- data applicationis --- */

    /// Scribe data applicata per velum TLS.
    /// Redit 0 si succedit, -1 si fallit.
    pub fn scribe(&mut self, data: &[u8]) -> i32 {
        let mut p: usize = 0;
        let mut restans = data.len();
        while restans > 0 {
            let n = if restans > 16384 { 16384 } else { restans };
            if self.mitte_tabellam_occultam(TABELLA_APPLICATIO, &data[p..p + n]) < 0 {
                return -1;
            }
            p += n;
            restans -= n;
        }
        0
    }

    /// Lege data applicata ex velo TLS.
    /// Redit numerum octorum lectorum, vel -1 si fallit.
    pub fn lege(&mut self, alveus: &mut [u8]) -> i32 {
        let mag = alveus.len();
        let mut lectum: usize = 0;

        while lectum < mag {
            // si habemus data in alveo applicationis, utere
            if self.app_pos < self.app_mag {
                let disponibilia = self.app_mag - self.app_pos;
                let mut n = mag - lectum;
                if n > disponibilia {
                    n = disponibilia;
                }
                alveus[lectum..lectum + n]
                    .copy_from_slice(&self.alveus_app[self.app_pos..self.app_pos + n]);
                self.app_pos += n;
                lectum += n;
                continue;
            }

            // lege novam tabellam
            let mut data_tab = vec![0u8; 16640];
            let (genus, data_mag) = match self.lege_tabellam_revelam(&mut data_tab) {
                Ok(v) => v,
                Err(_) => {
                    return if lectum > 0 { lectum as i32 } else { -1 };
                }
            };

            if genus != TABELLA_APPLICATIO {
                continue; // praetermitte non-applicationalia
            }

            self.alveus_app[..data_mag].copy_from_slice(&data_tab[..data_mag]);
            self.app_pos = 0;
            self.app_mag = data_mag;
        }
        lectum as i32
    }

    /// Claude velum: mitte close_notify et claude connexionem.
    pub fn claude(&mut self) {
        // mitte close_notify (optionalis)
        if self.occultans {
            let alerta: [u8; 2] = [1, 0]; // warning, close_notify
            let _ = self.mitte_tabellam_occultam(21, &alerta);
        }
    }
}
