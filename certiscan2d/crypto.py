from __future__ import annotations
import base64
import hashlib
import logging
import re
import threading
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, cast
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.extensions import SubjectKeyIdentifier
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)


# Exceptions
class CryptoError(Exception):
    """Erreur empêchant la vérification (AC inconnue, données manquantes...)."""
    pass


class AcInconnueError(CryptoError):
    """Aucun certificat trouvé pour l'autorité de certification indiquée."""
    pass


class SignatureInvalideError(CryptoError):
    """La signature ne correspond à aucune variante testée du payload."""
    pass


# Constantes & chemins
NS = {"tsl": "http://uri.etsi.org/02231/v2#"}
SVCSTATUS_INACCORD = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"
SVCSTATUS_GRANTED = "http://uri.etsi.org/TrstSvc/Svcstatus/granted"

CACHE_DIR = Path(__file__).parent.parent / "cache_2ddoc"
TSL_LOCAL = CACHE_DIR / "tsl_signed.xml"
TSL_URL = "https://pub.ants.gouv.fr/2D-DOC/V1/PRD/01_TSL/tsl_signed.xml"
LEAF_CACHE_DIR = CACHE_DIR / "leaf_certs"

GS = "\x1d"
US = "\x1f"


# Scan / parsing de certificats X.509
def _scan_der_certs(data: bytes) -> List[x509.Certificate]:
    """Balaye un flux binaire pour extraire des certificats DER (heuristique ASN.1)."""
    out: List[x509.Certificate] = []
    seen: Set[bytes] = set()
    i, n = 0, len(data)
    while i + 4 <= n:
        if data[i] != 0x30:
            i += 1
            continue
        lb = data[i + 1]
        if lb == 0x82 and i + 4 <= n:
            total = 4 + ((data[i + 2] << 8) | data[i + 3])
        elif lb == 0x81 and i + 3 <= n:
            total = 3 + data[i + 2]
        elif lb < 0x80:
            total = 2 + lb
        else:
            i += 1
            continue
        if total <= 0 or i + total > n:
            i += 1
            continue
        chunk = data[i:i + total]
        try:
            cert = x509.load_der_x509_certificate(chunk)
            fp = cert.fingerprint(hashes.SHA256())
            if fp not in seen:
                out.append(cert)
                seen.add(fp)
            i += total
        except Exception:
            i += 1
    return out


def _parse_certs(data: bytes) -> List[x509.Certificate]:
    """Parse un flux pouvant être du PEM, du DER unique, ou un flux DER mixte."""
    pem_re = re.compile(
        rb"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
        re.DOTALL,
    )
    found = []
    for block in pem_re.findall(data):
        try:
            found.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
    if found:
        return found
    try:
        return [x509.load_der_x509_certificate(data)]
    except Exception:
        pass
    return _scan_der_certs(data)


def _derive_cert_ids(cert: x509.Certificate) -> List[str]:
    """Génère les cert_id candidats (4 chars alphanumériques) pour un X.509."""
    ids: Set[str] = set()

    serial_hex = f"{cert.serial_number:X}"
    for n in (4, 5, 6, 8):
        if len(serial_hex) >= n:
            ids.add(serial_hex[-n:].upper())

    try:
        ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski = cast(SubjectKeyIdentifier, ski_ext.value).digest.hex().upper()
        for n in (4, 5, 6, 8):
            if len(ski) >= n:
                ids.add(ski[-n:])
    except x509.ExtensionNotFound:
        pass

    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_sha1 = hashlib.sha1(spki_der).hexdigest().upper()
    for n in (4, 6, 8):
        ids.add(spki_sha1[:n])

    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        for m in re.finditer(r"\b[A-Z0-9]{4}\b", str(cn).upper()):
            ids.add(m.group(0))
    except Exception:
        pass

    return list(ids)


# Réseau
def _fetch_bytes(url: str, timeout: int = 10) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "certiscan2d/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        logger.warning(f"Échec du téléchargement de {url} : {e}")
        return None


def _extract_ca_id(tsp: ET.Element) -> Optional[str]:
    for n in tsp.findall(".//tsl:TSPTradeName/tsl:Name", NS):
        tn = (n.text or "").strip()
        if re.fullmatch(r"FR\d{2}", tn):
            return tn
    for n in tsp.findall(".//tsl:TSPName/tsl:Name", NS):
        m = re.search(r"(FR\d{2})", n.text or "")
        if m:
            return m.group(1)
    return None


def download_missing_leaf_certs(force_refresh: bool = False, timeout: int = 10) -> int:
    """
    Télécharge les certificats feuilles référencés dans la TSL vers le cache local.
    À exécuter en tâche de fond (cron, script de maintenance) — jamais dans une
    requête Flask, car ça fait des appels réseau bloquants.

    Retourne le nombre de certificats téléchargés.
    """
    if not TSL_LOCAL.exists():
        logger.error("TSL locale absente — impossible de télécharger les feuilles.")
        return 0

    LEAF_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    root = ET.fromstring(TSL_LOCAL.read_bytes())
    count = 0

    for tsp in root.findall(".//tsl:TrustServiceProvider", NS):
        ca_id = _extract_ca_id(tsp)
        if not ca_id:
            continue

        for u in tsp.findall(".//tsl:TSPInformationURI/tsl:URI", NS):
            url = (u.text or "").strip()
            if not url.startswith("http"):
                continue

            url_hash = hashlib.md5(url.encode()).hexdigest()
            cache_file = LEAF_CACHE_DIR / f"{ca_id}_{url_hash}.der"

            if cache_file.exists() and not force_refresh:
                continue

            logger.info(f"Téléchargement certificat feuille {ca_id} : {url}")
            data = _fetch_bytes(url, timeout=timeout)
            if data:
                cache_file.write_bytes(data)
                count += 1

    return count


# Construction de l'index de clés
def _build_index(tsl_bytes: bytes) -> Tuple[
    Dict[Tuple[str, str], x509.Certificate],
    Dict[str, List[x509.Certificate]],
]:
    """
    Construit {(ca_id, cert_id): cert} depuis la TSL locale + cache de
    certificats feuilles. Aucun appel réseau ici (lecture disque uniquement).
    """
    root = ET.fromstring(tsl_bytes)
    index: Dict[Tuple[str, str], x509.Certificate] = {}
    per_ca: Dict[str, List[x509.Certificate]] = {}

    for tsp in root.findall(".//tsl:TrustServiceProvider", NS):
        ca_id = _extract_ca_id(tsp)
        if not ca_id:
            continue

        for svc in tsp.findall(".//tsl:TSPService", NS):
            status = (svc.findtext(".//tsl:ServiceStatus", default="", namespaces=NS) or "").strip()
            if status not in (SVCSTATUS_INACCORD, SVCSTATUS_GRANTED):
                continue
            for elem in svc.findall(".//tsl:ServiceDigitalIdentity//tsl:X509Certificate", NS):
                b64 = (elem.text or "").strip()
                if not b64:
                    continue
                try:
                    der = base64.b64decode(b64, validate=True)
                    cert = x509.load_der_x509_certificate(der)
                    per_ca.setdefault(ca_id, []).append(cert)
                    for cid in _derive_cert_ids(cert):
                        index[(ca_id, cid)] = cert
                except Exception:
                    pass

    if LEAF_CACHE_DIR.exists():
        for cache_file in LEAF_CACHE_DIR.glob("*.der"):
            ca_id = cache_file.stem.split("_")[0]
            try:
                for cert in _parse_certs(cache_file.read_bytes()):
                    per_ca.setdefault(ca_id, []).append(cert)
                    for cid in _derive_cert_ids(cert):
                        index[(ca_id, cid)] = cert
            except Exception as e:
                logger.warning(f"Certificat en cache illisible {cache_file} : {e}")

    return index, per_ca


# Singleton thread-safe
_lock = threading.Lock()
_KEY_INDEX: Optional[Dict[Tuple[str, str], x509.Certificate]] = None
_PER_CA_INDEX: Optional[Dict[str, List[x509.Certificate]]] = None


def get_key_indexes() -> Tuple[
    Dict[Tuple[str, str], x509.Certificate],
    Dict[str, List[x509.Certificate]],
]:
    """
    Retourne (index_exact, index_par_ca). Construit l'index une seule fois
    par worker et le garde en mémoire (coût : quelques centaines de Ko).
    """
    global _KEY_INDEX, _PER_CA_INDEX
    if _KEY_INDEX is not None and _PER_CA_INDEX is not None:
        return _KEY_INDEX, _PER_CA_INDEX

    with _lock:
        if _KEY_INDEX is not None and _PER_CA_INDEX is not None:
            return _KEY_INDEX, _PER_CA_INDEX

        if TSL_LOCAL.exists():
            logger.info(f"Chargement TSL locale : {TSL_LOCAL}")
            tsl_bytes = TSL_LOCAL.read_bytes()
        else:
            logger.warning("TSL locale absente — téléchargement d'urgence")
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            tsl_bytes = _fetch_bytes(TSL_URL)
            if not tsl_bytes:
                raise CryptoError("TSL introuvable (ni locale, ni réseau)")
            TSL_LOCAL.write_bytes(tsl_bytes)

        _KEY_INDEX, _PER_CA_INDEX = _build_index(tsl_bytes)
        logger.info(
            f"Index TSL prêt : {len(_KEY_INDEX)} cert_id exacts, "
            f"{sum(len(v) for v in _PER_CA_INDEX.values())} certificats au total"
        )
        return _KEY_INDEX, _PER_CA_INDEX


def reset_key_indexes() -> None:
    """Force le rechargement de l'index au prochain appel (tests, rafraîchissement)."""
    global _KEY_INDEX, _PER_CA_INDEX
    with _lock:
        _KEY_INDEX = None
        _PER_CA_INDEX = None


# Décodage de la signature
def _decode_signature_base32(sig_brute: str) -> bytes:
    """
    Décode la signature Base32 utilisée par le 2D-Doc à partir de la version '02'. Le padding n'est jamais inclus dans
    le Data Matrix — on le complète avant décodage.
    """
    sig = sig_brute.strip().upper()
    sig = re.sub(r"[^A-Z2-7]", "", sig)  # purge séparateurs résiduels

    rem = len(sig) % 8
    if rem:
        sig += "=" * (8 - rem)

    try:
        return base64.b32decode(sig)
    except Exception as e:
        raise CryptoError(f"Décodage Base32 échoué : {e}")


# Vérification bas niveau ECDSA / RSA
def _verify_ecdsa(pub_key: ec.EllipticCurvePublicKey, payload: bytes, sig: bytes) -> bool:
    curve = pub_key.curve
    if isinstance(curve, ec.SECP256R1):
        digest = hashes.SHA256()
    elif isinstance(curve, ec.SECP384R1):
        digest = hashes.SHA384()
    elif isinstance(curve, ec.SECP521R1):
        digest = hashes.SHA512()
    else:
        digest = hashes.SHA256()

    if len(sig) % 2 != 0:
        return False

    half = len(sig) // 2
    r = int.from_bytes(sig[:half], "big")
    s = int.from_bytes(sig[half:], "big")

    try:
        der_sig = encode_dss_signature(r, s)
        pub_key.verify(der_sig, payload, ec.ECDSA(digest))
        return True
    except (InvalidSignature, ValueError):
        return False


def _verify_rsa(pub_key: rsa.RSAPublicKey, payload: bytes, sig: bytes) -> bool:
    for digest in (hashes.SHA256(), hashes.SHA384(), hashes.SHA512()):
        try:
            pub_key.verify(sig, payload, padding.PKCS1v15(), digest)
            return True
        except InvalidSignature:
            continue
    return False



def _verify_with_key(public_key, payload: bytes, sig_bytes: bytes) -> bool:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return _verify_ecdsa(public_key, payload, sig_bytes)
    if isinstance(public_key, rsa.RSAPublicKey):
        return _verify_rsa(public_key, payload, sig_bytes)
    return False


# Construction des variantes de payload
def _payload_variants(payload_brut: str) -> List[bytes]:
    """
    Génère les variantes plausibles du payload signé à partir de la chaîne
    'data_part' produite par parse_2ddoc.

    La spec dit : "intégrité de la zone de données (en-tête + message) après
    compression et troncature, avant encodage C40". Comme nous recevons déjà
    le texte décodé du C40 (pas les octets pré-C40), on ne peut pas
    reconstruire exactement le flux d'origine — on teste donc les variantes
    structurelles les plus probables
    """
    variants: List[bytes] = []
    seen: Set[bytes] = set()

    candidats_str = {
        "complet": payload_brut,
        "sans_gs_final": payload_brut.rstrip("\x1d"),
        "sans_gs_initial": payload_brut.lstrip("\x1d"),
    }

    for s in candidats_str.values():
        for encoding in ("latin-1", "utf-8"):
            try:
                b = s.encode(encoding)
            except UnicodeEncodeError:
                continue
            if b not in seen:
                variants.append(b)
                seen.add(b)

    return variants


# Point d'entrée principal
def verify_2ddoc_signature(doc_fields) -> bool:
    """
    Vérifie la signature d'un 2D-Doc parsé contre la TSL ANTS.
    Test plusieurs variantes de reconstruction du payload (voir
    _payload_variants) contre toutes les clés candidates pour l'AC indiquée
    (cert_id exact en priorité, puis tous les certs connus de cette AC).
    """
    if not doc_fields.signature_brute:
        raise CryptoError("Champ signature_brute absent")
    if not doc_fields.payload_brut:
        raise CryptoError("Champ payload_brut absent")

    sig_bytes = _decode_signature_base32(doc_fields.signature_brute)
    payload_variants = _payload_variants(doc_fields.payload_brut)

    key_index, per_ca_index = get_key_indexes()
    ca_id = doc_fields.ca_id.upper()
    cert_id = (doc_fields.certif_id or "").upper()

    candidate_certs: List[x509.Certificate] = []
    exact = key_index.get((ca_id, cert_id))
    if exact is not None:
        candidate_certs.append(exact)
    for cert in per_ca_index.get(ca_id, []):
        if cert not in candidate_certs:
            candidate_certs.append(cert)

    if not candidate_certs:
        raise AcInconnueError(
            f"Aucun certificat trouvé pour l'AC={ca_id}. "
            f"Vérifiez que la TSL locale est à jour et que les certificats "
            f"feuilles ont été téléchargés (download_missing_leaf_certs)."
        )

    for cert in candidate_certs:
        public_key = cert.public_key()
        for payload in payload_variants:
            try:
                if _verify_with_key(public_key, payload, sig_bytes):
                    logger.info(
                        f"Signature VALIDE — CA={ca_id} cert_id={cert_id} "
                        f"(payload {len(payload)} octets)"
                    )
                    return True
            except Exception:
                continue

    raise SignatureInvalideError(
        f"Signature invalide pour CA={ca_id} cert_id={cert_id} "
        f"({len(candidate_certs)} certificat(s) testé(s), "
        f"{len(payload_variants)} variante(s) de payload testée(s))"
    )