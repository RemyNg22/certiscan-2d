import pymupdf
import cv2
from pathlib import Path
import numpy as np
import zxingcpp
import pytesseract
import logging
import platform


# pour test windows sinon pytesseract dans serveur nginx
if platform.system() == "Windows":
    pytesseract.pytesseract.tesseract_cmd = (r"C:\Program Files\Tesseract-OCR\tesseract.exe")


logger = logging.getLogger(__name__)


# constantes
EXTENSIONS_IMAGE = {".jpg", ".jpeg", ".png", ".tiff", ".bmp"}
MAX_FILE_SIZE_MB = 20
OCR_LANG_PRIMARY = "fra"
OCR_LANG_EXTENDED = "fra+eng+deu+spa+ita"
OCR_CONFIG = "--psm 6"

# création des différentes exceptions possibles
class ExtractionError(Exception): pass
class InvalidImageError(ExtractionError): pass
class DataMatrixNotFoundError(ExtractionError): pass
class MultipleDataMatrixFoundError(ExtractionError): pass


def normalisation_document(file_path: Path):
    file_path = Path(file_path)

    if not file_path.exists():
        raise ExtractionError(f"Fichier introuvable: {file_path}")

    # vérification de la taille du fichier (Sécurité serveur Flask)
    if file_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise ExtractionError("Fichier trop volumineux")

    # gestion des pdf
    if file_path.suffix.lower() == ".pdf":
        doc = pymupdf.open(file_path)
        pages = []

        for i, page in enumerate(doc):
            pix = page.get_pixmap(dpi=350)  # pdf vers pixels bitmap 350 DPI
            
            #conversion vers array NumPy et reconstruction matrice image (longueurxlargeur x channels)
            img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)

            #conversion couleur sécurisée pour OpenCV
            if pix.n == 4:
                img = cv2.cvtColor(img, cv2.COLOR_RGBA2BGR)
            elif pix.n == 3:
                img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
            else:
                img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
            pages.append(img)
            logger.debug(f"Page {i+1} rasterisée")

        doc.close()
        return pages

    # Vérification des extensions valides
    if file_path.suffix.lower() in EXTENSIONS_IMAGE:
        img = cv2.imread(str(file_path))
        if img is None:
            raise InvalidImageError("Image illisible")
        return [img]

    raise InvalidImageError("Extension non supportée")



def traitement_image(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) #convertir en niveau de gris

    # augmentation contraste locale
    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
    gray = clahe.apply(gray)

    # réduction bruit
    blur = cv2.GaussianBlur(gray, (3, 3), 0)

    binary = cv2.adaptiveThreshold(
        blur,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        2)

    return gray, binary



def extract_text(gray: np.ndarray, binary: np.ndarray):
    """
    Extraction du texte d'une image à l'aide de pytesseract 
    dans un format avec plusieurs langues principales. Fallback en binaire 
    si rien n'est détecté
    """
    txt = pytesseract.image_to_string(gray, lang=OCR_LANG_PRIMARY, config=OCR_CONFIG)

    if not txt.strip():
        txt = pytesseract.image_to_string(
            binary,
            lang=OCR_LANG_EXTENDED,
            config=OCR_CONFIG)

    return txt.strip()



def extract_2d_code(gray: np.ndarray, binary: np.ndarray, original: np.ndarray = None):
    """
    Extraction des 2D codes détectés dans une image, principalement le document original.
    Test fait sur plusieurs représentation de l'image, plusieurs fallback si besoin
    """
    def try_decode(img):
        try:
            decoded = zxingcpp.read_barcodes(img)
            return [r.text.strip() for r in decoded if r.text]
        except Exception:
            return []

    def enhance(img):
        # upscale
        up = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)

        # contraste fort
        clahe = cv2.createCLAHE(3.0, (8, 8))
        gray_img = cv2.cvtColor(up, cv2.COLOR_BGR2GRAY)
        gray_img = clahe.apply(gray_img)

        # sharpen (important sur jepg flou)
        kernel = np.array([[0,-1,0],
                           [-1,5,-1],
                           [0,-1,0]])
        sharp = cv2.filter2D(gray_img, -1, kernel)
        return sharp

    def binarize(img):
        return cv2.adaptiveThreshold(
            img,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,
            2)

    candidates = []

    # base
    candidates.append(binary)
    candidates.append(gray)

    # enhanced
    candidates.append(enhance(original if original is not None else cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)))

    # binarisation
    candidates.append(binarize(gray))

    # fallback rotation
    def rotations(img):
        return [
            img,
            cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE),
            cv2.rotate(img, cv2.ROTATE_180),
            cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)]

    all_codes = []

    for c in candidates:
        for r in rotations(c):
            codes = try_decode(r)
            if codes:
                all_codes.extend(codes)

    # dedup
    unique = list(set(all_codes))

    if not unique:
        return None

    return unique[0]


def detect_input_type(img):
    """
    Classe l'image pour adaper les traitements (surtout pour photo avec téléphone ou screenshot
    par exemple, recherche le flou, ratio, résolution)
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = img.shape[:2]
    blur = cv2.Laplacian(gray, cv2.CV_64F).var()

    # screenshot = image propre + ratio typique écran
    aspect = w / h

    if blur > 200 and 0.4 < aspect < 0.7:
        return "screenshot"

    if blur < 80 or h < 1200 or w < 900:
        return "mobile"

    return "document"


def normalize_mobile_image(img):
    """
    Nettoyage spécifique smartphone :
    - contraste fort
    - réduction bruit capteur / compression JPEG
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # correction contraste agressive
    clahe = cv2.createCLAHE(clipLimit=3.5, tileGridSize=(8,8))
    gray = clahe.apply(gray)

    # réduction bruit type JPEG / capteur
    gray = cv2.bilateralFilter(gray, 7, 50, 50)

    return gray


def auto_deskew(img):
    """
    Correction de perspective si document incliné grâce à la détection des contours, 
    calcul du rectangle minimal englobant, transformation perspective
    """
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    edges = cv2.Canny(gray, 50, 150)

    pts = np.column_stack(np.where(edges > 0))

    if len(pts) < 200:
        return img

    rect = cv2.minAreaRect(pts)
    box = cv2.boxPoints(rect)
    box = np.float32(box)

    w = int(rect[1][0])
    h = int(rect[1][1])

    if w == 0 or h == 0:
        return img

    dst = np.array([[0,0],[w,0],[w,h],[0,h]], dtype=np.float32)

    M = cv2.getPerspectiveTransform(box, dst)

    return cv2.warpPerspective(img, M, (w, h))


def detect_mobile_rois(img):
    """
    Découpe de l'image pour trouver les zones utiles.
    """
    h, w = img.shape[:2]

    scales = [
        (0, 1, 0, 1),# full
        (0.3, 1, 0, 1), # bottom half
        (0.2, 0.8, 0.2, 0.8), # center crop
        (0, 0.6, 0, 1)] # top region (rare fallback)

    rois = []

    for y1, y2, x1, x2 in scales:
        roi = img[
            int(h*y1):int(h*y2),
            int(w*x1):int(w*x2)]
        
        rois.append(roi)

    return rois


def generate_variants(img):
    """
    Génère plusieurs versions de l’image pour améliorer la détection de code.
    """
    variants = []

    gray = normalize_mobile_image(img)

    variants.append(gray)

    # upscale
    variants.append(cv2.resize(gray, None, fx=2, fy=2))

    # sharpen
    kernel = np.array([[0,-1,0],
                       [-1,5,-1],
                       [0,-1,0]])

    variants.append(cv2.filter2D(gray, -1, kernel))

    # threshold adaptatif
    variants.append(cv2.adaptiveThreshold(
        gray, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31, 2))

    return variants


def extract_2d_mobile(img):
    """
    Pipeline DataMatrix mobile
    """
    img = auto_deskew(img)
    rois = detect_mobile_rois(img)
    all_codes = []

    for roi in rois:

        variants = generate_variants(roi)

        for v in variants:

            # rotations smartphone
            for r in [v,
                cv2.rotate(v, cv2.ROTATE_90_CLOCKWISE),
                cv2.rotate(v, cv2.ROTATE_180),
                cv2.rotate(v, cv2.ROTATE_90_COUNTERCLOCKWISE)
            ]:

                try:
                    results = zxingcpp.read_barcodes(r)

                    for res in results:
                        if res.text:
                            all_codes.append(res.text.strip())

                except:
                    continue

    if not all_codes:
        return None

    from collections import Counter
    return Counter(all_codes).most_common(1)[0][0]


def extract_2d_router(img, gray, binary):
    """
    Choisit la stratégie de lecture de code selon le type d’image.
    """
    mode = detect_input_type(img)

    if mode == "mobile":
        return extract_2d_mobile(img)

    if mode == "screenshot":
        up = cv2.resize(img, None, fx=2, fy=2)

        codes = zxingcpp.read_barcodes(up)
        codes = [c.text for c in codes if c.text]

        return codes[0] if codes else None

    return extract_2d_code(gray, binary, original=img)


def extract_page(img):
    """
    Prendre une image et retourner les données brutes extraites 
    (ocr texte, extraction code et statut de validation)
    """
    if img is None:
        raise InvalidImageError("Image None")

    gray, binary = traitement_image(img)

    text = extract_text(gray, binary)

    try:
        code = extract_2d_router(img, gray, binary)
        if code is None:
            error = "missing_code"
        else:
            error = "ok"

    except DataMatrixNotFoundError:
        code = None
        error = "missing_code"
    except MultipleDataMatrixFoundError:
        code = None
        error = "multiple_codes"

    return {
        "code_2d": code,
        "text": text,
        "page_error": error}



def extract_document(file_path):
    """
    Extraction complète du document (même si plusieurs pages) :
    conversion pdf/images, traitement par page, consolidation des codes
    """
    pages = normalisation_document(file_path)
    results = []
    all_codes = []

    for i, page in enumerate(pages, 1):

        data = extract_page(page)

        results.append({
            "page": i,
            **data
        })

        if data["code_2d"]:
            if data["code_2d"] not in all_codes:
                all_codes.append(data["code_2d"])


    # aucun code du tout => ok mais document incomplet
    if not all_codes:
        return {
            "pages": results,
            "document_validation": {
                "unique_codes": [],
                "status": "no_2d_code_found"
            }
        }

    # 1 code global => cas standard fiscal
    if len(all_codes) == 1:
        return {
            "pages": results,
            "document_validation": {
                "unique_codes": all_codes,
                "status": "single_code_ok"
            }
        }

    # plusieurs codes différents => on les accepte tous mais on signale l’anomalie sans exception
    return {
        "pages": results,
        "document_validation": {
            "unique_codes": all_codes,
            "status": "multiple_codes_detected_but_accepted"
        }
    }