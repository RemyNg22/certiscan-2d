import pymupdf
import cv2
from pathlib import Path
import numpy as np
import zxingcpp
import pytesseract

# création des différentes exceptions possibles
class ExtractionError(Exception):
    pass

class InvalidImageError(ExtractionError):
    pass

class DataMatrixNotFoundError(ExtractionError):
    pass

class MultipleDataMatrixFoundError(ExtractionError):
    pass


def normalisation_document(file_path : Path):
    file_path = Path(file_path)

    if file_path.suffix.lower() == ".pdf":
        document = pymupdf.open(file_path)
        pages = []

        for page in document:
            pix = page.get_pixmap(dpi=300) # pdf vers pixels bitmap 300 DPI
            img = np.frombuffer(pix.samples, dtype=np.uint8) #conversion vers array NumPy
            img = img.reshape(pix.height, pix.width, pix.n) # reconstruction matrice image (longueurxlargeur x channels)
           
            # conversion couleur sécurisée pour OpenCV
            if pix.n == 4:
                img = cv2.cvtColor(img, cv2.COLOR_RGBA2BGR)
            elif pix.n == 3:
                img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
            elif pix.n == 1:
                img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)

            pages.append(img)

        document.close()
        return pages
    
    else:
        img = cv2.imread(str(file_path))

        if img is None:
            raise ValueError("Format invalide ou fichier illisible")

        return [img]
    

def traitement_image(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) #convertir en niveau de gris
    _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU) # binarisation auto pour renforcer le contraste entre texte/2d code et arrière plan

    return {"gray": gray,
            "binary" : binary}


def extract_2d_code(gray : np.ndarray, binary: np.ndarray):
    """
    Extraction des 2D codes détectés dans une image, lève une exception 
    si soucis de lecture d'image, si erreur zxing, si pas de 2D code ou si 
    plus d'un 2D code sur le document
    """

    if gray is None or binary is None:
        raise InvalidImageError("Image invalide (None)")
    
    def decode(img):
        results = []
        try:
            decoded = zxingcpp.read_barcodes(img) #on essaie de trouver les qrcodes
            for r in decoded:
                if r.text:
                    results.append(r.text.strip())
        except Exception as exc:
            raise RuntimeError(f"Erreur ZXing {exc}") from exc
        return results
    
    codes = decode(binary) #on teste d'abord la fonction avec binary et si rien, avec gray

    if not codes:
        codes = decode(gray)

    unique_codes = list(set(codes))

    if len(unique_codes) == 0:
        raise DataMatrixNotFoundError("Aucun code 2D détecté")

    if len(unique_codes) > 1:
        raise MultipleDataMatrixFoundError(f"Plusieurs codes détectés : {unique_codes}")
    
    return unique_codes[0]


def extract_text(gray : np.ndarray, binary: np.ndarray):
    """
    Extraction du texte d'une image à l'aide de pytesseract 
    dans un format avec plusieurs langues européenne
    """
    if gray is None or binary is None:
        raise InvalidImageError("Image invalide (None)")
    
    langues = "fra+eng+deu+spa+ita"

    custom_config = f"--psm 3" # segmentation auto des pages

    try:
        decode_str = pytesseract.image_to_string(gray, lang=langues, config=custom_config)

        if not decode_str.strip():
            decode_str = pytesseract.image_to_string(binary, lang=langues, config=custom_config)

        return decode_str.strip()
    
    except pytesseract.TesseractError as e:
        raise RuntimeError(f"Erreur d'extraction Tesseract. Les packs de la langue du document n'est peut-être pas installé : {e}") from e
    except Exception as exc:
        raise RuntimeError(f"Erreur inattendue lors de l'OCR : {exc}") from exc

def extract_page(img):
    """
    Prendre une image et retourner les données brutes extraites
    """
    if img is None:
        raise InvalidImageError("Image de page invalide")
    
    image_traitee = traitement_image(img)

    gray = image_traitee["gray"]
    binary = image_traitee["binary"]

    code_2d = extract_2d_code(gray, binary)
    text = extract_text(gray, binary)

    return {
        "code_2d": code_2d,
        "text": text
    }


def extract_document():
    pass