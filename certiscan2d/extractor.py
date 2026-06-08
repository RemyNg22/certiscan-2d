import pymupdf
import cv2
from pathlib import Path
import numpy as np
import zxingcpp, pyzbar

class DataMatrixNotFoundError(Exception):
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


def extract_2d_code(img):
    pass

def extract_text(img):
    pass