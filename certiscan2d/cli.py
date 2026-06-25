from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from certiscan2d.orchestrateur import verifier_document


def configurer_arguments() -> argparse.ArgumentParser:
    """Configure l'analyseur d'arguments natif de la ligne de commande."""
    parser = argparse.ArgumentParser(
        prog="certiscan",
        description="CertiScan 2D - Solution locale d'audit de sécurité et de conformité des documents (2D-Doc).",
        epilog="Exemple : certiscan ~/Documents/facture_edf.pdf")

    # Argument principal (Le fichier à analyser)
    parser.add_argument(
        "fichier",
        type=str,
        help="Chemin d'accès (absolu ou relatif) vers le document local (PDF, PNG, JPG).")

    # Options d'affichage des résultats
    group_format = parser.add_mutually_exclusive_group()
    group_format.add_argument(
        "--json",
        action="store_true",
        help="Affiche le rapport complet sous forme de données JSON brutes.")
    
    group_format.add_argument(
        "--court",
        action="store_true",
        help="Affiche uniquement une ligne avec la typologie et le verdict.")

    return parser


def afficher_rapport_console(rapport) -> None:
    """Affiche le résultat de l'analyse avec un formatage professionnel en couleur."""
    # Codes couleur ANSI universels pour terminaux
    c_vert = "\033[92m"
    c_rouge = "\033[91m"
    c_jaune = "\033[93m"
    c_reset = "\033[0m"

    # Assignation de la couleur selon la gravité du statut
    couleur = c_jaune
    if rapport.statut == "VALID":
        couleur = c_vert
    elif rapport.statut in ["INVALID", "CRYPTO_FAIL", "SUSPICIOUS"]:
        couleur = c_rouge

    # Formatage de la date en heure locale française
    maintenant = datetime.now(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y à %H:%M:%S")

    print("=" * 65)
    print(f"RAPPORT D'ANALYSE LOCAL : {rapport.nom_fichier_origine}")
    print("=" * 65)
    print(f"Exécuté le : {maintenant}")
    print(f"Type de document : {rapport.type_document_libelle}")
    print(f"Verdict du contrôle : {couleur}{rapport.statut_libelle} [{rapport.statut}]{c_reset}")
    print(f"Synthèse : {rapport.message_principal}")
    print("-" * 65)
    
    print("DÉTAIL DU PIPELINE DE CONTRÔLE :")
    for etape in rapport.etapes:
        icone = "  "
        if etape.statut == "ok":
            icone = f"{c_vert}[✓]{c_reset}"
        elif etape.statut == "echec":
            icone = f"{c_rouge}[✗]{c_reset}"
        else:
            icone = f"{c_jaune}[-]{c_reset}"
            
        duree = f"({etape.duree_ms} ms)" if etape.duree_ms is not None else ""
        print(f" {icone} {etape.nom:<30} : {etape.message} {duree}")
        
    print("-" * 65)
    if rapport.champs_verifies:
        print("COMPARAISON ET CONCORDANCE DES DONNÉES CROISÉES :")
        for champ, donnees in rapport.champs_verifies.items():
            valeur_attendue = donnees.get("attendu", "N/A")
            statut_champ = donnees.get("statut", "")

            # Alignement direct sur les statuts de verifier.py : MATCH, MISSING, CONTRADICTION
            if statut_champ == "MATCH":
                symbole_champ = f"{c_vert}[OK]{c_reset}"
                details_concordance = f"-> {valeur_attendue} (Confirmé à la surface)"
            elif statut_champ == "CONTRADICTION":
                symbole_champ = f"{c_rouge}[FRAUDE]{c_reset}"
                details_concordance = f"-> {valeur_attendue} (Une valeur différente a été lue sur le document !)"
            elif statut_champ == "MISSING":
                symbole_champ = f"{c_jaune}[PARTIEL]{c_reset}"
                details_concordance = f"-> {valeur_attendue} (Absent du texte imprimé ou scan illisible)"
            else:
                symbole_champ = f"{c_jaune}[-]{c_reset}"
                details_concordance = f"-> {valeur_attendue}"

            print(f"  • {symbole_champ:<19} {champ:<23} : {details_concordance}")
    else:
        print("Aucune donnée scellée n'a pu être extraite (analyse interrompue).")
    print("=" * 65)


def main() -> None:
    """Point d'entrée de l'exécutable local."""
    parser = configurer_arguments()
    args = parser.parse_args()

    # Résolution automatique du chemin d'accès
    target_path = Path(args.fichier).expanduser().resolve()
    
    if not target_path.is_file():
        print(f"Erreur : Le fichier spécifié est introuvable ou invalide : {target_path}", file=sys.stderr)
        sys.exit(1)

    try:
        # L'orchestrateur traite le fichier depuis son emplacement temporaire/local, sans aucune persistance
        rapport = verifier_document(str(target_path), target_path.name)
    except Exception as e:
        print(f"Incident critique lors de l'analyse : {str(e)}", file=sys.stderr)
        sys.exit(2)

    # Routage de l'affichage selon les flags optionnels
    if args.json:
        print(json.dumps(rapport.to_dict(), ensure_ascii=False, indent=4))
    elif args.court:
        print(f"{rapport.type_document_libelle} | Verdict: {rapport.statut}")
    else:
        afficher_rapport_console(rapport)

    # Codes de retour système standardisés
    if rapport.statut == "VALID":
        sys.exit(0)
    elif rapport.statut in ["INVALID", "CRYPTO_FAIL", "SUSPICIOUS"]:
        sys.exit(1)
    else:
        sys.exit(3)


if __name__ == "__main__":
    main()