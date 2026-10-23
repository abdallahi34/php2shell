# Vérifier et mettre à jour PHP

## 1. Lancer le contrôle

Décompressez le dépôt et ouvrez un terminal dans son dossier.
Python 3.10+ suffit ; rien à installer avec pip.

```bash
python3 check.py https://ton-site.com
```

Vous pouvez aussi lancer `python3 check.py` et saisir l’URL lorsqu’elle est demandée.
Utilisez l’URL finale du site affichée dans votre navigateur. Les redirections vers une
autre origine (www, autre domaine, passage HTTP → HTTPS) ne sont pas suivies automatiquement.
Sur Windows, utilisez `py -3` à la place de `python3`.

Si le site cache sa version, demandez-la à votre hébergeur puis lancez :

```bash
python3 check.py --php-version 8.4.27
```

Sur votre serveur, pour inspecter le binaire PHP local :

```bash
python3 check.py --local
# Si plusieurs versions sont installées :
python3 check.py --local --php-binary /usr/bin/php8.3
```

Attention : le PHP de la ligne de commande peut différer du PHP du site,
de ses pools FPM ou de ses conteneurs. Vérifiez le runtime web auprès de l’administrateur.

## 2. Comprendre le résultat

| Affichage | Ce qu’il faut faire |
|---|---|
| `VERIFICATION_EDITEUR_REQUISE` | Version sous le seuil amont : mettre à jour, sauf correctif rétroporté confirmé par le fournisseur |
| `BRANCHE_HORS_SUPPORT_AMONT` | Migrer vers une branche supportée ou obtenir la confirmation du correctif LTS |
| `CORRECTIF_AMONT_PRESENT` | Numéro atteignant le seuil : confirmer provenance du paquet, runtime web et redémarrage des workers |
| `INDETERMINE` | Version masquée, incomplète ou inconnue : demander les informations à l’hébergeur |
| `Erreur` | Vérifier URL, connexion, certificat et accès réseau ; aucune conclusion de sécurité |

**Ce contrôle ne prouve pas l’exploitabilité.** Il lit seulement les en-têtes HTTP
(HEAD, puis GET si nécessaire, sans lire le corps). Les en-têtes peuvent être faux ou
provenir d’un proxy. Un résultat inconnu ne veut pas dire que le site est sécurisé.
Aucun fichier ni formulaire n’est envoyé. Utilisez-le sur vos sites ou vos laboratoires autorisés.

Pour enregistrer un rapport :

```bash
python3 check.py https://ton-site.com --json --output rapport.json
```

Codes de sortie : `0` seuil amont atteint, `1` vérification/mise à jour requise,
`2` indéterminé, `3` erreur. Le code `0` n’est pas un certificat de sécurité.

## 3. Mettre à jour

Sauvegardez le site et sa configuration avant intervention. Choisissez la dernière
mise à jour de sécurité d’une branche supportée compatible avec votre application.
Les premiers correctifs amont des deux CVE initiales sont :

| Branche | Première version corrigée |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

- **Hébergement / cPanel / Plesk :** sélectionnez une version corrigée pour chaque domaine,
  ou demandez au support de confirmer les correctifs CVE-2026-109618 et CVE-2026-109619.
- **Ubuntu / Debian :** mettez à jour les paquets PHP réellement installés depuis votre
  fournisseur, puis redémarrez les services PHP-FPM et/ou Apache concernés.
- **Docker :** récupérez/reconstruisez une image corrigée puis recréez les conteneurs PHP.
  Un simple redémarrage de l’ancienne image ne la corrige pas.

Exemple Ubuntu/Debian **uniquement si votre site utilise PHP 8.3 FPM** :

```bash
sudo apt update
sudo apt install --only-upgrade php8.3-fpm php8.3-cli
sudo systemctl restart php8.3-fpm
```

Mettez également à jour les autres paquets PHP installés concernés. Pour mod_php,
mettez à jour son paquet puis redémarrez Apache. Les distributeurs peuvent conserver
un numéro ancien avec un correctif rétroporté : vérifiez la révision complète dans
[leur avis de sécurité, par exemple Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1).
Mettre à jour WordPress seul ne met pas à jour PHP.

## 4. Vérifier après mise à jour

Confirmez le paquet et le runtime web sur toutes les instances, le redémarrage des
workers, puis testez connexion, formulaires et uploads légitimes.

**Avis complémentaire du 23 octobre 2026 :** PHP recommande temporairement
`session.upload_progress.enabled=0` pour un cas supplémentaire lié aux sessions,
CVE-2026-115560. Appliquez-le dans la configuration effective du runtime web avant
traitement des requêtes, puis redémarrez les workers. Cela peut désactiver le suivi
de progression des uploads et ne remplace pas les mises à jour initiales.
Consultez [l’avis PHP actuel](https://www.php.net/) avant intervention.

Informations vérifiées le 23/10/2026. Les nouvelles branches et les préversions
restent indéterminées jusqu’à une revue des sources.
