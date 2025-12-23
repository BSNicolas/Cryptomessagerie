# CryptoMessagerie


## Nom

Cryptomessagerie


## Description

Code simulant une messagerie avec cryptographie post-quantique.


## Installation pour Windows

- Installer Anaconda : [anaconda.com](https://www.anaconda.com/download/success)
- Ouvrir le terminal Anaconda Prompt
- Créer un environnement dédié pour le projet en tapant ces commandes dans le terminal :
    - conda create -n pqc_project python=3.10
    - conda activate pqc_project
- Installer MSYS2 : [msys2.org](https://www.msys2.org/)
- Une fois installé, lancer le terminal "MSYS2 MINGW64" (attention à bien prendre le 64-bit)
- Mettre à jour et installer liboqs avec ces commandes dans le terminal :
    - pacman -Syu
    - pacman -S mingw-w64-x86_64-liboqs
- Retourner dans le Anaconda Prompt et taper cette commande :
    - pip install liboqs-python
- Pour coder avec Visual Studio Code :
    - Sélecteur d'interprète : Dans VS Code, appuyez sur Ctrl+Shift+P et tapez "Python: Select Interpreter"
    - Choisir le bon Python : Sélectionner celui de l'environnement Anaconda (pqc_project)
- Pour que Python accepte de charger la DLL de MSYS2, il faut lui donner le chemin explicitement dans le code. Le chemin dans lequel se trouve liboqs.dll ressemble à ça : `C:\msys64\mingw64\bin`


## Utilisation

- Lancer dans un terminal à la racine du projet le code bob : `python server_bob.py`
- Ouvrir un autre terminal et lancer à la racine du projet le code alice : `python client_alice.py`
- Alice et Bob peuvent désormais s'échanger des messages en toute sécurité
