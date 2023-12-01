## Installation 

### paquets systeme

``` bash
sudo apt-get install libldap2-dev libsasl2-dev
```

### paquets python

``` bash
pip3 install sphinx --user
pip3 install sphinx_rtd_theme --user
pip3 install sphinx-argparse --user
pip3 install git+https://github.com/christophe-marteau/python-cilogger#egg=cilogger --user
pip3 install python-ldap  --user

```

### vscode

#### Pré-requis
``` bash
pip3 install esbonio --user
pip3 install rstcheck --user
```

#### Plugins vscode
``` 
ext install lextudio.restructuredtext
ext install trond-snekvik.simple-rst
```

## Création de la configuration sphinx

``` bash
git clone ssh://xxx@yyy/hpcManager.git python-hpcManager
cd python-hpcManager/doc
sphinx-quickstart
```

>```
>[...]
>Chemin racine sélectionné : .
>[...]
>> Séparer les répertoires source et de sortie (y/n) [n]: y
>[...]
>> Nom du projet: hpcManager
>> Nom(s) de(s) l'auteur(s): Christophe Marteau
>> Version du projet []: 0.1
>[...]
>> Langue du projet [en]:
>[...] 
>Terminé : la structure initiale a été créée.
>[...]
>```

## Génération de la documentation

``` bash
cd python-hpcManager/doc
make html
```

### Visualisation de la documentation

``` bash
cd python-hpcManager/doc/build/html
python3 -m http.server
firefox http://localhost:8000
```