## Ankama Launcher Emulator

Pour générer du code a partir de zaap.thrift :
`thrift --gen py resources/zaap.thrift && mv gen-py src/gen_zaap`

Pour lancer un compte aller dans src/server/server.py, modifiez le login et lancer le script :
`python src/server/server.py`

### Installer le package

`pip install git+https://github.com/Valentin-alix/AnkamaLauncherEmulator`
