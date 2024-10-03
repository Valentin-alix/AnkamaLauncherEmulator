## Ankama Launcher Emulator

Pour générer du code a partir de zaap.thrift :
`thrift --gen py resources/zaap.thrift && mv gen-py src/gen_zaap`

Pour lancer un compte aller dans src/server.py, modifiez le login et lancer src/server.py :
`python src/server.py`
