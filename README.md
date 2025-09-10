# Ankama Launcher Emulator

## Code Generation

To generate code from `zaap.thrift`:
```bash
thrift --gen py resources/zaap.thrift && mv gen-py src/gen_zaap
```

## Running an Account

Go to `src/server/server.py`, modify the login, then run:
```bash
python src/server/server.py
```

## Installation

Install the package:
```bash
poetry add git+https://github.com/Valentin-alix/AnkamaLauncherEmulator
```

## Debugging

Extract the `app.asar` file:
```bash
asar extract "C://Program Files//Ankama//Ankama Launcher//resources//app.asar" "D:/Ankama Games/AnkamaLauncher/AnkaLauncherExtracted"
```
