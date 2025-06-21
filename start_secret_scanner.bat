@echo off
cd /d "%~dp0"
git checkout add_context
git fetch --all
git pull
if not exist venv\ (
python -m venv venv
echo Created venv
) else (
echo Venv already exist
)
call .\venv\Scripts\activate.bat
python -m pip install --upgrade pip --index-url http://our.nexus:8080/repository/pypi-all/simple --trusted-host our.nexus
pip install wheel --index-url http://our.nexus:8080/repository/pypi-all/simple --trusted-host our.nexus
pip install -r requirements.txt --index-url http://our.nexus:8080/repository/pypi-all/simple --trusted-host our.nexus

if not exist tmp\ (
mkdir tmp
)

call .\venv\Scripts\activate.bat
echo
echo
echo
echo ALL OK

python run.py

echo Usage: python run.py ...