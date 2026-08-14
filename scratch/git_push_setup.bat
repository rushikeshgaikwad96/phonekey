@echo off
git remote remove origin 2>nul
git remote add origin https://github.com/rushikeshgaikwad96/phonekey.git
git branch -M main
git add README.md
git commit -m "Update README for rushikeshgaikwad96 repository"
echo ====================================================
echo   GIT REMOTE SET TO: https://github.com/rushikeshgaikwad96/phonekey.git
echo ====================================================
