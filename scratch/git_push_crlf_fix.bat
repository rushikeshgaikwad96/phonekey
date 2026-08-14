@echo off
git add .
git commit -m "Fix CRLF line endings for gradlew via .gitattributes and sed sanitization in workflow"
git push origin main
