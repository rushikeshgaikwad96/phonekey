@echo off
git add .github/workflows/android_build.yml
git commit -m "Fix GitHub Actions workflow using gradle/actions/setup-gradle@v3"
git push origin main
