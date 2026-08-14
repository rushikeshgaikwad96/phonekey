@echo off
git add -A
git commit -m "Pin Gradle wrapper 8.5 with bootstrap JAR, update setup-java@v5, and invoke ./gradlew in CI"
git push origin main
