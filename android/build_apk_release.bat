@echo off
echo ====================================================
echo      BUILDING PHONEKEY ANDROID RELEASE APK          
echo ====================================================

cd /d "%~dp0"

if exist gradlew.bat (
    call gradlew.bat assembleRelease
) else (
    echo Gradle wrapper gradlew.bat not found in directory.
    echo Opening project in Android Studio or running standard gradle assembleRelease...
    gradle assembleRelease
)

if %ERRORLEVEL% EQU 0 (
    echo ====================================================
    echo   ANDROID APK BUILD COMPLETED SUCCESSFULLY!        
    echo ====================================================
) else (
    echo Gradle build returned code %ERRORLEVEL%. Open directory in Android Studio to build APK.
)
