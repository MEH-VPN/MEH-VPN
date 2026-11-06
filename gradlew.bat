@rem Gradle startup script for Windows
@if "%DEBUG%"=="" @echo off
set DIRNAME=%~dp0
if "%DIRNAME%"=="" set DIRNAME=.
set WRAPPER_JAR=%DIRNAME%gradle\wrapper\gradle-wrapper.jar
if exist "%WRAPPER_JAR%" (
  java -classpath "%WRAPPER_JAR%" org.gradle.wrapper.GradleWrapperMain %*
) else (
  gradle %*
)
