@echo off
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0secretctl.ps1" %*
