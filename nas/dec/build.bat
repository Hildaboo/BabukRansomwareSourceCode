@echo off

set GOOS=linux
set GOARCH=386
go build -o d_nas_x86.out

set GOOS=linux
set GOARCH=arm
go build -o d_nas_arm.out

pause