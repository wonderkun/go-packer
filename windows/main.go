package main


/*
#cgo LDFLAGS: -L./  -lMmLoadExe  -L./Syscalls -lsyscallsStubs -lsyscalls
#include "mm.h"
*/
import "C"
import "fmt"
import "unsafe"

func main() {
    
	data, err := Asset("test.exe")
	if err != nil {
		// Asset was not found.
		fmt.Println("read test.exe file content error!")
	}

	fileSize := len(data)
	// fmt.Println("file size %d",fileSize)

	pData := (*C.uchar)(unsafe.Pointer(&data[0]))

	C.runmain( pData ,C.ulong(fileSize) )
	return
}