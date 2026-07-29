//go:build windows

package eval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	extendedStartupInfoPresent     = 0x00080000
	createUnicodeEnvironment       = 0x00000400
	createSuspended                = 0x00000004
	startfUseStdHandles            = 0x00000100
	handleFlagInherit              = 0x00000001
	procThreadSecurityCapabilities = 0x00020009
	jobObjectExtendedLimitInfo     = 9
	jobObjectLimitProcessMemory    = 0x00000100
	jobObjectLimitKillOnJobClose   = 0x00002000
	infinite                       = 0xffffffff
	errorAlreadyExistsHRESULT      = 0x800700b7
	waitObject0                    = 0
	appContainerProfileNamePrefix  = "domehahn.skil.eval."
)

var (
	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	userenv                       = syscall.NewLazyDLL("userenv.dll")
	ole32                         = syscall.NewLazyDLL("ole32.dll")
	advapi32                      = syscall.NewLazyDLL("advapi32.dll")
	procInitializeAttributeList   = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateAttribute           = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteAttributeList       = kernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcess             = kernel32.NewProc("CreateProcessW")
	procSetHandleInformation      = kernel32.NewProc("SetHandleInformation")
	procLocalFree                 = kernel32.NewProc("LocalFree")
	procCreateJobObject           = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject   = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject  = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject        = kernel32.NewProc("TerminateJobObject")
	procResumeThread              = kernel32.NewProc("ResumeThread")
	procWaitForSingleObject       = kernel32.NewProc("WaitForSingleObject")
	procGetExitCodeProcess        = kernel32.NewProc("GetExitCodeProcess")
	procTerminateProcess          = kernel32.NewProc("TerminateProcess")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
	procCreateAppContainerProfile = userenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile = userenv.NewProc("DeleteAppContainerProfile")
	procGetAppContainerFolderPath = userenv.NewProc("GetAppContainerFolderPath")
	procCoTaskMemFree             = ole32.NewProc("CoTaskMemFree")
	procConvertSidToStringSid     = advapi32.NewProc("ConvertSidToStringSidW")
	procFreeSid                   = advapi32.NewProc("FreeSid")
)

type startupInfoEx struct {
	startup       syscall.StartupInfo
	attributeList uintptr
}

type securityCapabilities struct {
	appContainerSID uintptr
	capabilities    uintptr
	capabilityCount uint32
	reserved        uint32
}

type jobBasicLimitInformation struct {
	perProcessUserTimeLimit int64
	perJobUserTimeLimit     int64
	limitFlags              uint32
	minimumWorkingSetSize   uintptr
	maximumWorkingSetSize   uintptr
	activeProcessLimit      uint32
	affinity                uintptr
	priorityClass           uint32
	schedulingClass         uint32
}

type ioCounters struct {
	readOperationCount  uint64
	writeOperationCount uint64
	otherOperationCount uint64
	readTransferCount   uint64
	writeTransferCount  uint64
	otherTransferCount  uint64
}

type jobExtendedLimitInformation struct {
	basicLimitInformation jobBasicLimitInformation
	ioInfo                ioCounters
	processMemoryLimit    uintptr
	jobMemoryLimit        uintptr
	peakProcessMemoryUsed uintptr
	peakJobMemoryUsed     uintptr
}

func windowsIsolationAvailable() error {
	required := []*syscall.LazyProc{
		procInitializeAttributeList, procUpdateAttribute, procCreateProcess,
		procCreateAppContainerProfile, procGetAppContainerFolderPath, procConvertSidToStringSid,
	}
	for _, proc := range required {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("required Windows AppContainer API is unavailable: %w", err)
		}
	}
	return nil
}

func runWindowsIsolation(ctx context.Context, executable string, request IsolationRequest, limits IsolationLimits,
	_ string, stdout, stderr io.Writer,
) error {
	identity := appContainerProfileNamePrefix + fmt.Sprintf("%d.%d", os.Getpid(), time.Now().UnixNano())
	identityPtr, err := syscall.UTF16PtrFromString(identity)
	if err != nil {
		return err
	}
	var sid uintptr
	hr, _, _ := procCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(identityPtr)), uintptr(unsafe.Pointer(identityPtr)),
		uintptr(unsafe.Pointer(identityPtr)), 0, 0, uintptr(unsafe.Pointer(&sid)),
	)
	if uint32(hr) != 0 && uint32(hr) != errorAlreadyExistsHRESULT {
		return fmt.Errorf("create Windows AppContainer profile: HRESULT 0x%08x", uint32(hr))
	}
	defer procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(identityPtr)))
	if sid == 0 {
		return errors.New("Windows AppContainer profile returned no SID")
	}
	defer procFreeSid.Call(sid)

	sidString, releaseSIDString, err := appContainerSIDString(sid)
	if err != nil {
		return err
	}
	defer releaseSIDString()
	folder, err := appContainerFolder(sidString)
	if err != nil {
		return err
	}
	isolatedExecutable := filepath.Join(folder, "adapter.exe")
	if err := copyRegularFile(executable, isolatedExecutable); err != nil {
		return fmt.Errorf("stage Windows AppContainer adapter: %w", err)
	}

	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer stdinRead.Close()
	defer stdinWrite.Close()
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer stdoutRead.Close()
	defer stdoutWrite.Close()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer stderrRead.Close()
	defer stderrWrite.Close()
	for _, file := range []*os.File{stdinRead, stdoutWrite, stderrWrite} {
		if err := setInheritable(file); err != nil {
			return err
		}
	}

	attributeList, cleanupAttributes, err := appContainerAttributes(sid)
	if err != nil {
		return err
	}
	defer cleanupAttributes()
	startup := startupInfoEx{attributeList: attributeList}
	startup.startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.startup.Flags = startfUseStdHandles
	startup.startup.StdInput = syscall.Handle(stdinRead.Fd())
	startup.startup.StdOutput = syscall.Handle(stdoutWrite.Fd())
	startup.startup.StdErr = syscall.Handle(stderrWrite.Fd())

	commandLine := syscall.EscapeArg(isolatedExecutable)
	for _, argument := range request.Args {
		commandLine += " " + syscall.EscapeArg(argument)
	}
	commandPtr, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return err
	}
	applicationPtr, err := syscall.UTF16PtrFromString(isolatedExecutable)
	if err != nil {
		return err
	}
	directoryPtr, err := syscall.UTF16PtrFromString(folder)
	if err != nil {
		return err
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	environment, err := windowsEnvironment([]string{
		"SystemRoot=" + systemRoot,
		"PATH=" + filepath.Join(systemRoot, "System32"),
		"TMP=" + folder,
		"TEMP=" + folder,
	})
	if err != nil {
		return err
	}
	var processInfo syscall.ProcessInformation
	success, _, callErr := procCreateProcess.Call(
		uintptr(unsafe.Pointer(applicationPtr)), uintptr(unsafe.Pointer(commandPtr)),
		0, 0, 1,
		extendedStartupInfoPresent|createUnicodeEnvironment|createSuspended,
		uintptr(unsafe.Pointer(&environment[0])), uintptr(unsafe.Pointer(directoryPtr)),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&processInfo)),
	)
	if success == 0 {
		return fmt.Errorf("create Windows AppContainer process: %w", callErr)
	}
	processActive := true
	defer func() {
		if processActive {
			procTerminateProcess.Call(uintptr(processInfo.Process), 1)
		}
	}()
	defer procCloseHandle.Call(uintptr(processInfo.Process))
	defer procCloseHandle.Call(uintptr(processInfo.Thread))

	job, _, jobErr := procCreateJobObject.Call(0, 0)
	if job == 0 {
		return fmt.Errorf("create Windows isolation job: %w", jobErr)
	}
	defer procCloseHandle.Call(job)
	jobLimits := jobExtendedLimitInformation{}
	jobLimits.basicLimitInformation.limitFlags = jobObjectLimitKillOnJobClose
	if limits.MemoryBytes > 0 {
		if uint64(limits.MemoryBytes) > uint64(^uintptr(0)) {
			return errors.New("Windows process memory limit exceeds platform range")
		}
		jobLimits.basicLimitInformation.limitFlags |= jobObjectLimitProcessMemory
		jobLimits.processMemoryLimit = uintptr(limits.MemoryBytes)
	}
	if ok, _, setErr := procSetInformationJobObject.Call(job, jobObjectExtendedLimitInfo,
		uintptr(unsafe.Pointer(&jobLimits)), unsafe.Sizeof(jobLimits)); ok == 0 {
		return fmt.Errorf("configure Windows isolation job: %w", setErr)
	}
	if ok, _, assignErr := procAssignProcessToJobObject.Call(job, uintptr(processInfo.Process)); ok == 0 {
		return fmt.Errorf("assign Windows AppContainer to job: %w", assignErr)
	}
	if resumed, _, resumeErr := procResumeThread.Call(uintptr(processInfo.Thread)); resumed == 0xffffffff {
		return fmt.Errorf("resume Windows AppContainer process: %w", resumeErr)
	}
	_ = stdinRead.Close()
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()

	copyDone := make(chan error, 3)
	go func() {
		_, copyErr := stdinWrite.Write(request.Stdin)
		closeErr := stdinWrite.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		copyDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(stdout, stdoutRead)
		copyDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(stderr, stderrRead)
		copyDone <- copyErr
	}()

	waitDone := make(chan error, 1)
	go func() {
		status, _, waitErr := procWaitForSingleObject.Call(uintptr(processInfo.Process), infinite)
		if status != waitObject0 {
			waitDone <- fmt.Errorf("wait for Windows AppContainer process: %w", waitErr)
			return
		}
		var exitCode uint32
		if ok, _, exitErr := procGetExitCodeProcess.Call(uintptr(processInfo.Process),
			uintptr(unsafe.Pointer(&exitCode))); ok == 0 {
			waitDone <- fmt.Errorf("read Windows AppContainer exit code: %w", exitErr)
			return
		}
		if exitCode != 0 {
			waitDone <- fmt.Errorf("Windows AppContainer adapter exited with code %d", exitCode)
			return
		}
		waitDone <- nil
	}()
	select {
	case <-ctx.Done():
		procTerminateJobObject.Call(job, 1)
		<-waitDone
		processActive = false
		return ctx.Err()
	case err := <-waitDone:
		processActive = false
		procTerminateJobObject.Call(job, 0)
		for range 3 {
			if copyErr := <-copyDone; err == nil && copyErr != nil {
				err = copyErr
			}
		}
		return err
	}
}

func appContainerSIDString(sid uintptr) (*uint16, func(), error) {
	var value *uint16
	ok, _, callErr := procConvertSidToStringSid.Call(sid, uintptr(unsafe.Pointer(&value)))
	if ok == 0 || value == nil {
		return nil, func() {}, fmt.Errorf("convert Windows AppContainer SID: %w", callErr)
	}
	return value, func() {
		procLocalFree.Call(uintptr(unsafe.Pointer(value)))
	}, nil
}

func appContainerFolder(sidString *uint16) (string, error) {
	var value *uint16
	hr, _, _ := procGetAppContainerFolderPath.Call(
		uintptr(unsafe.Pointer(sidString)), uintptr(unsafe.Pointer(&value)),
	)
	if uint32(hr) != 0 || value == nil {
		return "", fmt.Errorf("resolve Windows AppContainer folder: HRESULT 0x%08x", uint32(hr))
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(value)))
	return utf16PointerString(value, 32768)
}

func utf16PointerString(value *uint16, maxUnits int) (string, error) {
	units := unsafe.Slice(value, maxUnits)
	for index, unit := range units {
		if unit == 0 {
			return syscall.UTF16ToString(units[:index]), nil
		}
	}
	return "", errors.New("Windows API returned an unterminated UTF-16 string")
}

func appContainerAttributes(sid uintptr) (uintptr, func(), error) {
	var size uintptr
	procInitializeAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return 0, func() {}, errors.New("size Windows process attribute list")
	}
	buffer := make([]byte, size)
	list := uintptr(unsafe.Pointer(&buffer[0]))
	if ok, _, err := procInitializeAttributeList.Call(list, 1, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return 0, func() {}, fmt.Errorf("initialize Windows process attribute list: %w", err)
	}
	capabilities := securityCapabilities{appContainerSID: sid}
	if ok, _, err := procUpdateAttribute.Call(list, 0, procThreadSecurityCapabilities,
		uintptr(unsafe.Pointer(&capabilities)), unsafe.Sizeof(capabilities), 0, 0); ok == 0 {
		procDeleteAttributeList.Call(list)
		return 0, func() {}, fmt.Errorf("set Windows AppContainer security capabilities: %w", err)
	}
	cleanup := func() {
		procDeleteAttributeList.Call(list)
		_ = buffer
		_ = capabilities
	}
	return list, cleanup, nil
}

func setInheritable(file *os.File) error {
	if ok, _, err := procSetHandleInformation.Call(file.Fd(), handleFlagInherit, handleFlagInherit); ok == 0 {
		return fmt.Errorf("make Windows sandbox pipe inheritable: %w", err)
	}
	return nil
}

func windowsEnvironment(values []string) ([]uint16, error) {
	values = append([]string(nil), values...)
	sort.Slice(values, func(left, right int) bool {
		return strings.ToUpper(values[left]) < strings.ToUpper(values[right])
	})
	environment := make([]uint16, 0)
	for _, value := range values {
		if strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("Windows environment value contains NUL")
		}
		environment = append(environment, utf16.Encode([]rune(value))...)
		environment = append(environment, 0)
	}
	return append(environment, 0), nil
}

func copyRegularFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("adapter is not a regular file")
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
