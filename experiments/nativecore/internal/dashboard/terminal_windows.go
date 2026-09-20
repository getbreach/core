//go:build windows

package dashboard

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

type terminal struct {
	input                *os.File
	state                *term.State
	output               windows.Handle
	outputMode, outputCP uint32
}

func openTerminal() (*terminal, error) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, errors.New("TUI requires Windows Terminal or a VT-capable console; use breach run for plain logs")
	}
	f, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	state, err := term.MakeRaw(int(f.Fd()))
	if err != nil {
		f.Close()
		return nil, err
	}
	t := &terminal{input: f, state: state, output: windows.Handle(os.Stdout.Fd())}
	restore := func() { term.Restore(int(f.Fd()), state); f.Close() }
	if err = windows.GetConsoleMode(t.output, &t.outputMode); err != nil {
		restore()
		return nil, err
	}
	t.outputCP, err = windows.GetConsoleOutputCP()
	if err != nil {
		restore()
		return nil, err
	}
	if err = windows.SetConsoleMode(t.output, t.outputMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		restore()
		return nil, err
	}
	if err = windows.SetConsoleOutputCP(65001); err != nil {
		t.close()
		return nil, err
	}
	// Read input events directly so polling never blocks on resize/mouse events.
	var mode uint32
	if err = windows.GetConsoleMode(windows.Handle(f.Fd()), &mode); err == nil {
		err = windows.SetConsoleMode(windows.Handle(f.Fd()), mode&^windows.ENABLE_VIRTUAL_TERMINAL_INPUT)
	}
	if err != nil {
		t.close()
		return nil, err
	}
	return t, nil
}
func (t *terminal) close() error {
	return errors.Join(term.Restore(int(t.input.Fd()), t.state), windows.SetConsoleMode(t.output, t.outputMode), windows.SetConsoleOutputCP(t.outputCP), t.input.Close())
}
func (*terminal) size() (int, int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80, 24
	}
	return w, h
}

// Win32 INPUT_RECORD: WORD type + alignment + 16-byte event union.
// See https://learn.microsoft.com/windows/console/input-record-str.
type consoleRecord struct {
	kind                           uint16
	pad                            uint16
	down                           uint32
	repeat, virtualKey, scan, char uint16
	control                        uint32
}

var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

func (t *terminal) keys() ([]byte, error) {
	h := windows.Handle(t.input.Fd())
	var count uint32
	if err := windows.GetNumberOfConsoleInputEvents(h, &count); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	var records [64]consoleRecord
	var read uint32
	ok, _, err := readConsoleInput.Call(uintptr(h), uintptr(unsafe.Pointer(&records[0])), uintptr(min(count, 64)), uintptr(unsafe.Pointer(&read)))
	if ok == 0 {
		return nil, err
	}
	var keys []byte
	for _, r := range records[:read] {
		if r.kind == 1 && r.down != 0 && r.char > 0 && r.char < 128 {
			for i := uint16(0); i < min(r.repeat, 64); i++ {
				keys = append(keys, byte(r.char))
			}
		}
	}
	return keys, nil
}
