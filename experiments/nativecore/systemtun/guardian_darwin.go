//go:build darwin && !ios

package systemtun

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"
)

type guardianRequest struct {
	Interface string `json:"interface"`
}
type guardianReply struct {
	Snapshot string `json:"snapshot,omitempty"`
	Error    string `json:"error,omitempty"`
}

// RunRouteGuardian is the private CLI entry point. It accepts only interface
// selections, never shell commands or arbitrary paths. EOF is the lease end.
func RunRouteGuardian(in io.Reader, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("route guardian requires root")
	}
	signals := make(chan os.Signal, 1)
	stop := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	defer close(stop)
	go func() {
		select {
		case <-stop:
		case <-signals:
			if closer, ok := in.(io.Closer); ok {
				closer.Close()
			}
		}
	}()
	return serveRouteGuardian(in, out, newRouteManager(runCommand))
}

func serveRouteGuardian(in io.Reader, out io.Writer, routes routeLease) (err error) {
	// Parent death closes stdout too. Turn EPIPE into an ordinary write error
	// so deferred route cleanup runs even while sending the final reply.
	signal.Ignore(syscall.SIGPIPE)
	defer func() { err = errors.Join(err, routes.Close()) }()
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 1024), 1024)
	encode := json.NewEncoder(out)
	for scan.Scan() {
		var req guardianRequest
		if err := json.Unmarshal(scan.Bytes(), &req); err != nil {
			return err
		}
		if !regexp.MustCompile(`^(auto|[a-zA-Z][a-zA-Z0-9]{0,14})$`).MatchString(req.Interface) {
			return errors.New("invalid outbound interface")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		snapshot, e := routes.Sync(ctx, req.Interface)
		cancel()
		reply := guardianReply{Snapshot: snapshot}
		if e != nil {
			reply.Error = e.Error()
		}
		if err := encode.Encode(reply); err != nil {
			return err
		}
	}
	return scan.Err()
}

type routeGuardian struct {
	mu                sync.Mutex
	cmd               *exec.Cmd
	in                io.WriteCloser
	out               *os.File
	reader            *bufio.Reader
	done              chan struct{}
	once              sync.Once
	waitErr, closeErr error
}

func startRouteGuardian() (*routeGuardian, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return startGuardianCommand(exec.Command(path, "internal-route-guardian"))
}

func startGuardianCommand(cmd *exec.Cmd) (*routeGuardian, error) {
	// Survive terminal Ctrl+C and parent SIGKILL. The OS pipe still closes on
	// parent death; no user-space heartbeat or PID reuse assumption is involved.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	g := &routeGuardian{cmd: cmd, in: in, out: out.(*os.File), done: make(chan struct{})}
	g.reader = bufio.NewReader(g.out)
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	go func() { g.waitErr = cmd.Wait(); close(g.done) }()
	return g, nil
}

func (g *routeGuardian) Sync(ctx context.Context, iface string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if iface == "" {
		iface = "auto"
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := g.out.SetReadDeadline(deadline); err != nil {
		return "", err
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { g.out.SetReadDeadline(time.Now()); close(canceled) })
	defer func() {
		if !stop() {
			<-canceled
		}
		g.out.SetReadDeadline(time.Time{})
	}()
	if err := json.NewEncoder(g.in).Encode(guardianRequest{iface}); err != nil {
		return "", err
	}
	line, err := g.reader.ReadString('\n')
	if err != nil {
		// A timed-out exchange cannot be reused: its late reply would be
		// mistaken for the next request. EOF asks the guardian to clean up.
		g.in.Close()
		return "", fmt.Errorf("route guardian response: %w", err)
	}
	var reply guardianReply
	if err := json.Unmarshal([]byte(line), &reply); err != nil {
		g.in.Close()
		return "", err
	}
	if reply.Error != "" {
		return "", errors.New(reply.Error)
	}
	return reply.Snapshot, nil
}
func (g *routeGuardian) Done() <-chan struct{} { return g.done }
func (g *routeGuardian) Close() error {
	g.once.Do(func() {
		g.mu.Lock()
		g.in.Close()
		g.mu.Unlock()
		select {
		case <-g.done:
			g.closeErr = g.waitErr
		case <-time.After(25 * time.Second):
			g.closeErr = errors.New("route guardian cleanup still running")
		}
	})
	return g.closeErr
}
