package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"breach/wbproto"
)

// runWBLogin drives the WB ID browser-callback OAuth flow: it prints an authorize
// link, waits for the user to sign in on the web and paste back the full callback
// URL, exchanges the code for tokens, and saves the WBID session to sessionPath.
// Re-uses the device identity from an existing session file when present.
func runWBLogin(sessionPath string) error {
	return runWBLoginR(bufio.NewReader(os.Stdin), sessionPath)
}

// runWBLoginR is runWBLogin reading the callback URL from r, so the setup wizard
// can drive it with the same stdin reader it uses for its other prompts.
func runWBLoginR(r *bufio.Reader, sessionPath string) error {
	if sessionPath == "" {
		return fmt.Errorf("need -wb-session <file> to save the session to")
	}
	flow, err := wbproto.StartLogin(wbproto.DeviceIDFromSession(sessionPath))
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, "\nOpen this link and sign in with WB ID:\n\n")
	fmt.Fprintln(os.Stderr, flow.AuthURL)
	fmt.Fprint(os.Stderr, "\nAfter signing in the browser lands on a callback URL.\n")
	fmt.Fprint(os.Stderr, "Paste the FULL callback URL here: ")

	line, err := r.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return fmt.Errorf("read callback URL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	sess, err := flow.Complete(ctx, line, sessionPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "saved WBID session to %s (device %s)\n", sessionPath, sess.DeviceID)
	return nil
}
