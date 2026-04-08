// SPDX-License-Identifier: Apache-2.0 OR MIT

// Command socks5-srv starts a lightweight SOCKS5 proxy server.
//
// It supports TCP CONNECT and UDP ASSOCIATE through IPv4 and IPv6 networks,
// with optional username/password authentication per RFC 1928 and RFC 1929.
//
// A config file (-config) is required; the server refuses to start without
// one to prevent accidentally running an open proxy. Private, loopback, and
// link-local destinations are blocked by default and permitted only for users
// whose config entry sets "private": true.
//
// Usage:
//
//	socks5-srv -config users.jsonl [flags]
//	  -config    users.jsonl   NDJSON file with user entries (required)
//	  -addr      :1080         listen address (host:port)
//	  -bind      203.0.113.1   bind outgoing connections to this IP
//	  -quiet                   suppress informational log output
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/vadimpiven/socks5-srv/socks5"
)

// userEntry represents one line of the NDJSON config file.
type userEntry struct {
	ID       string `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
	Private  bool   `json:"private"`
}

func main() {
	addr := flag.String("addr", ":1080", "listen address (host:port)")
	configPath := flag.String("config", "", "NDJSON file with user entries ({id, login, password, private})")
	bind := flag.String("bind", "", "local IP for outbound connections")
	quiet := flag.Bool("quiet", false, "suppress informational log output")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: -config is required")
		flag.Usage()
		os.Exit(1)
	}

	users, err := loadUsers(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(users) == 0 {
		fmt.Fprintln(os.Stderr, "error: config file contains no user entries")
		os.Exit(1)
	}

	creds := make(map[string]string, len(users))
	privateSet := make(map[string]bool, len(users))
	for _, u := range users {
		if u.Login == "" || u.Password == "" {
			fmt.Fprintf(os.Stderr, "error: user %q has empty login or password\n", u.ID)
			os.Exit(1)
		}
		if _, dup := creds[u.Login]; dup {
			fmt.Fprintf(os.Stderr, "error: duplicate login %q\n", u.Login)
			os.Exit(1)
		}
		creds[u.Login] = u.Password
		privateSet[u.Login] = u.Private
	}

	logLevel := slog.LevelInfo
	if *quiet {
		logLevel = slog.LevelWarn
	}

	cfg := socks5.Config{
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})),
		BindAddr: *bind,
		Authenticators: []socks5.Authenticator{
			socks5.UserPassAuthMulti(creds),
		},
		AllowPrivateDestinations: func(identity string) bool {
			return privateSet[identity]
		},
	}

	srv, err := socks5.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid configuration: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg.Logger.Info("listening", "addr", *addr)
	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		cfg.Logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// loadUsers reads an NDJSON file (one JSON object per line) and returns
// the parsed user entries. Blank lines are skipped.
func loadUsers(path string) ([]userEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var users []userEntry
	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if text == "" {
			continue
		}
		var u userEntry
		if err := json.Unmarshal([]byte(text), &u); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		users = append(users, u)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return users, nil
}
