# socks5-srv

A lightweight, embeddable SOCKS5 proxy server written in Go, implementing
[RFC 1928](rfcs/rfc1928.txt) and [RFC 1929](rfcs/rfc1929.txt).

## Features

| Feature             | Detail                                                   |
| ------------------- | -------------------------------------------------------- |
| Commands            | `CONNECT` (TCP tunnel), `UDP ASSOCIATE` (datagram relay) |
| Auth methods        | No-auth (0x00), username/password (0x02)                 |
| Address families    | IPv4, IPv6, domain names                                 |
| Per-user policy     | Private-destination access controlled per user           |
| Concurrency limit   | Configurable max simultaneous connections (default 1024) |
| Graceful shutdown   | Drains active sessions before exiting                    |

> **Not implemented:** BIND (0x02) — rejected with reply 0x07.  
> **Not implemented:** GSSAPI (method 0x01) — absent from virtually all deployed SOCKS5 stacks.  
> **Not implemented:** UDP fragmentation — silently dropped per RFC 1928 §7.

## Requirements

- Go 1.26+

## Build

```sh
go build -o socks5-srv .
```

## Usage

```text
socks5-srv -config <file> [flags]

  -config   string   NDJSON file with user entries (required)
  -addr     string   listen address (default ":1080")
  -bind     string   local IP to bind outgoing connections to
  -quiet             suppress informational log output
```

### Config file format (NDJSON — one JSON object per line)

```jsonl
{"id": "alice", "login": "alice", "password": "s3cr3t", "private": true}
{"id": "bob",   "login": "bob",   "password": "hunter2", "private": false}
```

| Field      | Description                                              |
| ---------- | -------------------------------------------------------- |
| `id`       | Human-readable name (for the operator's convenience)     |
| `login`    | SOCKS5 authentication username                           |
| `password` | SOCKS5 authentication password                           |
| `private`  | Allow connections to private/loopback destinations       |

### Basic usage

```sh
./socks5-srv -config users.jsonl
```

### Restrict outbound to a specific network interface

```sh
./socks5-srv -config users.jsonl -bind 203.0.113.1
```

## Embedding

```go
import "github.com/vadimpiven/socks5-srv/socks5"

srv, err := socks5.NewServer(socks5.Config{
    Authenticators: []socks5.Authenticator{
        socks5.UserPassAuth("alice", "s3cr3t"),
    },
})
if err != nil {
    log.Fatal(err)
}

ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

if err := srv.ListenAndServe(ctx, ":1080"); err != nil {
    log.Fatal(err)
}
```

### Multiple users

```go
socks5.UserPassAuthMulti(map[string]string{
    "alice": "s3cr3t",
    "bob":   "hunter2",
})
```

### Custom outbound dialer (proxy chaining, metrics, TLS)

```go
socks5.Config{
    Dial: (&net.Dialer{LocalAddr: bindAddr}).DialContext,
}
```

### Private-destination policy

By default, CONNECT to private, loopback, and link-local addresses is blocked
(SSRF protection). Set `AllowPrivateDestinations` to permit specific users
(or all users) to reach internal infrastructure:

```go
socks5.Config{
    AllowPrivateDestinations: func(identity string) bool { return true },
}
```

## Testing

```sh
go test ./...
go test -race ./...
```

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE.txt) or [MIT](LICENSE-MIT.txt).
