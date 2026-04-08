# socks5-srv

A lightweight, embeddable SOCKS5 proxy server written in Go, implementing
[RFC 1928](rfcs/rfc1928.txt) and [RFC 1929](rfcs/rfc1929.txt).

## Features

| Feature             | Detail                                                   |
| ------------------- | -------------------------------------------------------- |
| Commands            | `CONNECT` (TCP tunnel), `UDP ASSOCIATE` (datagram relay) |
| Auth methods        | No-auth (0x00), username/password (0x02)                 |
| Address families    | IPv4, IPv6, domain names                                 |
| Trusted-IP bypass   | Skip auth for known source IPs                           |
| Auth-once promotion | Whitelist a client IP after its first successful auth    |
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

```
socks5-srv [flags]

  -addr   string   listen address (default ":1080")
  -user   string   username for authentication
  -pass   string   password for authentication (must pair with -user)
  -bind   string   local IP to bind outgoing connections to
  -allow  string   comma-separated IPs that bypass authentication
  -auth-once       whitelist a client IP after first successful auth
  -quiet           suppress informational log output
```

### Open proxy (no auth)

```sh
./socks5-srv -addr :1080
```

### Username/password auth

```sh
./socks5-srv -addr :1080 -user alice -pass s3cr3t
```

### Restrict outbound to a specific network interface

```sh
./socks5-srv -addr :1080 -bind 203.0.113.1
```

### Trusted IPs bypass auth; all others must authenticate

```sh
./socks5-srv -addr :1080 -user alice -pass s3cr3t -allow 10.0.0.1,10.0.0.2
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

### Custom access control

```go
// Allow only CONNECT; reject UDP ASSOCIATE.
socks5.Config{
    Rules: socks5.PermitCommand{EnableConnect: true},
}

// Implement socks5.RuleSet for user- or destination-based control.
```

## Testing

```sh
go test ./...
go test -race ./...
```

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE.txt) or [MIT](LICENSE-MIT.txt).
