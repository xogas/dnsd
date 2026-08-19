# dnsd

A minimal DNS daemon in Go: authoritative for local zones, with optional
forwarding and caching. Zero third-party dependencies.

- Go version: 1.26+
- DNS RFCs implemented: 1034, 1035, 2181, 2308, 2782, 3596, 4343, 6891, 7766

## Roadmap

Production hardening, in priority order:

1. Retry truncated upstream responses over TCP (RFC 7766)
2. Fuzz the wire codec (go test -fuzz)
3. Per-client rate limiting and ACLs
4. Metrics (expvar / Prometheus) and a health endpoint
5. Zone hot reload on SIGHUP
6. DNS Cookies (RFC 7873)

## License

MIT - see [license](./license) for details.
