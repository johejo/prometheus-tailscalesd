# prometheus-tailscalesd

## Description

[Prometheus HTTP Service Discovery](https://prometheus.io/docs/prometheus/latest/http_sd) using [tailscale](https://tailscale.com/) localapi or publicapi

You can flexibly translate api response to http_sd using jq expressions powered by [gojq](https://github.com/itchyny/gojq).

## Install

```
go install github.com/johejo/prometheus-tailscalesd@latest
```

## Usage

```
Usage of prometheus-tailscalesd:
  -address string
        listen address (default ":9924")
  -config string
        config file (default "config.yaml")
  -enable-compression
        enable response compression (default true)
  -expose-metadata
        expose metadata on self metrics endpoint (default true)
  -log-level string
        logging level: debug, info, warn, error (default "info")
  -tailscaled-socket string
        unix socket path of tailscaled (default "/var/run/tailscale/tailscaled.sock")
```

## Configuration

A module consists of three jq expressions: filter, targets, and labels.

You can filter for specific devices, build targets with specific port or assign any labels.

See also

- https://prometheus.io/docs/prometheus/latest/http_sd
- https://jqlang.github.io/jq/manual


### Example localapi configuration

```yaml
modules:
  node-exporter:
    path: /node-exporter # http path for this module
    source: localapi
    filter: | # filter devices
      select(.OS == "linux")
    targets: | # build targets: must be an array
      [(.DNSName | split(".")[0]) + ":9100"]
    labels: | # build labels: must be a object
      {
        "__meta_tailscale_device_id": .ID,
        "__meta_tailscale_device_dns_name": .DNSName | trimstr("."),
        "__meta_tailscale_device_ipv4": .TailscaleIPs[0],
      }
```

```sh
prometheus-tailscalesd -config config.yaml
```

A model showing how to translate localapi response to HTTP SD

```
[
	[.Peer | to_entries[].value] +
	[.Self] |
	.[] | 
	<filter> |
	{
		targets: <targets>,
		labels: <labels>,
	}
]
```

See also

- https://pkg.go.dev/tailscale.com/ipn/ipnstate#PeerStatus

### Example publicapi configuration

```yaml
modules:
  node-exporter:
    path: /node-exporter # http path for this module
    source: publicapi
    oauthClientIDEnv: TAILSCALE_OAUTH_CLIENT_ID # env var name for oauth client id
    oauthClientSecretEnv: TAILSCALE_OAUTH_CLIENT_SECRET # env var name for oauth client secret
    filter: | # filter devices
      select(.os == "linux")
    targets: | # build targets: must be an array
      [(.name | split(".")[0]) + ":9100"]
    labels: | # build labels: must be a object
      {
        "__meta_tailscale_device_id": .nodeId,
        "__meta_tailscale_device_dns_name": .name,
        "__meta_tailscale_device_ipv4": .addresses[0][0],
      }
```

```sh
TAILSCALE_OAUTH_CLIENT_ID="xxx" TAILSCALE_OAUTH_CLIENT_SECRET="yyy" prometheus-tailscalesd -config config.yaml
```

A model showing how to translate publicapi response to HTTP SD

```
[
	.devices[] |
	<filter> |
	{
		targets: <targets>,
		labels: <labels>,
	}
]
```

See also

- https://tailscale.com/kb/1215/oauth-clients
- https://tailscale.com/api#tag/devices/GET/tailnet/{tailnet}/devices

## Author

Mitsuo HEIJO

## License

Apache License 2.0
