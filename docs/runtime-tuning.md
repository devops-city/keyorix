# Go runtime settings for the server

Three knobs matter for a long-running server container. Only the first needs
anything from you.

| Setting | What the server does | You do |
|---|---|---|
| `GOMEMLIMIT` | Soft heap limit. Not set by the Go runtime on its own. | Set it when the process has a memory limit (below). The Helm chart does it for you. |
| `GOMAXPROCS` | Go >= 1.25 (the image builds with 1.27) reads the cgroup CPU limit and keeps `GOMAXPROCS` in step with it, including when the limit changes at runtime. | Nothing. No `automaxprocs` module is needed. Set `GOMAXPROCS` yourself only to override. |
| `GOGC` | Go default (100). | Leave it. Change it only with a measurement that shows a win on your workload. |

## GOMEMLIMIT

`GOMEMLIMIT` makes the garbage collector work harder as the heap approaches the
value instead of letting it grow until the kernel OOM-kills the process. It is a
soft limit on Go-managed memory: stacks, cgo and mapped files are outside it, so
set it below the hard limit. About 85% of the container limit is the default used
here.

### Helm

The chart sets `GOMEMLIMIT` on the server container from
`server.resources.limits.memory`:

```yaml
server:
  goMemLimitPercent: 85   # default; 0 = leave GOMEMLIMIT unset
  goMemLimit: ""          # e.g. "400MiB": used verbatim, wins over the percent
```

With the default 512Mi limit this renders `GOMEMLIMIT=445644KiB`. If there is no
memory limit, or its unit is not one of `Ki/Mi/Gi/Ti/k/K/M/G/T`, nothing is set.
After raising the memory limit the value follows automatically.

### Docker Compose

Compose does not derive it. Set both together in your override file:

```yaml
services:
  backend:
    mem_limit: 512m
    environment:
      GOMEMLIMIT: 435MiB   # ~85% of mem_limit
```

### systemd

Set the hard limit with `MemoryMax` and the soft one a little under it:

```ini
[Service]
MemoryMax=512M
Environment=GOMEMLIMIT=435MiB
```

If `GOMEMLIMIT` is set below the live heap the collector runs almost
continuously, so size the container for the working set first.
