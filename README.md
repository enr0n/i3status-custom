# Custom i3status

Customized `i3status` command built with [Barista](https://barista.run/). Includes a Barista module for strongSwan.

## Install

```bash
go install enr0n.net/i3status/cmd/i3status-enr0n@latest
```

## Configure

Set the `status_command` in your i3 config:

```
# Start i3bar to display a workspace bar (plus the system information i3status
# finds out, if available)
bar {
        status_command "exec ~/go/bin/i3status-enr0n"

        ...

}
```

It may be better to run vici over TCP, otherwise the `/var/run/charon.vici` socket permissions need to be changed. If using a non-default vici socket, set this with the `--vici-socket` flag:


```
# Start i3bar to display a workspace bar (plus the system information i3status
# finds out, if available)
bar {
        status_command "exec ~/go/bin/i3status-enr0n --vici-socket tcp://localhost:9999"

        ...

}
```

## strongSwan Barista Module

[![Go Reference](https://pkg.go.dev/badge/enr0n.net/i3status/strongswan.svg)](https://pkg.go.dev/enr0n.net/i3status/strongswan)

This module grabs information from the charon daemon over vici, and can be used to display IKE SA name, child SA name, virtual IPs, etc.
