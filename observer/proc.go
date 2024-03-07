package main

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

var (
	proc         procfs.FS
	appIDEnvVars = []string{"NAME", "IDENTITY", "APP_NAME", "APP_ID"}

	errNotLocal     = errors.New("no local socket for host")
	errUnknownOwner = errors.New("can't find socket owner PID")
)

func init() {
	var err error
	proc, err = procfs.NewDefaultFS()
	if err != nil {
		panic(err)
	}
}

func AppID(pid int) string {
	c, err := proc.Proc(pid)
	if err != nil {
		return ""
	}

	app, _ := c.Comm()
	env, _ := c.Environ()
	ids := searchEnvAll(env, appIDEnvVars)
	if len(ids) == 0 {
		return app
	}

	return fmt.Sprintf("%s@%s", app, strings.Join(ids, "-"))
}

func searchEnvAll(env []string, keys []string) (vals []string) {
	for _, entry := range env {
		k, v, ok := strings.Cut(entry, "=")
		if ok && slices.Contains(keys, k) {
			vals = append(vals, v)
		}
	}
	return
}

type TCPSocketProcs struct {
	// netip.AddrPort -> inode
	socks map[netip.AddrPort]uint64
	// inode -> []pid
	inos map[uint64][]int
}

func LoadTCPSocketProcs() TCPSocketProcs {
	res := TCPSocketProcs{
		socks: make(map[netip.AddrPort]uint64, 8),
		inos:  make(map[uint64][]int, 100),
	}

	allProcs, _ := proc.AllProcs()
	for _, p := range allProcs {
		fds, _ := p.FileDescriptorsInfo()
		for _, fd := range fds {
			inode, err := strconv.ParseUint(fd.Ino, 10, 64)
			if err == nil {
				res.inos[inode] = append(res.inos[inode], p.PID)
			}
		}
	}

	socks, _ := proc.NetTCP()
	for _, s := range socks {
		const TCP_LISTEN = 10
		if s.St != TCP_LISTEN || s.LocalPort > math.MaxUint16 {
			continue
		}

		ip, _ := netip.AddrFromSlice(s.LocalAddr.To16())
		key := netip.AddrPortFrom(ip, uint16(s.LocalPort))
		res.socks[key] = s.Inode
	}

	for _, pids := range res.inos {
		slices.Sort(pids)
	}
	return res
}

func (p TCPSocketProcs) HostPid(host string) (int, error) {
	addr, err := net.ResolveTCPAddr("tcp4", host)
	if err != nil {
		return 0, fmt.Errorf("resolve hostname: %w", err)
	}

	ino, ok := p.socks[addr.AddrPort()]
	if !ok {
		return 0, errNotLocal
	}

	pid, ok := p.inos[ino]
	if !ok {
		return 0, errUnknownOwner
	}
	return pid[0], nil // smallest pid
}
