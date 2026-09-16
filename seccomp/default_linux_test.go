// SPDX-FileCopyrightText: Copyright The Moby Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func socketTestSyscall(args ...specs.LinuxSeccompArg) *Syscall {
	return &Syscall{
		LinuxSyscall: specs.LinuxSyscall{
			Names:  []string{"socket"},
			Action: specs.ActAllow,
			Args:   args,
		},
	}
}

func TestSocketSyscallsForDomains(t *testing.T) {
	fixtures := []struct {
		name    string
		domains []uint64
		want    []*Syscall
	}{
		{
			name:    "singleton",
			domains: []uint64{39},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 39, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "later consecutive run",
			domains: []uint64{1, 2, 4, 5},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 3, Op: specs.OpLessThan}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 4, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 5, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "multiple gaps",
			domains: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 16, 20},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 11, Op: specs.OpLessThan}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 12, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 13, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 14, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 16, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 20, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "two-domain initial range",
			domains: []uint64{1, 2},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 3, Op: specs.OpLessThan}),
			},
		},
		{
			name:    "gap after initial domain",
			domains: []uint64{1, 3, 4},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 1, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 3, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 4, Op: specs.OpEqualTo}),
			},
		},
		{
			name:    "range not at initial domain",
			domains: []uint64{10, 11, 12},
			want: []*Syscall{
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 10, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 11, Op: specs.OpEqualTo}),
				socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: 12, Op: specs.OpEqualTo}),
			},
		},
	}

	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			assertDeepEqual(t, test.want, socketSyscallsForDomains(test.domains))
		})
	}
}

func TestDefaultSyscalls(t *testing.T) {
	want := []*Syscall{
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_ALG, Op: specs.OpLessThan}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_NFC, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_KCM, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_QIPCRTR, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_SMC, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_XDP, Op: specs.OpEqualTo}),
		socketTestSyscall(specs.LinuxSeccompArg{Index: 0, Value: unix.AF_MCTP, Op: specs.OpEqualTo}),
	}

	assertDeepEqual(t, want, socketSyscalls())
}
