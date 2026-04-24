// Copyright The Moby Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package apparmor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// profileDirectory is the file store for AppArmor profiles and macros.
const profileDirectory = "/etc/apparmor.d"

// profileData holds information about the given profile for generation.
type profileData struct {
	// Abi is the ABI version to use.
	Abi string
	// Name is profile name.
	Name string
	// DaemonProfile is the profile name of our daemon.
	DaemonProfile string
	// Imports defines the AppArmor functions to import, before defining the profile.
	Imports []string
	// InnerImports defines the AppArmor functions to import in the profile.
	InnerImports []string
}

// generate creates an AppArmor profile from ProfileData.
func generate(p *profileData, out io.Writer, macroExistsFn func(string) bool) error {
	compiled, err := template.New("apparmor_profile").Parse(baseTemplate)
	if err != nil {
		return err
	}

	if p.DaemonProfile == "" {
		p.DaemonProfile = "unconfined"
	}

	const abi = "abi/3.0"
	if macroExistsFn(abi) {
		p.Abi = abi
	}

	if macroExistsFn("tunables/global") {
		p.Imports = append(p.Imports, "#include <tunables/global>")
	} else {
		p.Imports = append(p.Imports, "@{PROC}=/proc/")
	}

	if macroExistsFn("abstractions/base") {
		p.InnerImports = append(p.InnerImports, "#include <abstractions/base>")
	}

	return compiled.Execute(out, p)
}

// macroExists checks if the passed macro exists.
func macroExists(m string) bool {
	_, err := os.Stat(filepath.Join(profileDirectory, m))
	return err == nil
}

// InstallDefault generates a default profile, then loads the profile into the
// kernel using 'apparmor_parser'.
func InstallDefault(name string) error {
	return installDefault(context.Background(), name)
}

func installDefault(ctx context.Context, name string) error {
	// Figure out the daemon profile.
	var daemonProfile string
	if currentProfile, err := os.ReadFile("/proc/self/attr/current"); err == nil {
		// Normally profiles are suffixed by " (enforce)" or similar. AppArmor
		// profiles cannot contain spaces so this doesn't restrict daemon profile
		// names.
		profile, _, _ := strings.Cut(string(currentProfile), " ")
		// Trim trailing newline.
		profile = strings.TrimSpace(profile)
		if profile != "" {
			daemonProfile = profile
		}
	}

	p := profileData{
		Name:          name,
		DaemonProfile: daemonProfile,
	}

	var buf bytes.Buffer
	if err := generate(&p, &buf, macroExists); err != nil {
		return err
	}

	return loadProfile(ctx, &buf)
}

// IsLoaded checks if a profile with the given name has been loaded into the
// kernel.
func IsLoaded(name string) (bool, error) {
	return isLoaded(name, "/sys/kernel/security/apparmor/profiles")
}

func isLoaded(name string, fileName string) (bool, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Normally profiles are suffixed by " (enforce)" or similar. AppArmor
		// profiles cannot contain spaces so this doesn't restrict daemon profile
		// names.
		if prefix, _, ok := strings.Cut(scanner.Text(), " "); ok && prefix == name {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// loadProfile runs "apparmor_parser -Kr", providing the AppArmor profile on
// stdin to replace the profile. The "-K" is necessary to make sure that
// apparmor_parser doesn't try to write to a read-only filesystem.
func loadProfile(ctx context.Context, profile io.Reader) error {
	c := exec.CommandContext(ctx, "apparmor_parser", "-Kr")
	c.Stdin = profile
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("running '%s' failed with output: %s\nerror: %w", c, out, err)
	}

	return nil
}
