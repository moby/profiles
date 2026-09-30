# Profiles

A collection of security profiles for containers, including AppArmor and seccomp profiles used by Moby.

## Overview

This repository contains:

- **AppArmor profiles**: Linux kernel security module profiles for mandatory access control
- **seccomp profiles**: Secure computing mode profiles for syscall filtering

## Components

### AppArmor (`/apparmor`)

The AppArmor package provides functionality for generating and managing AppArmor profiles for containers.

### seccomp (`/seccomp`)

The seccomp package provides functionality for generating and managing seccomp profiles for syscall filtering in containers.

## Usage

Each package can be imported and used independently:

```go
import (
    "github.com/moby/profiles/apparmor"
    "github.com/moby/profiles/seccomp"
)
```

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## AI-assisted contributions

AI-assisted contributions to this repository must follow the [Moby and Docker AI usage policy](https://github.com/moby/.github/blob/main/AI_POLICY.md).

## Security

For security issues, please follow the [Moby security policy](https://github.com/moby/moby/security/policy).
