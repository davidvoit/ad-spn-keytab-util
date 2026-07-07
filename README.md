# AD Service User Keytab Generator

A small .NET command-line utility to generate (or update) Kerberos keytab files for an Active Directory service account which has a SPN bound to it.

The tool authenticates with a user account, validates access to the target SPN, determines the correct Kerberos salt, and writes keytab entries for modern AES encryption types.

## Features

- Generates keytab entries for a service principal name (SPN)
- Creates a new keytab file or updates an existing one
- Adds entries for these encryption types:
  - `AES128_CTS_HMAC_SHA1_96`
  - `AES256_CTS_HMAC_SHA1_96`
  - `AES128_CTS_HMAC_SHA256_128`
  - `AES256_CTS_HMAC_SHA384_192`

## Requirements

- .NET SDK `10.0` (project target: `net10.0`)
- Network access to your Kerberos/Active Directory domain controllers
- A valid user account that can request a service ticket for the target SPN

## AD Service Account Requirements

- User needs to have servicePrincipalName set for the target SPN (e.g., `HTTP/app.example.com`)
- rc4 only accounts are not supported. Change the password to enable AES support on the AD KDCs 

## How is this different from `ktpass`?

- `ktpass` must be run by an AD admin
- `ktpass` changes the upn to the spn name. This is required to change the salt to the RFC format
- UPNs with '/' are not handled well with tools like entra ad sync
- This tools works with normal sys accounts and don't modify the accounts at all

## Build

From the repository root:

```shell
dotnet build
```

## Run

```shell
ad-spn-keytab-util --user svc_account@EXAMPLE.COM --spn HTTP/app.example.com --output service.keytab
```

When started, the tool prompts for the user password interactively.

## Command-line options

- `-u`, `--user` (required): Username, optionally as `user@DOMAIN`
- `-d`, `--domain` (optional): Kerberos realm/domain (required if `--user` does not include `@DOMAIN`)
- `-s`, `--spn` (required): Target service principal name
- `-o`, `--output` (required): Path to the keytab file to create or update


## Packaging as a .NET tool

The project is configured as a .NET tool package:

- Tool command name: `ad-spn-keytab-util`
- Package version: `0.0.1`

## License

Apache 2.0. See `LICENSE`.

