# storepass CLI

`storepass` is a command-line tool for managing passwords securely. This tool allows you to create vaults, add, retrieve, modify, delete passwords, and list all services stored in a vault.


## Features

- Create encrypted vaults to store passwords.
- Add new passwords to an existing vault.
- Retrieve passwords for specific services.
- Modify existing passwords.
- Delete passwords from a vault.
- List all services stored in a vault.
- List all vaults created.


## Installation

To install the `storepass` CLI tool, use npm:

```sh
npm install -g storepass
```

## Usage

Below are the available commands for the storepass CLI tool:

### Create a Vault

Creates a new vault to store passwords. You will be prompted to enter the vault name and master password.

```sh
storepass create-vault
```
### Add a Password
Adds a new password to an existing vault. You will be prompted to enter the vault name, master password, service name, username, and password.

```sh
storepass add
```
### Get a Password
Retrieves a password for a specific service from the vault. You will be prompted to enter the vault name, master password, and service name.

```sh
storepass get
```
### Modify a Password
Modifies an existing password in the vault. You will be prompted to enter the vault name, master password, service name, and new password.

```sh
storepass modify
```
### Delete a Password
Deletes a password for a specific service from the vault. You will be prompted to enter the vault name, master password, and service name.

```sh
storepass delete
```
### List Services
Lists all the services stored in a vault. You will be prompted to enter the vault name and master password.

```sh
storepass list-services
```
### List Vaults
Lists all the vaults created.

```sh
storepass list-vaults
```

## Acknowledgements

- Commander.js - CLI framework
- Inquirer.js - Command-line user interface
- zxcvbn - Password strength estimator
- chalk - Terminal string styling done right


## Author
Divya Gandhi - 16gandhi.hemani@gmail.com




