#!/usr/bin/env node

import { Command } from 'commander';
import inquirer from 'inquirer';
import fs from 'fs';
import crypto from 'crypto';
import zxcvbn from 'zxcvbn';
import chalk from 'chalk';

const program = new Command();
program.version('0.1.0');

const orange = chalk.hex('#FFA500'); 

const algorithm = 'aes-256-ctr';

const encrypt = (text, key) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
};

const decrypt = (hash, key) => {
    try {
        const [iv, encryptedText] = hash.split(':');
        const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv, 'hex'));
        const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedText, 'hex')), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (err) {
        throw new Error(chalk.red('Error decrypting data. Check your master password.'));
    }
};

const loadVault = (vaultFile, masterKey) => {
    if (fs.existsSync(vaultFile)) {
        try {
            const encryptedData = fs.readFileSync(vaultFile, 'utf8');
            const decryptedData = decrypt(encryptedData, masterKey);
            const vault = JSON.parse(decryptedData);

            // Verify master password hash
            const masterPasswordHash = crypto.createHash('sha256').update(masterKey).digest('hex');
            if (vault.masterPasswordHash !== masterPasswordHash) {
                throw new Error(chalk.red('Wrong master password entered for this vault.'));
            }

            return vault;
        } catch (err) {
            throw new Error(chalk.red('Error loading vault. Check your master password.'));
        }
    }
    throw new Error(chalk.red(`Error loading vault '${vaultFile}': Vault file not found.`));
};

const saveVault = (vaultFile, vault, masterKey) => {
    const masterPasswordHash = crypto.createHash('sha256').update(masterKey).digest('hex');
    const data = { masterPasswordHash, passwords: vault.passwords };
    const jsonData = JSON.stringify(data, null, 2);
    const encryptedData = encrypt(jsonData, masterKey);
    fs.writeFileSync(vaultFile, encryptedData, 'utf8');
};

const checkUniquePassword = (vault, password, masterKey) => {
    return !vault.passwords.some(entry => decrypt(entry.password, masterKey) === password);
};

const checkPasswordStrength = (password) => {
    const result = zxcvbn(password);
    const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
    console.log(chalk.magenta(`Password strength: ${strengthLabels[result.score]}`));
    if (result.feedback.suggestions.length) {
        console.log(chalk.cyan('Suggestions:'));
        result.feedback.suggestions.forEach(suggestion => console.log(chalk.cyan(`- ${suggestion}`)));
    }
    return result.score;
};

const savePassword = (vaultFile, vault, masterKey, service, username, password) => {
    if (!checkUniquePassword(vault, password, masterKey)) {
        console.error(chalk.red('Error: This password is already in use by another service.'));
        return;
    }
    const encryptedPassword = encrypt(password, masterKey);
    const data = { service, username, password: encryptedPassword };
    vault.passwords.push(data);
    saveVault(vaultFile, vault, masterKey);
    console.log(chalk.green('Password saved!'));
};

const getPassword = (vault, masterKey, service) => {
    const entry = vault.passwords.find(p => p.service === service);
    if (entry) {
        console.log(orange(`Service: `) , `${entry.service}`);
        console.log(orange(`Username: `), `${entry.username}`);
        console.log(orange(`Password: `), `${decrypt(entry.password, masterKey)}`);
    } else {
        console.log(chalk.magenta('No password found for that service.'));
    }
};

const modifyPassword = (vaultFile, vault, masterKey, service, newPassword) => {
    if (!checkUniquePassword(vault, newPassword, masterKey)) {
        console.error(chalk.red('Error: This password is already in use by another service.'));
        return;
    }
    const entryIndex = vault.passwords.findIndex(p => p.service === service);
    if (entryIndex !== -1) {
        vault.passwords[entryIndex].password = encrypt(newPassword, masterKey);
        saveVault(vaultFile, vault, masterKey);
        console.log(chalk.green('Password updated!'));
    } else {
        console.log(chalk.magenta('No password found for that service.'));
    }
};

const deletePassword = (vaultFile, vault, masterKey, service) => {
    const updatedVault = vault.passwords.filter(p => p.service !== service);
    if (vault.passwords.length === updatedVault.length) {
        console.log(chalk.magenta('No password found for that service.'));
        return;
    }
    vault.passwords = updatedVault;
    saveVault(vaultFile, vault, masterKey);
    console.log(chalk.green('Password deleted!'));
};

const listVaults = () => {
    fs.readdir('.', (err, files) => {
        if (err) {
            console.error(chalk.red('Error reading directory:', err));
            return;
        }
        const vaultFiles = files.filter(file => file.endsWith('.vault'));
        if (vaultFiles.length === 0) {
            console.log(chalk.magenta('No vaults created yet.'));
        } else {
            console.log(chalk.cyan('List of created vaults:'));
            vaultFiles.forEach(file => console.log('- ' + file));
        }
    });
};

const listServices = (vaultFile, masterKey) => {
    try {
        const vault = loadVault(vaultFile, masterKey);
        console.log(chalk.cyan('Services in this vault:'));
        vault.passwords.forEach(entry => console.log(entry.service));
    } catch (err) {
        console.error(chalk.red(err.message));
    }
};

// Command: create-vault
program
    .command('create-vault')
    .description('Create a new vault')
    .action(() => {
        inquirer.prompt([
            { type: 'input', name: 'vaultName', message: 'Vault Name: ' },
            { type: 'password', name: 'masterPassword', message: 'Master Password: ' }
        ]).then(answers => {
            const vaultFile = `${answers.vaultName}.vault`;
            if (fs.existsSync(vaultFile)) {
                console.error(chalk.red('Error: A vault with this name already exists.'));
                return;
            }
            const masterKey = crypto.createHash('sha256').update(answers.masterPassword).digest();
            const masterPasswordHash = crypto.createHash('sha256').update(masterKey).digest('hex');
            const vault = { masterPasswordHash, passwords: [] };
            saveVault(vaultFile, vault, masterKey);
            console.log(chalk.green(`Vault '${answers.vaultName}' created!`));
        });
    });

// Command: add
program
    .command('add')
    .description('Add a new password')
    .action(() => {
        inquirer.prompt([
            { type: 'input', name: 'vaultName', message: 'Vault Name: ' },
            { type: 'password', name: 'masterPassword', message: 'Master Password: ' },
            { type: 'input', name: 'service', message: 'Service: ' },
            { type: 'input', name: 'username', message: 'Username: ' },
            { type: 'password', name: 'password', message: 'Password: ' }
        ]).then(answers => {
            const vaultFile = `${answers.vaultName}.vault`;
            if (!fs.existsSync(vaultFile)) {
                console.error(chalk.red('Error: This vault does not exist.'));
                return;
            }
            try {
                const masterKey = crypto.createHash('sha256').update(answers.masterPassword).digest();
                const vault = loadVault(vaultFile, masterKey);
                const strength = checkPasswordStrength(answers.password);
                if (strength < 2) {
                    console.error(chalk.red('Error: Password is too weak. Please choose a stronger password.'));
                    return;
                }
                savePassword(vaultFile, vault, masterKey, answers.service, answers.username, answers.password);
            } catch (err) {
                console.error(chalk.red(err.message));
            }
        });
    });

// Command: get
program
    .command('get')
    .description('Get a password for a service')
    .action(() => {
        inquirer.prompt([
            { type: 'input', name: 'vaultName', message: 'Vault Name: ' },
            { type: 'password', name: 'masterPassword', message: 'Master Password: ' },
            { type: 'input', name: 'service', message: 'Service: ' }
        ]).then(answers => {
            const vaultFile = `${answers.vaultName}.vault`;
            if (!fs.existsSync(vaultFile)) {
                console.error(chalk.red('Error: This vault does not exist.'));
                return;
            }
            try {
                const masterKey = crypto.createHash('sha256').update(answers.masterPassword).digest();
                const vault = loadVault(vaultFile, masterKey);
                getPassword(vault, masterKey, answers.service);
            } catch (err) {
                console.error(chalk.red(err.message));
            }
        });
    });


// Command: modify
program
    .command('modify')
    .description('Modify an existing password')
    .action(() => {
        inquirer.prompt([
            { type: 'input', name: 'vaultName', message: 'Vault Name: ' },
            { type: 'password', name: 'masterPassword', message: 'Master Password: ' },
            { type: 'input', name: 'service', message: 'Service: ' },
            { type: 'password', name: 'newPassword', message: 'New Password: ' }
        ]).then(answers => {
            const vaultFile = `${answers.vaultName}.vault`;
            if (!fs.existsSync(vaultFile)) {
                console.error(chalk.red('Error: This vault does not exist.'));
                return;
            }
            try {
                const masterKey = crypto.createHash('sha256').update(answers.masterPassword).digest();
                const vault = loadVault(vaultFile, masterKey);
                const strength = checkPasswordStrength(answers.newPassword);
                if (strength < 2) {
                    console.error(chalk.red('Error: Password is too weak. Please choose a stronger password.'));
                    return;
                }
                modifyPassword(vaultFile, vault, masterKey, answers.service, answers.newPassword);
            } catch (err) {
                console.error(chalk.red(err.message));
            }
        });
    });

// Command: delete
program
    .command('delete')
    .description('Delete a password for a service')
    .action(() => {
        inquirer.prompt([
            { type: 'input', name: 'vaultName', message: 'Vault Name: ' },
            { type: 'password', name: 'masterPassword', message: 'Master Password: ' },
            { type: 'input', name: 'service', message: 'Service: ' }
        ]).then(answers => {
            const vaultFile = `${answers.vaultName}.vault`;
            if (!fs.existsSync(vaultFile)) {
                console.error(chalk.red('Error: This vault does not exist.'));
                return;
            }
            try {
                const masterKey = crypto.createHash('sha256').update(answers.masterPassword).digest();
                const vault = loadVault(vaultFile, masterKey);
                deletePassword(vaultFile, vault, masterKey, answers.service);
            } catch (err) {
                console.error(chalk.red(err.message));
            }
        });
    });

// Command: list-vaults
program
    .command('list-vaults')
    .description('List all created vaults')
    .action(() => {
        listVaults();
    });

// Command: list-services
program
    .command('list-services')
    .description('List all services in a vault')
    .action(() => {
        inquirer.prompt([
            { type: 'input', name: 'vaultName', message: 'Vault Name: ' },
            { type: 'password', name: 'masterPassword', message: 'Master Password: ' }
        ]).then(answers => {
            const vaultFile = `${answers.vaultName}.vault`;
            try {
                const masterKey = crypto.createHash('sha256').update(answers.masterPassword).digest();
                listServices(vaultFile, masterKey);
            } catch (err) {
                console.error(chalk.red(err.message));
            }
        });
    });    


program.parse(process.argv);




