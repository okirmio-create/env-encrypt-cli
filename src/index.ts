import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;
const PREFIX = 'enc:v1:';

function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LENGTH);
}

function encryptValue(value: string, password: string): string {
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKey(password, salt);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const payload = Buffer.concat([salt, iv, authTag, encrypted]);
  return PREFIX + payload.toString('base64');
}

function decryptValue(encoded: string, password: string): string {
  if (!encoded.startsWith(PREFIX)) {
    throw new Error('Value is not encrypted (missing enc:v1: prefix)');
  }

  const payload = Buffer.from(encoded.slice(PREFIX.length), 'base64');

  const salt = payload.subarray(0, SALT_LENGTH);
  const iv = payload.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = payload.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
  const encrypted = payload.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = deriveKey(password, salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

function resolveKey(keyOption: string | undefined, keyFileOption: string | undefined): string {
  if (keyFileOption) {
    const keyFilePath = resolve(keyFileOption);
    if (!existsSync(keyFilePath)) {
      console.error(chalk.red(`Key file not found: ${keyFilePath}`));
      process.exit(1);
    }
    return readFileSync(keyFilePath, 'utf8').trim();
  }

  if (keyOption) {
    // If the value looks like an env var name (all caps, underscores), resolve it
    if (/^[A-Z_][A-Z0-9_]*$/.test(keyOption)) {
      const envValue = process.env[keyOption];
      if (envValue) {
        return envValue;
      }
      // Fall through to use the literal value if env var not set
    }
    return keyOption;
  }

  // Check default env var
  const defaultKey = process.env['ENV_ENCRYPT_KEY'];
  if (defaultKey) {
    return defaultKey;
  }

  console.error(chalk.red('No encryption key provided.'));
  console.error(chalk.yellow('Use -k/--key, --key-file, or set ENV_ENCRYPT_KEY environment variable.'));
  process.exit(1);
}

function parseEnvFile(content: string): Array<{ raw: string; key?: string; value?: string }> {
  const lines = content.split('\n');
  return lines.map((raw) => {
    // Preserve comments and empty lines
    if (raw.trim() === '' || raw.trim().startsWith('#')) {
      return { raw };
    }

    const eqIndex = raw.indexOf('=');
    if (eqIndex === -1) {
      return { raw };
    }

    const key = raw.substring(0, eqIndex).trim();
    const value = raw.substring(eqIndex + 1);
    return { raw, key, value };
  });
}

function encryptCommand(options: { input: string; output: string; key?: string; keyFile?: string }): void {
  const inputPath = resolve(options.input);
  const outputPath = resolve(options.output);

  if (!existsSync(inputPath)) {
    console.error(chalk.red(`Input file not found: ${inputPath}`));
    process.exit(1);
  }

  const password = resolveKey(options.key, options.keyFile);
  const content = readFileSync(inputPath, 'utf8');
  const entries = parseEnvFile(content);

  let encryptedCount = 0;
  let skippedCount = 0;

  const outputLines = entries.map(({ raw, key, value }) => {
    if (key === undefined || value === undefined) {
      return raw;
    }

    if (value.startsWith(PREFIX)) {
      skippedCount++;
      console.log(chalk.dim(`  skip  ${key} (already encrypted)`));
      return raw;
    }

    if (value.trim() === '') {
      skippedCount++;
      console.log(chalk.dim(`  skip  ${key} (empty value)`));
      return `${key}=${value}`;
    }

    const encrypted = encryptValue(value, password);
    encryptedCount++;
    console.log(chalk.green(`  enc   ${key}`));
    return `${key}=${encrypted}`;
  });

  writeFileSync(outputPath, outputLines.join('\n'), 'utf8');

  console.log('');
  console.log(chalk.bold(`Encrypted ${chalk.green(String(encryptedCount))} variable(s), skipped ${chalk.yellow(String(skippedCount))}.`));
  console.log(chalk.dim(`Output: ${outputPath}`));
}

function decryptCommand(options: { input: string; output: string; key?: string; keyFile?: string }): void {
  const inputPath = resolve(options.input);
  const outputPath = resolve(options.output);

  if (!existsSync(inputPath)) {
    console.error(chalk.red(`Input file not found: ${inputPath}`));
    process.exit(1);
  }

  const password = resolveKey(options.key, options.keyFile);
  const content = readFileSync(inputPath, 'utf8');
  const entries = parseEnvFile(content);

  let decryptedCount = 0;
  let skippedCount = 0;

  const outputLines = entries.map(({ raw, key, value }) => {
    if (key === undefined || value === undefined) {
      return raw;
    }

    if (!value.startsWith(PREFIX)) {
      skippedCount++;
      console.log(chalk.dim(`  skip  ${key} (not encrypted)`));
      return raw;
    }

    try {
      const decrypted = decryptValue(value, password);
      decryptedCount++;
      console.log(chalk.green(`  dec   ${key}`));
      return `${key}=${decrypted}`;
    } catch {
      console.error(chalk.red(`  FAIL  ${key} (wrong key or corrupted data)`));
      process.exit(1);
    }
  });

  writeFileSync(outputPath, outputLines.join('\n'), 'utf8');

  console.log('');
  console.log(chalk.bold(`Decrypted ${chalk.green(String(decryptedCount))} variable(s), skipped ${chalk.yellow(String(skippedCount))}.`));
  console.log(chalk.dim(`Output: ${outputPath}`));
}

function rotateCommand(options: { input: string; key?: string; keyFile?: string; newKey: string; newKeyFile?: string }): void {
  const inputPath = resolve(options.input);

  if (!existsSync(inputPath)) {
    console.error(chalk.red(`Input file not found: ${inputPath}`));
    process.exit(1);
  }

  const oldPassword = resolveKey(options.key, options.keyFile);

  let newPassword: string;
  if (options.newKeyFile) {
    const keyFilePath = resolve(options.newKeyFile);
    if (!existsSync(keyFilePath)) {
      console.error(chalk.red(`New key file not found: ${keyFilePath}`));
      process.exit(1);
    }
    newPassword = readFileSync(keyFilePath, 'utf8').trim();
  } else if (options.newKey) {
    newPassword = options.newKey;
  } else {
    console.error(chalk.red('New key is required for rotation. Use --new-key or --new-key-file.'));
    process.exit(1);
  }

  const content = readFileSync(inputPath, 'utf8');
  const entries = parseEnvFile(content);

  let rotatedCount = 0;

  const outputLines = entries.map(({ raw, key, value }) => {
    if (key === undefined || value === undefined) {
      return raw;
    }

    if (!value.startsWith(PREFIX)) {
      return raw;
    }

    try {
      const decrypted = decryptValue(value, oldPassword);
      const reEncrypted = encryptValue(decrypted, newPassword);
      rotatedCount++;
      console.log(chalk.green(`  rot   ${key}`));
      return `${key}=${reEncrypted}`;
    } catch {
      console.error(chalk.red(`  FAIL  ${key} (wrong old key or corrupted data)`));
      process.exit(1);
    }
  });

  writeFileSync(inputPath, outputLines.join('\n'), 'utf8');

  console.log('');
  console.log(chalk.bold(`Rotated ${chalk.green(String(rotatedCount))} variable(s).`));
  console.log(chalk.dim(`Updated: ${inputPath}`));
}

const program = new Command();

program
  .name('env-encrypt-cli')
  .description('Encrypt and decrypt .env file values for secure storage in git')
  .version('1.0.0');

program
  .command('encrypt')
  .description('Encrypt .env values → .env.encrypted')
  .option('-i, --input <file>', 'Input .env file', '.env')
  .option('-o, --output <file>', 'Output encrypted file', '.env.encrypted')
  .option('-k, --key <key>', 'Encryption key or ENV var name holding the key')
  .option('--key-file <file>', 'Read encryption key from file')
  .action(encryptCommand);

program
  .command('decrypt')
  .description('Decrypt .env.encrypted → .env')
  .option('-i, --input <file>', 'Input encrypted file', '.env.encrypted')
  .option('-o, --output <file>', 'Output .env file', '.env')
  .option('-k, --key <key>', 'Encryption key or ENV var name holding the key')
  .option('--key-file <file>', 'Read encryption key from file')
  .action(decryptCommand);

program
  .command('rotate')
  .description('Re-encrypt with a new key')
  .option('-i, --input <file>', 'Encrypted file to rotate', '.env.encrypted')
  .option('-k, --key <key>', 'Current encryption key')
  .option('--key-file <file>', 'Read current key from file')
  .option('--new-key <key>', 'New encryption key')
  .option('--new-key-file <file>', 'Read new key from file')
  .action(rotateCommand);

program.parse();
