const { exec } = require('node:child_process');
const got = require('got');
const FormData = require('form-data');
const debug = require('debug')('citizen:client');

import { exec as execCb } from 'child_process';
import { promisify } from 'util';

const exec = promisify(execCb);

async function importEnvKey() {
  const privateKey = process.env.GPG_PRIVATE_KEY;
  if (!privateKey) return null;

  // Import the private key
  await exec(`gpg --batch --import`, { input: privateKey });

  // Get the key ID
  const { stdout } = await exec(
    `gpg --list-secret-keys --with-colons`
  );

  const keyId = stdout
    .split('\n')
    .find((l) => l.startsWith('sec'))
    ?.split(':')[4];

  return keyId || null;
}

async function generateKeypair(name = "Auto Generated", email = "auto@example.com") {
  const batchConfig = `
Key-Type: RSA
Key-Length: 2048
Name-Real: ${name}
Name-Email: ${email}
Expire-Date: 0
%no-protection
%commit
`;

  await exec(`gpg --batch --generate-key`, { input: batchConfig });

  // Extract the new key ID
  const { stdout } = await exec(`gpg --list-secret-keys --with-colons`);
  const keyId = stdout
    .split('\n')
    .find((l) => l.startsWith('sec'))
    ?.split(':')[4];

  if (!keyId) {
    throw new Error("Failed to find generated GPG key ID");
  }

  return keyId;
}

async function ensureGpgKey() {
  // 1. Try importing from environment
  let keyId = await importEnvKey();
  if (keyId) {
    console.log(`Using GPG key from environment: ${keyId}`);
    return keyId;
  }

  // 2. Otherwise generate a new key
  keyId = await generateKeypair();
  console.log(`Generated new GPG key: ${keyId}`);
  return keyId;
}


const genShaSums = (fileNamePrefix, targetDir) =>
  new Promise((resolve, reject) => {
    exec(`sha256sum *.zip > ${fileNamePrefix}_SHA256SUMS`, { cwd: targetDir }, (err) => {
      if (err) {
        return reject(err);
      }
      return resolve(`${fileNamePrefix}_SHA256SUMS`);
    });
  });

async function sign(shaSumsFile, targetDir) {
  const gpgKey = await ensureGpgKey();
  await exec(
    `gpg --detach-sign --default-key ${gpgKey} --yes ${shaSumsFile}`,
    { cwd: targetDir }
  );
  return `${shaSumsFile}.sig`;
}


async function exportPublicKey(gpgKey) {
  // If a key is passed → use it.
  // If not → ensure we have a usable key (env-imported or auto-generated)
  const keyId = gpgKey || await ensureGpgKey();

  try {
    const { stdout } = await exec(`gpg --export --armor ${keyId}`);
    return stdout;
  } catch (err) {
    throw new Error(`Failed to export public key: ${err.message}`);
  }
}

const publish = async (registryAddr, providerPath, data, files) => {
  debug(`send post request to : ${registryAddr}/v1/providers/${providerPath}`);

  const form = new FormData();
  form.append('data', JSON.stringify(data));
  files.forEach((f, index) => {
    form.append(`file${index + 1}`, f.stream, { filename: f.filename });
  });

  const result = await got.post(`${registryAddr}/v1/providers/${providerPath}`, {
    body: form,
    hooks: {
      beforeError: [
        (error) => {
          /* eslint-disable no-param-reassign */
          if (error.code === 'ECONNREFUSED') {
            error.message = "The registry server doesn't response. Please check the registry.";
          } else {
            const { response } = error;
            if (response && response.body) {
              const { errors } = JSON.parse(response.body);
              error.name = `Duplicated (${response.statusCode})`;
              error.message = errors.map((msg) => `${msg}`).join('\n');
            }
          }
          return error;
          /* eslint-enable no-param-reassign */
        },
      ],
    },
  });
  return result;
};

module.exports = {
  genShaSums,
  sign,
  exportPublicKey,
  publish,
};
