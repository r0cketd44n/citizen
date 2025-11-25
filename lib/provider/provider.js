const { exec: execCb } = require("child_process");
const { promisify } = require("util");
const exec = promisify(execCb);

const got = require("got");
const FormData = require("form-data");
const debug = require("debug")("citizen:client");

// --- GPG helpers -----------------------------------------------------

async function importEnvKey() {
  const privateKey = process.env.GPG_PRIVATE_KEY;
  if (!privateKey) return null;

  // Feed private key using echo + pipe (exec doesn't support "input:")
  await exec(`echo "${privateKey}" | gpg --batch --import`);

  const { stdout } = await exec(`gpg --list-secret-keys --with-colons`);
  const keyId = stdout
    .split("\n")
    .find((l) => l.startsWith("sec"))
    ?.split(":")[4];

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

  await exec(`echo "${batchConfig}" | gpg --batch --generate-key`);

  const { stdout } = await exec(`gpg --list-secret-keys --with-colons`);
  const keyId = stdout
    .split("\n")
    .find((l) => l.startsWith("sec"))
    ?.split(":")[4];

  if (!keyId) throw new Error("Failed to find generated GPG key ID");

  return keyId;
}

async function ensureGpgKey() {
  let keyId = await importEnvKey();
  if (keyId) return keyId;

  keyId = await generateKeypair();
  return keyId;
}

// --- SHA SUMS --------------------------------------------------------

async function genShaSums(prefix, targetDir) {
  await exec(`sha256sum *.zip > ${prefix}_SHA256SUMS`, { cwd: targetDir });
  return `${prefix}_SHA256SUMS`;
}

// --- SIGNING ---------------------------------------------------------

async function sign(shaSumsFile, targetDir) {
  const keyId = await ensureGpgKey();
  await exec(
    `gpg --detach-sign --default-key ${keyId} --yes ${shaSumsFile}`,
    { cwd: targetDir }
  );
  return `${shaSumsFile}.sig`;
}

// --- EXPORT PUBLIC KEY -----------------------------------------------

async function exportPublicKey(gpgKey) {
  const keyId = gpgKey || await ensureGpgKey();
  const { stdout } = await exec(`gpg --export --armor ${keyId}`);
  return stdout;
}

// --- PUBLISH ----------------------------------------------------------

const publish = async (registryAddr, providerPath, data, files) => {
  debug(`send post request to : ${registryAddr}/v1/providers/${providerPath}`);

  const form = new FormData();
  form.append("data", JSON.stringify(data));

  files.forEach((f, index) => {
    form.append(`file${index + 1}`, f.stream, { filename: f.filename });
  });

  return got.post(`${registryAddr}/v1/providers/${providerPath}`, {
    body: form,
    hooks: {
      beforeError: [
        (error) => {
          if (error.code === "ECONNREFUSED") {
            error.message = "The registry server doesn't respond.";
          } else if (error.response?.body) {
            const { errors } = JSON.parse(error.response.body);
            error.name = `Duplicated (${error.response.statusCode})`;
            error.message = errors.join("\n");
          }
          return error;
        },
      ],
    },
  });
};

module.exports = {
  genShaSums,
  sign,
  exportPublicKey,
  publish,
};
