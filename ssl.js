const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const opensslCA = 'openssl req -x509 -nodes -days 9999 -sha256 -newkey rsa:2048';
const opensslReq = 'openssl req -nodes -newkey rsa:2048';
const opensslSign = 'openssl x509 -req -days 9999 -sha256';
const caSubj = '"/C=US/ST=California/L=Berkeley/O=Symmetric/OU=Engineering/CN=Symmetric Proxy CA"';
const subj = '"/C=US/ST=California/L=Berkeley/O=Symmetric/OU=Engineering/CN=Symmetric Proxy"';
const keymoji = '\u{1F510} ';

/**
 * Create a self-signed cert, save it to ~/.symmetric and then add it as a trusted cert to the keychain.
 * @param {Object} [options] - Pass through additionalDomains and/or additionalIPs here to add to the alt names of the cert
 * @param {Array} [options.additionalDomains] - Additional domain names to add as alternate names allowed with the SSL cert
 * @param {Array} [options.additionalIPs] - Additional IP addresses to add as alternate names allowed with the SSL cert
 * @param {string} [options.home] - Root directory used to store all generated certs and keys. Also can be given as SYMMETRIC_HOME env variable. Defaults to `~/.symmetric`
 * @description For a great example and informative websites this was based on see the following:
 * https://github.com/loganstellway/self-signed-ssl/blob/master/self-signed-tls
 * https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-16-04
 * https://datacenteroverlords.com/2012/03/01/creating-your-own-ssl-certificate-authority/
 * To inspect certs that were generated: openssl x509 -text -noout -in symmetric.crt
 */
function createSelfSignedCert(options) {
  const dir =
    (options && options.home) ||
    process.env.SYMMETRIC_HOME ||
    path.join(os.homedir(), '.symmetric');
  const caKey = path.join(dir, 'symmetric_ca.key');
  const caCert = path.join(dir, 'symmetric_ca.crt');
  const caExt = path.join(dir, 'symmetric_ca.ext');
  const key = path.join(dir, 'symmetric.key');
  const csr = path.join(dir, 'symmetric.csr');
  const cert = path.join(dir, 'symmetric.crt');
  const ext = path.join(dir, 'symmetric.ext');
  const altDomainNames = ['localhost'];
  const altIPs = ['127.0.0.1'];
  const addDomain = domain => {
    if (altDomainNames.indexOf(domain) === -1) altDomainNames.push(domain);
  };
  const addIP = ip => {
    if (altIPs.indexOf(ip) === -1) altIPs.push(ip);
  };

  if (options && options.additionalDomains) options.additionalDomains.forEach(addDomain);
  if (options && options.additionalIPs) options.additionalIPs.forEach(addIP);

  try {
    fs.mkdirSync(dir);
  } catch (err) {}

  if (!fs.existsSync(caKey) || !fs.existsSync(caCert)) {
    // Create the ext config for setting CA bits to true in the cert
    // This is required so that Android will install the cert as "Trusted credentials"
    const caExtData = `
    [ req ]
    req_extensions=v3_ca
    distinguished_name=req_distinguished_name

    [ req_distinguished_name ]

    [ v3_ca ]
    basicConstraints=CA:true
    `.replace(/ {2}/g, '');
    fs.writeFileSync(caExt, caExtData);

    // Generate a self-signed root cert
    console.log(keymoji, 'Generating self-signed root cert...');
    childProcess.execSync(
      `${opensslCA} -keyout ${caKey} -out ${caCert} -config ${caExt} -extensions v3_ca -subj ${caSubj}`,
    );

    // Add the CA cert to the keychain
    console.log(keymoji, 'Adding to keychain...');
    try {
      childProcess.execSync(
        `security add-trusted-cert -k ~/Library/Keychains/login.keychain ${caCert}`,
      );
    } catch (err) {
      console.log('Skipping - security command not available.');
      console.log(
        `NOTE: Before proceeding please be sure to add ${caCert} as a trusted root cert to your system.`,
      );
    }
  }

  // Gather all of the possible alt names
  try {
    altDomainNames.push(
      childProcess
        .execSync('uname -n')
        .toString()
        .trim(),
    );
  } catch (err) {}
  try {
    // Get LAN addresses
    if (process.platform !== 'darwin') {
      childProcess
        .execSync('hostname --all-ip-addresses || hostname -I')
        .toString()
        .trim()
        .split(' ')
        .forEach(addIP);
    } else {
      childProcess
        .execSync('ifconfig | grep "inet " | awk {\'print $2\'}')
        .toString()
        .trim()
        .split('\n')
        .forEach(addIP);
    }
  } catch (err) {}
  try {
    // Get public IP address
    addIP(
      childProcess
        .execSync('dig +short myip.opendns.com @resolver1.opendns.com')
        .toString()
        .trim(),
    );
  } catch (err) {}

  // Create the ext alt-names and compare to the alt-names of the existing cert
  const extData = `
    subjectAltName = @alt_names

    [ alt_names ]
    ${altDomainNames.map((domain, index) => `DNS.${index + 1} = ${domain}`).join('\n')}
    ${altIPs.map((ip, index) => `IP.${index + 1} = ${ip}`).join('\n')}
  `.replace(/ {2}/g, '');
  if (
    fs.existsSync(ext) &&
    fs.readFileSync(ext).toString() === extData &&
    fs.existsSync(key) &&
    fs.existsSync(cert)
  ) {
    console.log(keymoji, 'Using existing SSL cert and key...');
  } else {
    console.log(keymoji, 'Creating new SSL cert and key...');
    // Save the ext file
    fs.writeFileSync(ext, extData);
    // Generate a cert signing request
    childProcess.execSync(`${opensslReq} -keyout ${key} -out ${csr} -subj ${subj}`);
    // Sign the request
    childProcess.execSync(
      `${opensslSign} -CA ${caCert} -CAkey ${caKey} -CAcreateserial -in ${csr} -out ${cert} -extfile ${ext}`,
    );
  }

  return {
    key,
    cert,
    caKey,
    caCert,
  };
}

module.exports = createSelfSignedCert;
