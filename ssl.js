const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const opensslCA = 'openssl req -x509 -nodes -days 9999 -sha256 -newkey rsa:2048';
const opensslReq = 'openssl req -nodes -newkey rsa:2048';
const opensslSign = 'openssl x509 -req -days 9999 -sha256';
const caSubj = '"/C=US/ST=California/L=Berkeley/O=Symmetric/OU=Engineering/CN=Symmetric Proxy CA"';
const subj = '"/C=US/ST=California/L=Berkeley/O=Symmetric/OU=Engineering/CN=Symmetric Proxy"';

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
 */
function createSelfSignedCert(options) {
  const dir = (options && options.home) || process.env.SYMMETRIC_HOME || path.join(os.homedir(), '.symmetric');
  const caKey = path.join(dir, 'symmetric_ca.key');
  const caCert = path.join(dir, 'symmetric_ca.crt');
  const key = path.join(dir, 'symmetric.key');
  const csr = path.join(dir, 'symmetric.csr');
  const cert = path.join(dir, 'symmetric.crt');
  const ext = path.join(dir, 'symmetric.ext');
  const altDomainNames = ['localhost'];
  const altIPs = ['127.0.0.1'];
  const addDomain = (domain) => { if (altDomainNames.indexOf(domain) === -1) altDomainNames.push(domain); };
  const addIP = (ip) => { if (altIPs.indexOf(ip) === -1) altIPs.push(ip); };

  if (options && options.additionalDomains) options.additionalDomains.forEach(addDomain);
  if (options && options.additionalIPs) options.additionalIPs.forEach(addIP);

  try {
    fs.mkdirSync(dir);
  } catch (err) { }

  if (!fs.existsSync(caKey) || !fs.existsSync(caCert)) {
    // Generate a self-signed root cert
    console.log('Generating self-signed root cert...');
    child_process.execSync(`${opensslCA} -keyout ${caKey} -out ${caCert} -subj ${caSubj}`);

    // Add the CA cert to the keychain
    console.log('Adding to keychain...');
    try {
      child_process.execSync(`security add-trusted-cert -k ~/Library/Keychains/login.keychain ${caCert}`);
    } catch (err) {
      console.log('Skipping - security command not available.');
    }
  }

  // Gather all of the possible alt names
  try {
    altDomainNames.push(child_process.execSync('uname -n').toString().trim());
  } catch (err) { }
  try {
    // Get LAN addresses
    if (process.platform !== 'darwin') {
      child_process.execSync('hostname --all-ip-addresses || hostname -I').toString().trim().split(' ').forEach(addIP);
    } else {
      child_process.execSync('ifconfig | grep "inet " | awk {\'print $2\'}').toString().trim().split('\n').forEach(addIP);
    }
  } catch (err) { }
  try {
    // Get public IP address
    addIP(child_process.execSync('dig +short myip.opendns.com @resolver1.opendns.com').toString().trim());
  } catch (err) { }
  fs.writeFileSync(ext, `
    subjectAltName = @alt_names

    [ alt_names ]
    ${altDomainNames.map((domain, index) => `DNS.${index + 1} = ${domain}`).join('\n')}
    ${altIPs.map((ip, index) => `IP.${index + 1} = ${ip}`).join('\n')}
  `.replace(/  /g, ''));

  // Generate a cert signing request
  child_process.execSync(`${opensslReq} -keyout ${key} -out ${csr} -subj ${subj}`);
  // Sign the request
  child_process.execSync(`${opensslSign} -CA ${caCert} -CAkey ${caKey} -CAcreateserial -in ${csr} -out ${cert} -extfile ${ext}`);

  return {
    key,
    cert,
  };
}

module.exports = createSelfSignedCert;
