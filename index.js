const fs = require('fs');
const zlib = require('zlib');
const createSelfSignedCert = require('./ssl');

const STANDARD_PATHS = [
  'api',
  'login',
  'logout',
  'auth',
  'deauth',
  'setup',
  'callback',
  'static',
  '__debug__',
];
const STANDARD_SUBPATHS = [];
const BACKEND_COOKIE = 'proxybackend';

/**
 * Create backend proxy based on a process.env object.
 * @param {Object} options - An object of options
 * @param {string} options.backend - The backend origin to proxy to
 * @param {Array} [options.paths] - The first-level URL paths to match and proxy to the backend
 * @param {Array} [options.subpaths] - The second-level URL paths to match and proxy to the backend
 * @param {Array} [options.originRewrites] - Array of origins to localize as relative paths instead when found under src or href attributes in a proxied response
 * @param {Boolean} [options.insecure] - If true, run the server as http instead of self-signed https
 * @param {Object} [options.ssl] - Options to pass into createSelfSignedCert()
 * @returns - An object appropriate to pass in with a path key of the proxy setting of devServer
 * @description
 * All options come from https://github.com/nodejitsu/node-http-proxy
 * https://github.com/chimurai/http-proxy-middleware
 *
 * With this configuration, the apiclient auth flow is:
 * 1. Navigate to local /auth
 * 2. Proxy sends request to /auth on backend
 * 3. backend detects X-Forwarded-Host and uses that to build the callback URL
 * 4. User authorizes on third-party service
 * 5. Callback comes back to local /callback because of step 3
 * 6. /callback is proxied to backend and processed
 * 7. Final redirect is then to a backend URL but proxy rewrites this as a local URL
 */
function createBackendProxy(options) {
  const debug = (process.env.DEBUG || '').indexOf('webpack') !== -1;
  const { backend, paths = [], subpaths = [], insecure, generateCert, certServer } = options;
  const backendCookieRe = new RegExp(`${BACKEND_COOKIE}=${backend};?`);
  const sessionCookieRe = /sessionid=\w+;?/;

  // Remove any slashes from the paths
  paths.forEach((path, i) => {
    paths[i] = path.replace(/\//g, '');
  });
  subpaths.forEach((subpath, i) => {
    subpaths[i] = subpath.replace(/\//g, '');
  });

  // Add the standard paths
  paths.splice(-1, 0, ...STANDARD_PATHS);
  subpaths.splice(-1, 0, ...STANDARD_SUBPATHS);

  const proxy = {
    target: backend,
    // Always set the referer to the actual backend server otherwise csrf validation will fail
    headers: { Referer: backend },
    // On 30x redirects change the host to the request host, which should include the port
    autoRewrite: true,
    logLevel: debug ? 'debug' : 'info',
    // Change the Host: header to be backend otherwise
    // security checking for csrf and allowed hosts etc. would fail
    changeOrigin: true,
    // Set X-Forwarded headers so that apiclient in backend will make correct authorization callbacks
    xfwd: true,
    // Webpack specific bypass callback
    // Use unmodified req.url with GET/HEAD requests and bypass the proxy
    bypass(req) {
      const parts = req.url.split('/');
      if (
        (req.method !== 'GET' && req.method !== 'HEAD') ||
        paths.indexOf(parts[1]) !== -1 ||
        subpaths.indexOf(parts[2]) !== -1
      ) {
        return false;
      }
      return req.url;
    },
    // If backend does not match then remove the sessionid from the proxyReq to the backend
    // NOTE: args for onProxyReq are - proxyReq (ClientRequest), req (IncomingMessage), res (ServerResponse)
    onProxyReq(proxyReq) {
      const cookies = proxyReq.getHeader('cookie');
      if (cookies && !backendCookieRe.test(cookies)) {
        proxyReq.setHeader('cookie', cookies.replace(sessionCookieRe, ''));
      }
    },
    // If backend cookie does not match or is missing then set it in the response from the backend
    // Also delete the sessionid cookie if a new one is not supplied by the backend
    // NOTE: args for onProxyRes are - proxyRes (IncomingMessage), req (IncomingMessage), res (ServerResponse)
    onProxyRes(proxyRes, req) {
      if (!backendCookieRe.test(req.headers.cookie || '')) {
        let resCookies = proxyRes.headers['set-cookie'] || [];
        if (!Array.isArray(resCookies)) resCookies = [resCookies];
        const expires = new Date();
        expires.setDate(expires.getDate() + 365);
        resCookies.push(`${BACKEND_COOKIE}=${backend}; expires=${expires.toUTCString()}; path=/`);
        if (resCookies.filter(cookie => sessionCookieRe.test(cookie)).length === 0) {
          resCookies.push(`sessionid=; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/`);
        }
        proxyRes.headers['set-cookie'] = resCookies;
      }
    },
  };

  if (insecure) {
    // 30x redirects should be changed to insecure
    proxy.protocolRewrite = 'http';
    // Remove the secure flag from all cookies so they work with insecure http locally
    const { onProxyRes } = proxy;
    proxy.onProxyRes = (proxyRes, req, res) => {
      const cookies = proxyRes.headers['set-cookie'];
      if (cookies) {
        for (let i = 0; i < cookies.length; i += 1) {
          cookies[i] = cookies[i].replace(/secure\s*$/, '');
        }
      }
      if (onProxyRes) onProxyRes.call(proxy, proxyRes, req, res);
    };
  } else {
    // Just in case of an insecure vagrant-based backend 30x redirects should be changed to secure
    proxy.protocolRewrite = 'https';
    // Create the SSL cert only when webpack is running as a dev server otherwise skip on webpack builds
    if (
      generateCert ||
      process.env.GENERATE_CERT === 'true' ||
      process.argv.find(arg => arg.includes('webpack-dev-server'))
    ) {
      const sslFiles = createSelfSignedCert(options.ssl);
      // ssl options: https://nodejs.org/api/tls.html#tls_tls_createserver_options_secureconnectionlistener
      proxy.ssl = {
        key: fs.readFileSync(sslFiles.key),
        cert: fs.readFileSync(sslFiles.cert),
      };
      if (certServer || process.env.CERT_SERVER === 'true') {
        const startServer = require('./server');
        startServer(sslFiles.caCert);
      }
    }
  }

  if (options.originRewrites && options.originRewrites.length) {
    const re = new RegExp(`${options.originRewrites.join('|')}`, 'ig');
    const { onProxyRes } = proxy;
    proxy.onProxyRes = (proxyRes, req, res) => {
      if (onProxyRes) onProxyRes.call(proxy, proxyRes, req, res);
      if (
        proxyRes.headers['content-type'] &&
        proxyRes.headers['content-type'].indexOf('text/html') !== -1
      ) {
        // Handle the data piping manually by disabling pipe()
        // Do not use selfHandleResponse options because it would disable a number of other features
        // https://github.com/nodejitsu/node-http-proxy/blob/e94d52973a26cf817a9de12d97e5ae603093f70d/lib/http-proxy/passes/web-incoming.js#L173
        let body = Buffer.alloc(0);
        proxyRes.pipe = () => {};
        proxyRes.on('data', data => {
          body = Buffer.concat([body, data]);
        });
        proxyRes.on('end', () => {
          if (res.hasHeader('content-encoding') && res.getHeader('content-encoding') === 'gzip') {
            body = zlib.gunzipSync(body);
          }
          body = body.toString().replace(re, '');
          // Remove the content-encoding as it is no longer gzip
          res.removeHeader('content-encoding');
          res.end(body);
        });
      }
    };
  }

  return proxy;
}

module.exports = { createBackendProxy };
