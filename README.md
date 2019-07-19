# About

This package exposes a single function `createBackendProxy({...})` which will generate a proxy configuration and self-signed certs.

# Usage

The generated proxy configuration will do the following things:

-   Create request/response handlers that route to the backend any path starting with anything from `options.paths` or any second-level path from `options.subpaths`.
-   Reset `sessionid` cookies when switching between projects.
-   Generate a self-signed root cert and add it as trusted to your keychain. So no browser warnings should ever popup.
-   Generate a root signed cert used in the proxy, which includes standard alternate names of `localhost`, `<host>.local`, `127.0.0.1`, any other detected interface ips, and your externally facing ip.

**NOTE: SSL cert generation only happens when `webpack` is run as `webpack-dev-server`**

## The root CA cert

In order to avoid warnings in your browser make sure that the root CA cert is installed as a trusted root cert in your system after the first time running webpack server. This only needs to be done once and not repeated for every project. On OSX this is done automatically but look for a console message on other systems.

### Installing the root CA cert on other devices

See `certServer` setting below and follow the instructions on the installation page.

## `createBackendProxy` options

The only required option is `backend`, everything else is optional.

-   `backend` - The backend origin to proxy to
-   `paths` - The first-level URL paths to match and proxy to the backend
-   `subpaths` - The second-level URL paths to match and proxy to the backend
-   `originRewrites` - Array of origins to localize as relative paths instead when found under src or href attributes in a proxied response
-   `insecure` - If true run the server as http instead of self-signed https
-   `generateCert` - If true will force the certificate to be generated outside of a `webpack-dev-server` invocations
-   `certServer` - If true will run a separate http server on port 3007 with instructions on installing the root cert on other devices
-   `ssl.additionalDomains` - Additional domain names to add as alternate names allowed with the SSL cert
-   `ssl.additionalIPs` - Additional IP addresses to add as alternate names allowed with the SSL cert
-   `ssl.home` - Root directory used to store all generated certs and keys. Defaults to `~/.symmetric`

## Environment variables

-   `CERT_SERVER=true` - Can be used instead of the `certServer` option
-   `GENERATE_CERT=true` - Can be used in place of the `generateCert` option
-   `SYMMETRIC_HOME` - Can be used instead of the `ssl.home` option

## Setting up devServer in webpack

Add the following settings to your webpack devServer configuration object to get the proxy going.

First generate a `proxy` configuration using `proxy = createBackendProxy({...})`. Within your `devServer` object:

-   Set `proxy: { '/': proxy }` for the most basic setup off the root URL path
-   If running with SSL, set `https: proxy.ssl`
-   Optionally, set `host: '0.0.0.0'` to allow any remote connection in not just from localhost, needed if running inside a VM
-   Optionally, to allow connections to mDBS `.local` hostnames, set `allowedHosts: ['localhost', '.local']`

# License

MIT
