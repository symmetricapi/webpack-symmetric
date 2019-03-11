const http = require('http');
const fs = require('fs');
const path = require('path');

const keymoji = '\u{1F510} ';

function certServer(caCert) {
  const index = fs.readFileSync(path.join(__dirname, 'server.html'));
  const cert = fs.readFileSync(caCert);
  const notFound = '404 - Not Found';

  const server = http.createServer((req, res) => {
    if (req.url === '/') {
      res.writeHead(200, {
        'Content-Length': Buffer.byteLength(index),
        'Content-Type': 'text/html',
      });
      res.end(index);
    } else if (req.url === '/symmetric_ca.crt') {
      res.writeHead(200, {
        'Content-Length': Buffer.byteLength(cert),
        'Content-Type': 'application/x-x509-ca-cert',
      });
      res.end(cert);
    }
    res.writeHead(404, {
      'Content-Length': Buffer.byteLength(notFound),
      'Content-Type': 'text/plain',
    });
    res.end(notFound);
  });
  server.on('clientError', (err, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  server.listen({ host: '0.0.0.0', port: 3007 });
  console.log(keymoji, 'Running root cert install server at http://0.0.0.0:3007');
}

module.exports = certServer;
