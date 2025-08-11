#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const info = require('../etc/solc.json');

const cwd = process.cwd();
const vendor = path.join(__dirname, '..', 'vendor');
const dest = path.join(vendor, info.name);

const log = (...args) => console.log(...args);
const write = x => process.stdout.write(x);

let needsEOL = false;

const abort = (...args) => {
  if (needsEOL)
    write('\n');
  console.error(...args);
  console.error('Aborting.');
  process.exit(1);
};

const onError = (err) => {
  if (needsEOL)
    write('\n');
  console.error('%s', err.stack);
  process.exit(1);
};

// Create vendor directory if it doesn't exist
if (!fs.existsSync(vendor)) {
  log('Creating vendor directory: %s', path.relative(cwd, vendor));
  fs.mkdirSync(vendor, { recursive: true });
}

for (const name of fs.readdirSync(vendor)) {
  if (name.startsWith('soljson-') && name !== info.name) {
    const file = path.join(vendor, name);
    log('Removing %s', path.relative(cwd, file));
    fs.unlinkSync(file);
  }
}

if (fs.existsSync(dest)) {
  const data = fs.readFileSync(dest);
  const hash = crypto.createHash('sha256')
                     .update(data)
                     .digest('hex');

  if (hash === info.hash) {
    log('%s already present.', path.relative(cwd, dest));
    log('Checksum: %s', hash);
    return;
  }

  log('Invalid checksum for local file.');
  log('%s != %s', hash, info.hash);
  log('Removing %s', path.relative(cwd, dest));

  fs.unlinkSync(dest);
}

const req = https.request({
  method: 'GET',
  host: 'binaries.soliditylang.org',
  port: 443,
  path: `/bin/${info.name}`,
  headers: {
    'Accept': 'text/javascript'
  },
  agent: false
});

req.on('error', onError);

req.on('response', (res) => {
  const hdr = res.headers;
  const type = (hdr['content-type'] || '').split(';')[0];

  log('Received response.');

  if (hdr.location)
    abort('Server tried to redirect us to: %s', hdr.location);

  if (res.statusCode !== 200)
    abort('Server returned status code: %d', res.statusCode);

  if (type !== 'text/javascript' && type !== 'application/javascript')
    abort('Server returned invalid mime type: %s', type);

  const length = hdr['content-length'] >>> 0;
  const chunks = [];

  let total = 0;

  res.on('error', onError);

  res.on('data', (chunk) => {
    total += chunk.length;

    if (total > (50 << 20))
      abort('Too much data buffered.');

    if (length && process.stdout.isTTY) {
      const progress = (total / length) * 100;
      write('\x1b[0G\x1b[K');
      write(`Progress: ${progress.toFixed(2)}%`);
      needsEOL = true;
    }

    chunks.push(chunk);
  });

  res.on('end', () => {
    if (needsEOL) {
      needsEOL = false;
      write('\n');
    }

    const body = Buffer.concat(chunks);
    const hash = crypto.createHash('sha256')
                       .update(body)
                       .digest('hex');

    if (hash !== info.hash)
      abort('Invalid checksum: %s != %s', hash, info.hash);

    log('Complete.');
    log('Filename: %s', path.relative(cwd, dest));
    log('Checksum: %s', hash);

    fs.writeFileSync(dest, body);
  });
});

req.setTimeout(10000, () => {
  abort('Request timed out.');
});

req.on('finish', () => {
  log('Downloading %s', info.name);
});

req.end();
