/*!
 * hash256.js - Hash256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

'use strict';

const SHA256 = require('./sha256');

/**
 * Hash256
 */

class Hash256 {
  constructor() {
    this.ctx = new SHA256();
  }

  init() {
    this.ctx.init();
    return this;
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  final() {
    const out = Buffer.alloc(32);

    this.ctx._final(out);
    this.ctx.init();
    this.ctx.update(out);
    this.ctx._final(out);

    return out;
  }

  static hash() {
    return new Hash256();
  }

  static digest(data) {
    return Hash256.ctx.init().update(data).final();
  }
}

/*
 * Static
 */

Hash256.ctx = new Hash256();

/*
 * Expose
 */

module.exports = Hash256;
