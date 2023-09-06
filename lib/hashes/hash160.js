/*!
 * hash160.js - Hash160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

'use strict';

const SHA256 = require('./sha256');
const RIPEMD160 = require('./ripemd160');

/*
 * Constants
 */

const rmd = new RIPEMD160();

/**
 * Hash160
 */

class Hash160 {
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

    rmd.init();
    rmd.update(out);
    rmd._final(out);

    return out.slice(0, 20);
  }

  static hash() {
    return new Hash160();
  }

  static digest(data) {
    return Hash160.ctx.init().update(data).final();
  }
}

/*
 * Static
 */

Hash160.ctx = new Hash160();

/*
 * Expose
 */

module.exports = Hash160;
