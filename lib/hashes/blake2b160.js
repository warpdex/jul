/*!
 * blake2b160.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const BLAKE2b = require('./blake2b');

/**
 * BLAKE2b160
 */

class BLAKE2b160 extends BLAKE2b {
  constructor() {
    super();
  }

  init(key) {
    return super.init(20, key);
  }

  static hash() {
    return new BLAKE2b160();
  }

  static digest(data, key) {
    return super.digest(data, 20, key);
  }
}

/*
 * Expose
 */

module.exports = BLAKE2b160;
