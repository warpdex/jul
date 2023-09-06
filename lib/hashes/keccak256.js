/*!
 * keccak256.js - Keccak-256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak = require('./keccak');

/**
 * Keccak256
 */

class Keccak256 extends Keccak {
  constructor() {
    super();
  }

  init() {
    return super.init(256);
  }

  final() {
    return super.final(0x01, null);
  }

  static hash() {
    return new Keccak256();
  }

  static digest(data) {
    return super.digest(data, 256, 0x01, null);
  }
}

/*
 * Expose
 */

module.exports = Keccak256;
