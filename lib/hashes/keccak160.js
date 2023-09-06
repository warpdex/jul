/*!
 * keccak160.js - Keccak-160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const Keccak256 = require('./keccak256');

/**
 * Keccak160
 */

class Keccak160 extends Keccak256 {
  constructor() {
    super();
  }

  init() {
    return super.init();
  }

  final() {
    return super.final().slice(12);
  }

  static hash() {
    return new Keccak160();
  }

  static digest(data) {
    return super.digest(data).slice(12);
  }
}

/*
 * Expose
 */

module.exports = Keccak160;
