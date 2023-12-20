/*!
 * solidity.js - binding to emscripten libsolc
 * Copyright (c) 2022-2023, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

'use strict';

const assert = require('assert');

/*
 * Cache
 */

const cache = new WeakMap();

/**
 * Binding
 */

class Binding {
  constructor(binary) {
    assert(isBinary(binary));

    // https://github.com/ethereum/solidity/blob/develop/libsolc/libsolc.h
    this.binary = binary;
    this.license = binary.cwrap('solidity_license', 'string', []);
    this.version = binary.cwrap('solidity_version', 'string', []);
    this.alloc = binary.cwrap('solidity_alloc', 'number', ['number']);
    this.free = binary.cwrap('solidity_free', null, ['number']);
    this.compile = binary.cwrap('solidity_compile', 'string',
                                ['string', 'number', 'number']);
    this.reset = binary.cwrap('solidity_reset', null, []);
  }

  writeString(ptr, str) {
    const len = this.binary.lengthBytesUTF8(str);
    const buf = this.alloc(len + 1);

    assert(buf !== 0);

    this.binary.stringToUTF8(str, buf, len + 1);
    this.binary.setValue(ptr, buf, '*');
  }

  readString(ptr) {
    if (this.binary.UTF8ToString)
      return this.binary.UTF8ToString(ptr);

    return this.binary.Pointer_stringify(ptr);
  }

  addFunction(func, signature) {
    if (this.binary.addFunction)
      return this.binary.addFunction(func, signature);

    return this.binary.Runtime.addFunction(func, signature);
  }

  removeFunction(ptr) {
    if (this.binary.removeFunction)
      return this.binary.removeFunction(ptr);

    return this.binary.Runtime.removeFunction(ptr);
  }
}

/**
 * Solidity
 */

class Solidity {
  constructor(binary, options = {}) {
    assert(isBinary(binary));
    assert(isObject(options));

    this.binding = new Binding(binary);
    this._handler = this._handle.bind(this);
    this._handlers = {
      __proto__: null,
      'source': options.read || defaultRead,
      'smt-query': options.solve || defaultSolve
    };
  }

  license() {
    const result = this.binding.license();
    this.binding.reset();
    return result;
  }

  version() {
    const result = this.binding.version();
    this.binding.reset();
    return result;
  }

  compile(input) {
    assert(typeof input === 'string');

    const cb = this.binding.addFunction(this._handler, 'viiiii');

    let output;

    try {
      output = this.binding.compile(input, cb, 0);
    } finally {
      this.binding.removeFunction(cb);
    }

    this.binding.reset();

    return output;
  }

  _handle(context, kind_, data_, contents, error) {
    assert(context === 0);

    const handlers = this._handlers;
    const kind = this.binding.readString(kind_);
    const data = this.binding.readString(data_);

    if (!handlers[kind])
      throw new Error(`Unknown callback: ${kind}`);

    let result;

    try {
      result = handlers[kind].call(null, data);
    } catch (e) {
      this.binding.writeString(error, e.message);
      return;
    }

    this.binding.writeString(contents, result);
  }

  static from(binary, options) {
    assert(isBinary(binary));

    const cached = cache.get(binary);

    if (cached && cached[1] === options)
      return cached[0];

    const compiler = new Solidity(binary, options);

    cache.set(binary, [compiler, options]);

    return compiler;
  }
}

/*
 * Helpers
 */

function defaultRead(path) {
  throw new Error('File I/O not supported');
}

function defaultSolve(data) {
  throw new Error('SMT solver not supported');
}

function isObject(obj) {
  return obj && typeof obj === 'object';
}

function isBinary(obj) {
  return obj && typeof obj.cwrap === 'function';
}

/*
 * Expose
 */

module.exports = Solidity;
