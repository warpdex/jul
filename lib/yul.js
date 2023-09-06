/*!
 * yul.js - yul parser and transformer
 * Copyright (c) 2022-2023, Christopher Jeffrey (MIT License).
 * https://github.com/chjj
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const blake2b160 = require('bcrypto/lib/blake2b160');
const blake2b256 = require('bcrypto/lib/blake2b256');
const hash160 = require('bcrypto/lib/hash160');
const hash256 = require('bcrypto/lib/hash256');
const keccak256 = require('bcrypto/lib/keccak256');
const ripemd160 = require('bcrypto/lib/ripemd160');
const sha256 = require('bcrypto/lib/sha256');

/*
 * Constants
 */

const SUPPORT_FILE = path.resolve(__dirname, 'support.yul');
const BUILTINS_FILE = path.resolve(__dirname, 'builtins.yul');
const U256_MAX = (1n << 256n) - 1n;
const I256_SIGN = 1n << 255n;
const DEBUG_SIG = /* keccak256("Debug(bytes32, ...)") */
  '0x30c3b94e65122be6598eeacd112efc45d51b6797db32bf9b1a32af0ea1c4f604';

const hardforks = {
  __proto__: null,
  homestead: 201603, // Mar 2016
  tangerineWhistle: 201610, // Oct 2016
  spuriousDragon: 201611, // Nov 2016
  byzantium: 201710, // Oct 2017
  constantinople: 201902, // Feb 2019
  petersburg: 201903, // Mar 2019
  istanbul: 201912, // Dec 2019
  berlin: 202104, // Apr 2021
  london: 202108, // Aug 2021
  paris: 202209, // Sep 2022
  shanghai: 202304, // Apr 2023
  cancun: 300000 // TBD
};

// Function name blacklist.
const blacklist = new Set([
  'include',
  'struct',
  'method',
  'event',
  'error'
]);

/*
 * Parser
 */

class Parser {
  constructor(input, filename) {
    [this.code, this.comments] = stripComments(input);
    this.input = this.code;
    this.filename = filename ? path.resolve(filename) : '<stdin>';
    this.root = filename ? path.dirname(this.filename) : process.cwd();
    this.line = 0;
    this.start = 0;
    this.pos = 0;
    this.eatSpace();
  }

  assert(value, msg = 'Parse error') {
    if (!value) {
      const file = path.relative(process.cwd(), this.filename);
      const line = this.line + 1;
      const pos = this.pos - this.start;
      const indent = ' '.repeat(pos);

      throw new SyntaxError(`${msg} (${file}:${line}:${pos})\n\n` +
                            `${this.currentLine()}\n` +
                            `${indent}^`);
    }

    return value;
  }

  comment(line) {
    return this.comments.get(line) || null;
  }

  parse() {
    // Root = Statements
    const root = this.Statements();

    this.assert(this.input.length === 0);

    return root;
  }

  Statements() {
    // Statements = Statement*
    const nodes = [];

    for (;;) {
      const node = this.Statement();

      if (!node)
        break;

      nodes.push(node);
    }

    return {
      type: 'Root',
      nodes
    };
  }

  Statement() {
    // Statement =
    //     Block |
    //     FunctionDefinition |
    //     VariableDeclaration |
    //     Assignment |
    //     If |
    //     Expression |
    //     Switch |
    //     ForLoop |
    //     BreakContinue |
    //     Leave
    // Makes more sense to put Expression last.
    return this.Pragma()
        || this.Fold()
        || this.IncludeCall()
        || this.Enum()
        || this.StructDefinition()
        || this.Interface()
        || this.Contract()
        || this.ObjectBlock()
        || this.CodeBlock()
        || this.ConstructorDefinition()
        || this.DataValue()
        || this.Block()
        || this.Macro()
        || this.FunctionDefinition()
        || this.MethodDefinition()
        || this.EventDeclaration()
        || this.ErrorDeclaration()
        || this.VariableDeclaration()
        || this.ConstDeclaration()
        || this.MemberAssignment()
        || this.Assignment()
        || this.If()
        || this.Switch()
        || this.ForLoop()
        || this.While()
        || this.DoWhile()
        || this.BreakContinue()
        || this.Leave()
        || this.Emit()
        || this.Throw()
        || this.Expression();
  }

  Pragma() {
    // Pragma =
    //     'pragma' Identifier StringLiteral
    if (!this.keyword('pragma'))
      return null;

    const name = this.assert(this.Identifier());
    const string = this.assert(this.StringLiteral());
    const value = JSON.parse(string.value);

    switch (name.value) {
      case 'license':
        this.assert(/^[\-\.0-9A-Za-z]+$/.test(value));
        break;
      case 'solc':
      case 'yulc':
        this.assert(semver.test(value));
        break;
      case 'evm':
        this.assert(hardforks[value] != null);
        break;
      case 'optimize':
      case 'deoptimize':
        this.assert(/^[A-Za-z]+$/.test(value));
        break;
      case 'lock':
        this.assert(/^0x[0-9A-Fa-f]{1,64}$/.test(value));
        break;
      default:
        this.assert(0, `Unknown pragma: ${name.value}`);
        break;
    }

    return {
      type: 'Pragma',
      name: name.value,
      value
    };
  }

  Fold() {
    // Fold =
    //     '@if' Expression '{' Statements '}'
    //     ( 'elif' '{' Statements '}' )?
    //     ( 'else' '{' Statements '}' )?
    if (!this.keyword('@if'))
      return null;

    const expr = this.assert(this.Expression());
    const block = this.StatementBlock();
    const branches = [];

    while (this.keyword('elif')) {
      const expr = this.assert(this.Expression());
      const block = this.StatementBlock();

      branches.push([expr, block]);
    }

    let otherwise = null;

    if (this.keyword('else'))
      otherwise = this.StatementBlock();

    return {
      type: 'Fold',
      expr,
      block,
      branches,
      otherwise
    };
  }

  StatementBlock() {
    this.expect('{');

    const block = this.Statements();

    this.expect('}');

    return block;
  }

  IncludeCall() {
    // IncludeCall = 'include(' StringLiteral ')'
    if (!this.match(/^include\s*\(/))
      return null;

    const name = this.assert(this.StringLiteral());

    this.expect(')');

    return {
      type: 'IncludeCall',
      root: this.root,
      name: JSON.parse(name.value)
    };
  }

  Enum() {
    // Enum = 'enum' Identifier? '{' ( Identifier ( ':=' NumberLiteral )? )* '}'
    if (!this.match(/^enum(?=(?:\s+[\w$.]+)?\s*\{)/))
      return null;

    const name = this.Identifier();
    const members = [];

    this.expect('{');

    while (!this.peek('}')) {
      const name = this.assert(this.Identifier());

      let expr = null;

      if (this.consume(':='))
        expr = this.assert(this.Expression());

      members.push([name, expr]);
    }

    this.expect('}');

    return {
      type: 'Enum',
      name,
      members
    };
  }

  StructDefinition() {
    // StructDefinition = 'struct' Identifier '{' StructMember+ '}'
    if (!this.match(/^struct\s+(?=[\w$.]+\s*\{)/))
      return null;

    const name = this.assert(this.Identifier());
    const members = [];

    this.expect('{');

    while (!this.peek('}'))
      members.push(this.StructMember());

    this.assert(members.length > 0);
    this.expect('}');

    return {
      type: 'StructDefinition',
      name,
      members
    };
  }

  StructMember() {
    // StructMember = TypeName ( '+' | ( Identifier ( ':=' Literal )? ) )
    const kind = this.assert(this.TypeName());

    let name = Identifier('+');
    let value = Literal(0);

    if (!this.consume('+')) {
      name = this.assert(this.Identifier());

      if (this.consume(':='))
        value = this.assert(this.MaybeLiteral());
    }

    return {
      type: 'StructMember',
      kind,
      name,
      value
    };
  }

  Interface() {
    // Interface =
    // 'interface' Identifier '{' ConstructorDeclaration? MethodDeclaration* '}'
    const {line} = this;

    if (!this.match(/^interface(?=\s+[a-zA-Z_$][\w$.]*\s*{)/))
      return null;

    const name = this.assert(this.Identifier());
    const decls = [];

    this.assert(!name.value.includes('.'));

    this.expect('{');

    const ctor = this.ConstructorDeclaration();

    while (!this.peek('}')) {
      const decl = this.assert(this.MethodDeclaration());

      decls.push(decl);
    }

    this.expect('}');

    return {
      type: 'Interface',
      name,
      ctor,
      decls,
      comment: this.comment(line)
    };
  }

  Contract() {
    // Contract =
    //     'contract' Identifier ( 'optimize' )? Block
    const {line} = this;

    if (!this.match(/^contract(?=(?:\s+[a-zA-Z_$][\w$.]*)+\s*{)/))
      return null;

    const name = this.assert(this.Identifier());

    this.assert(!name.value.includes('.'));

    let modifier = null;

    if (this.keyword('optimize'))
      modifier = 'optimize';

    const block = this.assert(this.Block());

    return {
      type: 'Contract',
      name,
      modifier,
      block,
      comment: this.comment(line)
    };
  }

  ObjectBlock() {
    // ObjectBlock =
    //     'object' StringLiteral '{' CodeBlock ( ObjectBlock | DataValue )* '}'
    const {line} = this;

    if (!this.match(/^object(?=\s*")/))
      return null;

    const name = this.assert(this.StringLiteral());
    const block = this.assert(this.Block());

    return {
      type: 'ObjectBlock',
      name: JSON.parse(name.value),
      block,
      comment: this.comment(line)
    };
  }

  CodeBlock() {
    // CodeBlock = 'code' Block
    if (!this.match(/^code(?=\s*{)/))
      return null;

    const block = this.assert(this.Block());

    return {
      type: 'CodeBlock',
      block
    };
  }

  Constructor(decl) {
    // ConstructorDeclaration =
    //     'constructor' MethodParams Mutability?
    // ConstructorDefinition = ConstructorDeclaration ( 'unchecked' )? Block
    const {line} = this;

    if (!this.match(/^constructor(?=\s*\()/))
      return null;

    const params = this.MethodParams();

    let mutability = null;

    if (this.keyword('payable'))
      mutability = 'payable';

    if (decl) {
      return {
        type: 'ConstructorDeclaration',
        params,
        mutability,
        modifier: null,
        block: null,
        comment: this.comment(line)
      };
    }

    let modifier = null;

    if (this.keyword('unchecked'))
      modifier = 'unchecked';

    const block = this.assert(this.Block());

    return {
      type: 'ConstructorDefinition',
      params,
      mutability,
      modifier,
      block,
      comment: this.comment(line)
    };
  }

  ConstructorDeclaration() {
    return this.Constructor(true);
  }

  ConstructorDefinition() {
    return this.Constructor(false);
  }

  DataValue() {
    // DataValue = 'data' StringLiteral ( HexLiteral | StringLiteral )
    if (!this.match(/^data(?=\s*")/))
      return null;

    const name = this.assert(this.StringLiteral());
    const data = this.assert(this.HexLiteral() || this.StringLiteral());

    return {
      type: 'DataValue',
      name: JSON.parse(name.value),
      value: {
        type: 'Literal',
        subtype: data.type,
        kind: null,
        value: data.value
      }
    };
  }

  Block() {
    // Block = '{' Statement* '}'
    if (!this.consume('{'))
      return null;

    const body = [];

    for (;;) {
      const stmt = this.Statement();

      if (!stmt)
        break;

      body.push(stmt);
    }

    this.expect('}');

    return {
      type: 'Block',
      body
    };
  }

  Macro() {
    // Macro = MacroConstant | MacroDefinition
    // MacroConstant =
    //     'macro' Identifier ':=' Expression
    // MacroDefinition =
    //     'macro' Identifier '(' IdentifierList? ')'
    //     ( ':=' Expression | Block )
    if (!this.keyword('macro'))
      return null;

    const name = this.assert(this.Identifier());

    if (this.consume(':=')) {
      const expr = this.assert(this.Expression());

      return {
        type: 'MacroConstant',
        name: name.value,
        expr
      };
    }

    this.expect('(');

    let params = IdentifierList();

    if (!this.peek(')'))
      params = this.assert(this.IdentifierList());

    this.expect(')');

    let block = null;

    if (this.consume(':=')) {
      const expr = this.assert(this.Expression());

      block = Block([expr]);
    } else {
      block = this.assert(this.Block());
    }

    return {
      type: 'MacroDefinition',
      name: name.value,
      params: params.items.map(n => n.value),
      block
    };
  }

  FunctionDefinition() {
    // FunctionDefinition =
    //     'function' Identifier '(' TypedIdentifierList? ')'
    //     ( 'noinline' )? ( '->' TypedIdentifierList )? Block
    if (!this.keyword('function'))
      return null;

    const name = this.assert(this.Identifier());

    this.assert(!blacklist.has(name.value));

    this.expect('(');

    let params = TypedIdentifierList();

    if (!this.peek(')'))
      params = this.assert(this.TypedIdentifierList());

    this.expect(')');

    let modifier = null;

    if (this.keyword('noinline'))
      modifier = 'noinline';

    let returns = TypedIdentifierList();

    if (this.consume('->'))
      returns = this.assert(this.TypedIdentifierList());

    const block = this.assert(this.Block());

    return {
      type: 'FunctionDefinition',
      name,
      params,
      modifier,
      returns,
      block,
      builtin: false
    };
  }

  Method(decl) {
    // Visibility = ( 'internal' | 'external' | 'private' | 'public' )
    // Mutability = ( 'pure' | 'view' | 'payable' )
    // Modifier = ( 'locked' )
    // Returns = 'returns' MethodParams
    // MethodDeclaration =
    //     'method' Identifier MethodParams
    //      Visibility? Mutability? Modifier? Returns?
    // MethodDefinition = MethodDeclaration Block
    const {line} = this;

    if (!this.keyword('method'))
      return null;

    const name = this.assert(this.Identifier());

    this.assert(!name.value.includes('.'));

    const params = this.MethodParams();

    // Visibility.
    let visibility = null;

    if (this.keyword('internal'))
      this.assert(0);
    else if (this.keyword('external'))
      visibility = 'external';
    else if (this.keyword('private'))
      this.assert(0);
    else if (this.keyword('public'))
      visibility = 'public';

    // Mutability.
    let mutability = null;

    if (this.keyword('pure'))
      mutability = 'pure';
    else if (this.keyword('view'))
      mutability = 'view';
    else if (this.keyword('payable'))
      mutability = 'payable';

    // Modifier.
    let modifier = null;

    if (!decl) {
      if (this.keyword('locked'))
        modifier = 'locked';
    }

    // Returns.
    let returns = MethodParams();

    if (this.keyword('returns'))
      returns = this.MethodParams();

    if (decl) {
      return {
        type: 'MethodDeclaration',
        name,
        params,
        visibility,
        mutability,
        modifier,
        returns,
        block: null,
        comment: this.comment(line)
      };
    }

    const block = this.assert(this.Block());

    return {
      type: 'MethodDefinition',
      name,
      params,
      visibility,
      mutability,
      modifier,
      returns,
      block,
      comment: this.comment(line)
    };
  }

  MethodDeclaration() {
    return this.Method(true);
  }

  MethodDefinition() {
    return this.Method(false);
  }

  MethodParams() {
    // MethodParamsList =
    //     ABIType ( Identifier )? ( ',' ABIType ( Identifier )? )*
    // MethodParams = '(' MethodParamsList? ')'
    const items = [];

    this.expect('(');

    if (!this.peek(')')) {
      do {
        const type = this.assert(this.ABIType());
        const name = this.Identifier();

        items.push([type, name]);
      } while (this.consume(','));
    }

    this.expect(')');

    return {
      type: 'MethodParams',
      items
    };
  }

  EventDeclaration() {
    // EventDeclaration =
    //     'event' Identifier EventParams
    //     ( 'anonymous' )? ( 'packed' )?
    //     ( 'inline' | 'noinline' )?
    const {line} = this;

    if (!this.keyword('event'))
      return null;

    const name = this.assert(this.Identifier());
    const params = this.EventParams();
    const anonymous = this.keyword('anonymous');
    const packed = this.keyword('packed');

    // Modifier.
    let modifier = null;

    if (this.keyword('inline'))
      modifier = 'inline';
    else if (this.keyword('noinline'))
      modifier = 'noinline';

    return {
      type: 'EventDeclaration',
      name,
      params,
      anonymous,
      packed,
      modifier,
      comment: this.comment(line)
    };
  }

  EventParams() {
    // EventParamsList =
    //     ABIType ( 'indexed' )? ( Identifier )?
    //     ( ',' ABIType ( 'indexed' )? ( Identifier )? )*
    // EventParams = '(' EventParamsList? ')'
    const items = [];

    this.expect('(');

    if (!this.peek(')')) {
      let total = 0;

      do {
        const type = this.assert(this.ABIType());
        const indexed = this.keyword('indexed');
        const name = this.Identifier();

        items.push([type, name, indexed]);

        total += (indexed | 0);

        this.assert(total <= 4);
      } while (this.consume(','));
    }

    this.expect(')');

    return {
      type: 'EventParams',
      items
    };
  }

  ErrorDeclaration() {
    // ErrorDeclaration =
    //     'error' Identifier MethodParams
    const {line} = this;

    if (!this.keyword('error'))
      return null;

    const name = this.assert(this.Identifier());
    const params = this.MethodParams();

    return {
      type: 'ErrorDeclaration',
      name,
      params,
      comment: this.comment(line)
    };
  }

  ABIType() {
    // https://docs.soliditylang.org/en/v0.8.16/abi-spec.html#types
    // ABIType = [a-z]+ ( [0-9]{1,3} ( 'x' [0-9]{1,2} )? )? ( '[]' )?
    const parts = this.parts(/^([a-z]+)(\d{1,3})?(\[\])?/);

    if (!parts)
      return null;

    const [value, base, digits, brackets] = parts;

    let width = 0;
    let array = false;

    switch (base) {
      case 'uint':
      case 'int': { // Left-padded
        width = Number(digits || 256);
        array = Boolean(brackets);
        this.assert(width > 0 && (width & 7) === 0);
        break;
      }
      case 'address': { // Left-padded (uint160)
        this.assert(!digits);
        width = 160;
        array = Boolean(brackets);
        break;
      }
      case 'bool': { // Left-padded (uint8)
        this.assert(!digits);
        width = 1;
        array = Boolean(brackets);
        break;
      }
      case 'fixed':
      case 'ufixed': {
        this.assert(0, 'Fixed-point not supported');
        break;
      }
      case 'bytes': { // Right-padded
        if (digits) {
          width = Number(digits) * 8;
          array = Boolean(brackets);
          this.assert(width > 0);
        } else {
          this.assert(!brackets); // Possible, but we don't want to handle.
          width = 0;
          array = true;
        }
        break;
      }
      case 'string': { // Right-padded
        this.assert(!digits);
        this.assert(!brackets); // Possible, but we don't want to handle.
        width = 0;
        array = true;
        break;
      }
      case 'function': { // Right-padded (bytes24)
        this.assert(!digits);
        width = 192;
        array = Boolean(brackets);
        break;
      }
      default: {
        this.assert(0, `Invalid ABI type (${value})`);
        break;
      }
    }

    this.assert(width <= 256);

    return {
      type: 'ABIType',
      value,
      base,
      width,
      array
    };
  }

  VariableDeclaration() {
    // VariableDeclaration =
    //     'let' TypedIdentifierList ( ':=' Expression )?
    if (!this.keyword('let'))
      return null;

    const vars = this.assert(this.TypedIdentifierList());

    let expr = null;

    if (this.consume(':='))
      expr = this.assert(this.Expression());

    return {
      type: 'VariableDeclaration',
      vars,
      expr
    };
  }

  ConstDeclaration() {
    // ConstDeclaration =
    //     'const' Identifier ( '()' )? ':=' Expression
    if (!this.keyword('const'))
      return null;

    const name = this.assert(this.Identifier());
    const wrap = this.consume('()');

    this.expect(':=');

    const expr = this.assert(this.Expression());

    return {
      type: 'ConstDeclaration',
      name,
      expr,
      wrap
    };
  }

  TypeName(name = null) {
    // TypeName = Identifier
    if (name && this.consume('@'))
      return name;
    return this.Identifier();
  }

  TypedIdentifierList() {
    // TypedIdentifierList =
    //     Identifier ( ':' TypeName )? ( ',' Identifier ( ':' TypeName )? )*
    const items = [];

    do {
      const name = this.Identifier();

      if (!name) {
        this.assert(items.length === 0);
        return null;
      }

      let type = null;

      if (!this.peek(':=') && this.consume(':'))
        type = this.assert(this.TypeName(name));

      items.push([name, type]);
    } while (this.consume(','));

    return {
      type: 'TypedIdentifierList',
      items
    };
  }

  MemberAssignment() {
    // MemberAssignment =
    //     MemberIdentifier ':=' Expression
    const saved = this.save();
    const lhs = this.MemberIdentifier();

    if (!lhs)
      return null;

    const match = this.match(/^[:|]=/);

    if (!match) {
      this.restore(saved);
      return null;
    }

    const rhs = this.assert(this.Expression());

    return {
      type: 'MemberAssignment',
      or: match[0] === '|',
      lhs,
      rhs
    };
  }

  Assignment() {
    // Assignment =
    //     IdentifierList ':=' Expression
    const saved = this.save();
    const lhs = this.IdentifierList();

    if (!lhs)
      return null;

    if (!this.consume(':=')) {
      this.restore(saved);
      return null;
    }

    const rhs = this.assert(this.Expression());

    return {
      type: 'Assignment',
      lhs,
      rhs
    };
  }

  IdentifierList() {
    // IdentifierList = Identifier ( ',' Identifier)*
    const items = [];

    do {
      const name = this.Identifier();

      if (!name) {
        this.assert(items.length === 0);
        return null;
      }

      items.push(name);
    } while (this.consume(','));

    return {
      type: 'IdentifierList',
      items
    };
  }

  If() {
    // If =
    //     'if' Expression Block ( 'elif' Expression Block )* ( 'else' Block )?
    if (!this.keyword('if'))
      return null;

    const expr = this.assert(this.Expression());
    const block = this.assert(this.Block());
    const branches = [];

    while (this.keyword('elif')) {
      const expr = this.assert(this.Expression());
      const block = this.assert(this.Block());

      branches.push([expr, block]);
    }

    let otherwise = null;

    if (this.keyword('else'))
      otherwise = this.assert(this.Block());

    return {
      type: 'If',
      expr,
      block,
      branches,
      otherwise
    };
  }

  Switch() {
    // Switch =
    //     'switch' Expression ( '{' )? ( Case+ Default? | Default ) ( '}' )?
    if (!this.keyword('switch'))
      return null;

    const expr = this.assert(this.Expression());
    const cases = [];

    let def = null;

    // Extension: optional brace.
    const brace = this.consume('{');

    for (;;) {
      const case_ = this.Case();

      if (!case_)
        break;

      cases.push(case_);
    }

    def = this.Default();

    if (brace)
      this.expect('}');

    this.assert(cases.length > 0 || def);

    return {
      type: 'Switch',
      expr,
      cases,
      def
    };
  }

  Case() {
    // Case =
    //     'case' Literal Block
    if (!this.keyword('case'))
      return null;

    const value = this.assert(this.MethodSignature() || this.MaybeLiteral());
    const block = this.assert(this.Block());

    return {
      type: 'Case',
      value,
      block
    };
  }

  Default() {
    // Default =
    //     'default' Block
    if (!this.keyword('default'))
      return null;

    const block = this.assert(this.Block());

    return {
      type: 'Default',
      block
    };
  }

  MethodSignature() {
    // MethodSignature = 'method' '(' Identifier MethodParams? ')'
    if (!this.match(/^method\s*\(/))
      return null;

    const name = this.assert(this.Identifier());

    let params = null;

    if (this.peek('('))
      params = this.MethodParams();

    this.expect(')');

    return {
      type: 'MethodSignature',
      name,
      params
    };
  }

  EventSignature() {
    // EventSignature = 'event' '(' Identifier EventParams? ')'
    if (!this.match(/^event\s*\(/))
      return null;

    const name = this.assert(this.Identifier());

    let params = null;

    if (this.peek('('))
      params = this.EventParams();

    this.expect(')');

    return {
      type: 'EventSignature',
      name,
      params
    };
  }

  ErrorSignature() {
    // ErrorSignature = 'error' '(' Identifier MethodParams? ')'
    if (!this.match(/^error\s*\(/))
      return null;

    const name = this.assert(this.Identifier());

    let params = null;

    if (this.peek('('))
      params = this.MethodParams();

    this.expect(')');

    return {
      type: 'ErrorSignature',
      name,
      params
    };
  }

  MaybeLiteral() {
    // MaybeLiteral = Literal | Identifier
    // Should be a Literal, but we might have a const here.
    return this.Literal() || this.Identifier(true);
  }

  ForLoop() {
    // ForLoop =
    //     'for' Block Expression Block Block
    if (!this.keyword('for'))
      return null;

    return {
      type: 'ForLoop',
      init: this.assert(this.Block()),
      test: this.assert(this.Expression()),
      update: this.assert(this.Block()),
      block: this.assert(this.Block())
    };
  }

  While() {
    // While =
    //     'while' Expression Block
    if (!this.keyword('while'))
      return null;

    return {
      type: 'While',
      test: this.assert(this.Expression()),
      block: this.assert(this.Block())
    };
  }

  DoWhile() {
    // DoWhile =
    //     'do' Block 'while' Expression
    if (!this.match(/^do(?=\s*\{)/))
      return null;

    const block = this.assert(this.Block());

    this.assert(this.keyword('while'));

    const test = this.assert(this.Expression());

    return {
      type: 'DoWhile',
      test,
      block
    };
  }

  BreakContinue() {
    // BreakContinue =
    //     'break' | 'continue'
    if (this.keyword('break')) {
      return {
        type: 'BreakContinue',
        value: 'break'
      };
    }

    if (this.keyword('continue')) {
      return {
        type: 'BreakContinue',
        value: 'continue'
      };
    }

    return null;
  }

  Leave() {
    // Leave = 'leave'
    if (!this.keyword('leave'))
      return null;

    return {
      type: 'Leave'
    };
  }

  Emit() {
    // Emit =
    //     'emit' Identifier '(' Expression ( ',' Expression )* )? ')'
    if (!this.keyword('emit'))
      return null;

    const name = this.assert(this.Identifier());

    this.expect('(');

    const offset = this.assert(this.Expression());
    const args = [];

    while (this.consume(','))
      args.push(this.assert(this.Expression()));

    this.expect(')');

    return {
      type: 'Emit',
      name,
      offset,
      args
    };
  }

  Throw() {
    // Throw =
    //     'throw' Identifier '(' ( Expression ( ',' Expression )* )? ')'
    // if (!this.match(/^revert(?=\s+[a-zA-Z_$][\w$.]*\s*\()/))
    if (!this.keyword('throw'))
      return null;

    const name = this.assert(this.Identifier());
    const args = [];

    this.expect('(');

    do {
      args.push(this.assert(this.Expression()));
    } while (this.consume(','));

    this.expect(')');

    return {
      type: 'Throw',
      name,
      offset: null,
      args
    };
  }

  Expression() {
    // Expression =
    //     FunctionCall | Identifier | Literal
    // Makes more sense to put Identifier last.
    return this.StructInitializer()
        || this.MethodSignature()
        || this.EventSignature()
        || this.ErrorSignature()
        || this.InterfaceCall()
        || this.FunctionCall()
        || this.Literal()
        || this.AnyIdentifier(true);
  }

  StructInitializer() {
    // StructInitializer =
    //     'struct' '(' Identifier ( ',' Expression )* ')'
    if (!this.match(/^struct\s*\(/))
      return null;

    const name = this.assert(this.Identifier());
    const args = [];

    while (this.consume(',')) {
      let expr = this.DefaultIdentifier();

      if (!expr)
        expr = this.assert(this.Expression());

      args.push(expr);
    }

    this.expect(')');

    return {
      type: 'StructInitializer',
      name,
      args
    };
  }

  InterfaceCall() {
    // InterfaceCall =
    //     ( 'create' | 'create2' | 'call' ) ( '?' )? Identifier
    //    '(' ( Expression ( ',' Expression )* )? ')'
    if (!this.peek(/^(?:create2?|call)\??\s+[a-zA-Z_$][\w$.]*\s*\(/))
      return null;

    const kind = this.assert(this.Identifier()).value;
    const attempt = this.consume('?');
    const ident = this.assert(this.Identifier());
    const args = [];

    let name = ident;
    let method = null;

    if (kind === 'call') {
      const parts = ident.value.split('.');

      this.assert(parts.length === 2);
      this.assert(/^[a-zA-Z_$]/.test(parts[1]));

      name = Identifier(parts[0]);
      method = Identifier(parts[1]);
    } else {
      this.assert(!ident.value.includes('.'));
      this.assert(!attempt);
    }

    this.expect('(');

    do {
      args.push(this.assert(this.Expression()));
    } while (this.consume(','));

    this.expect(')');

    return {
      type: 'InterfaceCall',
      kind,
      attempt,
      name,
      method,
      args
    };
  }

  FunctionCall() {
    // FunctionCall =
    //     Identifier '(' ( Expression ( ',' Expression )* )? ')'
    const saved = this.save();
    const name = this.Identifier();
    const args = [];

    if (!name)
      return null;

    if (!this.consume('(')) {
      this.restore(saved);
      return null;
    }

    if (!this.peek(')')) {
      do {
        args.push(this.assert(this.Expression()));
      } while (this.consume(','));
    }

    this.expect(')');

    return {
      type: 'FunctionCall',
      name,
      args,
      filename: this.filename,
      line: saved[1]
    };
  }

  Literal() {
    // Literal = (NumberLiteral |
    //            StringLiteral |
    //            TrueLiteral |
    //            FalseLiteral) ( ':' TypeName )?
    const node = this.NumberLiteral()
              || this.StringLiteral()
              || this.HexLiteral()
              || this.TrueLiteral()
              || this.FalseLiteral();

    if (!node)
      return null;

    let kind = null;

    if (this.consume(':'))
      kind = this.assert(this.TypeName());

    return {
      type: 'Literal',
      subtype: node.type,
      kind,
      value: node.value
    };
  }

  NumberLiteral() {
    // NumberLiteral = HexNumber | DecimalNumber
    return this.HexNumber() || this.DecimalNumber();
  }

  HexNumber() {
    // HexNumber = ( '-' )? '0x' [0-9a-fA-F]+
    let value = this.match(/^-?0x[0-9a-fA-F]+/);

    if (!value)
      return null;

    this.assert(value.length <= Number(value[0] === '-') + 2 + 64);

    if (value.length === 67)
      this.assert(BigInt(value) >= -I256_SIGN);

    if (value[0] === '-') {
      value = BigInt(value) & U256_MAX;
      value = '0x' + value.toString(16);
    }

    return {
      type: 'HexNumber',
      value
    };
  }

  DecimalNumber() {
    // DecimalNumber = ( '-' )? [0-9]+
    let value = this.match(/^-?[0-9]+/);

    if (!value)
      return null;

    this.assert(value.length <= 78);

    if (value.length === 78) {
      const n = BigInt(value);

      this.assert(n >= -I256_SIGN && n <= U256_MAX);
    }

    if (value[0] === '-') {
      value = BigInt(value) & U256_MAX;
      value = '0x' + value.toString(16);

      return {
        type: 'HexNumber',
        value
      };
    }

    return {
      type: 'DecimalNumber',
      value
    };
  }

  StringLiteral() {
    // StringLiteral = '"' ([^"\r\n\\] | '\\' .)* '"'
    const value = this.match(/^"(?:[^"\r\n\\]|\\.)*"/);

    if (!value)
      return null;

    return {
      type: 'StringLiteral',
      value
    };
  }

  HexLiteral() {
    // HexLiteral =
    //     'hex' ('"' ([0-9a-fA-F]{2})* '"' | '\'' ([0-9a-fA-F]{2})* '\'')
    const value = this.match(/^hex(["'])(?:[0-9a-fA-F]{2})*\1/);

    if (!value)
      return null;

    return {
      type: 'HexLiteral',
      value
    };
  }

  TrueLiteral() {
    // TrueLiteral = 'true'
    if (!this.keyword('true'))
      return null;

    return {
      type: 'BoolLiteral',
      value: 'true'
    };
  }

  FalseLiteral() {
    // FalseLiteral = 'false'
    if (!this.keyword('false'))
      return null;

    return {
      type: 'BoolLiteral',
      value: 'false'
    };
  }

  AnyIdentifier(replaceable = false) {
    // AnyIdentifier = MemberIdentifier |
    //                 CallDataIdentifier |
    //                 Identifier
    return this.MemberIdentifier()
        || this.CallDataIdentifier()
        || this.Identifier(replaceable);
  }

  MemberIdentifier() {
    // MemberIdentifier = Identifier ( ':' TypeName ) ? '->' Identifier
    if (!this.peek(/^[a-zA-Z_$][\w$.]*(?::[a-zA-Z_$][\w$.]*)?->/))
      return null;

    const name = this.assert(this.Identifier());

    let cast = null;

    if (this.consume(':'))
      cast = this.assert(this.TypeName(name));

    this.expect('->');

    const member = this.assert(this.Identifier());

    return {
      type: 'MemberIdentifier',
      name,
      cast,
      member
    };
  }

  DefaultIdentifier() {
    // DefaultIdentifier = '@'
    const value = this.match(/^@(?=\s*[,)])/);

    if (!value)
      return null;

    return {
      type: 'Identifier',
      value,
      replaceable: false
    };
  }

  CallDataIdentifier() {
    // CallDataIdentifier = '&' ? 'calldata.' Identifier
    const match = this.match(/^&?calldata\./);

    if (!match)
      return null;

    const member = this.assert(this.Identifier());

    return {
      type: 'CallDataIdentifier',
      member,
      ref: match[0] === '&'
    };
  }

  Identifier(replaceable = false) {
    // Identifier = [a-zA-Z_$] [a-zA-Z_$0-9.]*
    const value = this.match(/^[a-zA-Z_$][\w$.]*/);

    if (!value)
      return null;

    return {
      type: 'Identifier',
      value,
      replaceable
    };
  }

  parts(rx) {
    const matches = rx.exec(this.input);

    if (!matches)
      return null;

    this.eat(matches[0].length);

    return matches;
  }

  match(rx) {
    const matches = this.parts(rx);

    if (!matches)
      return null;

    return matches[0];
  }

  eatChars(length) {
    for (let i = 0; i < length; i++) {
      const ch = this.input[i];

      if (ch === '\n') {
        this.start = this.pos + 1;
        this.line++;
      }

      this.pos++;
    }

    if (length > 0)
      this.input = this.input.substring(length);
  }

  eatSpace() {
    let spaces = 0;

    for (let i = 0; i < this.input.length; i++) {
      const ch = this.input[i];

      switch (ch) {
        case '\n':
          this.start = this.pos + 1;
          this.line++;
          // fallthrough
        case '\r':
        case '\t':
        case ' ':
          this.pos++;
          spaces++;
          continue;
      }

      break;
    }

    if (spaces > 0)
      this.input = this.input.substring(spaces);
  }

  eat(length) {
    this.eatChars(length);
    this.eatSpace();
    return true;
  }

  save() {
    return [this.input, this.line, this.start, this.pos];
  }

  restore(saved) {
    [this.input, this.line, this.start, this.pos] = saved;
  }

  peek(str) {
    if (str instanceof RegExp)
      return str.test(this.input);

    return this.input.startsWith(str);
  }

  consume(str) {
    if (!this.input.startsWith(str))
      return false;

    return this.eat(str.length);
  }

  keyword(str) {
    if (!this.input.startsWith(str))
      return false;

    if (str.length < this.input.length) {
      if (/[\w$.]/.test(this.input[str.length]))
        return false;
    }

    return this.eat(str.length);
  }

  expect(str) {
    this.assert(this.consume(str), `Expected "${str}"`);
  }

  currentLine() {
    const code = this.code;
    let pos = this.pos;

    while (pos < code.length && code[pos] !== '\n')
      pos++;

    return code.substring(this.start, pos);
  }
}

/*
 * Scope
 */

class Scope {
  constructor(node, parent = null, depth = 0) {
    this.node = node;
    this.parent = parent;
    this.depth = depth;
    this.consts = new Map();
    this.structs = new Map();
    this.macros = new Map();
    this.funcs = new Map();
    this.interfaces = new Map();
    this.methods = new Map();
    this.events = new Map();
    this.errors = new Map();
    this.vars = new Map();
    this.calldata = null;
    this.depends = new Map();
    this.data = [];
    this.immutable = [];
  }

  child(node) {
    return new Scope(node, this, this.depth + 1);
  }

  *scopes() {
    for (let scope = this; scope; scope = scope.parent)
      yield scope;
  }

  dependsOn(name, optional = false) {
    const func = this.findFunc(name);

    if (!func && !optional)
      throw new Error(`${name}() not available.`);

    if (func) {
      const scope = this.findCodeScope();
      scope.depends.set(name, func);
    }

    return func;
  }

  addData(prefix, value) {
    const scope = this.findObjectScope();
    const name = `__${prefix}_${scope.data.length}`;
    const data = DataValue(name, value);

    scope.data.push(data);

    return Literal(name);
  }

  findContractBlock() {
    for (const scope of this.scopes()) {
      if (scope.node.type === 'ObjectBlock') {
        if (scope.depth & 1)
          return scope.node;
      }
    }
    return null;
  }

  findObjectScope() {
    let root = this;

    for (const scope of this.scopes()) {
      if (scope.node.type === 'ObjectBlock')
        return scope;

      root = scope;
    }

    return root;
  }

  isDeployedObject() {
    if (this.node.type !== 'ObjectBlock')
      return false;

    return (this.depth & 1) === 0;
  }

  findCodeScope() {
    let root = this;

    for (const scope of this.scopes()) {
      if (scope.node.type === 'CodeBlock' ||
          scope.node.type === 'ConstructorDefinition') {
        return scope;
      }

      root = scope;
    }

    return root;
  }

  findConst(name) {
    for (const scope of this.scopes()) {
      const result = scope.consts.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findStruct(name) {
    for (const scope of this.scopes()) {
      const result = scope.structs.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findMacro(name) {
    for (const scope of this.scopes()) {
      const result = scope.macros.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findFunc(name) {
    for (const scope of this.scopes()) {
      const result = scope.funcs.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findInterface(name) {
    for (const scope of this.scopes()) {
      const result = scope.interfaces.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findConstructor(name) {
    const iface = this.findInterface(name);

    if (!iface)
      return null;

    return iface.ctor;
  }

  findDeclaration(name) {
    const parts = name.split('.');

    if (parts.length !== 2)
      return null;

    const iface = this.findInterface(parts[0]);

    if (!iface)
      return null;

    return iface.map.get(parts[1]) || null;
  }

  findMethod(name) {
    for (const scope of this.scopes()) {
      const result = scope.methods.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findEvent(name) {
    for (const scope of this.scopes()) {
      const result = scope.events.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findError(name) {
    for (const scope of this.scopes()) {
      const result = scope.errors.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findVar(name) {
    for (const scope of this.scopes()) {
      const result = scope.vars.get(name);

      if (result != null)
        return result;
    }

    return null;
  }

  findCalldata() {
    for (const scope of this.scopes()) {
      if (scope.calldata)
        return scope.calldata;
    }
    return null;
  }

  findMember(node) {
    assert(node.type === 'MemberIdentifier');

    const name = node.name.value;
    const cast = node.cast ? node.cast.value : null;
    const member = node.member.value;
    const type = cast || this.findVar(name);

    if (type == null)
      throw new Error(`Referencing non-existent variable: ${name}`);

    const struct = this.findStruct(type);

    if (struct == null)
      throw new Error(`${name}:${type} is not a struct`);

    const mem = struct.map.get(member);

    if (mem == null)
      throw new Error(`Non-existent member ${name}->${member}`);

    return mem;
  }

  addConst(name, value) {
    if (this.vars.has(name))
      throw new Error(`Variable already declared: ${name}`);

    if (this.consts.has(name))
      throw new Error(`Constant already defined: ${name}`);

    this.consts.set(name, value);
  }

  addStruct(struct) {
    if (this.structs.has(struct.name))
      throw new Error(`Duplicate struct name: ${struct.name}`);

    this.structs.set(struct.name, struct);
  }

  addMacro(node) {
    assert(node.type === 'MacroConstant' ||
           node.type === 'MacroDefinition');

    if (this.macros.has(node.name))
      throw new Error(`Macro already defined: ${node.name}`);

    this.macros.set(node.name, node);
  }

  addInterface(iface) {
    const {name} = iface;

    if (this.interfaces.has(name))
      throw new Error(`Interface ${name} already defined.`);

    this.interfaces.set(name, iface);
  }

  addMethod(method) {
    const {name} = method;

    if (this.methods.has(name))
      throw new Error(`Method ${name} already defined.`);

    this.methods.set(name, method);
  }

  addEvent(event) {
    const {name} = event;

    if (this.events.has(name))
      throw new Error(`Event ${name} already defined.`);

    this.events.set(name, event);
  }

  addError(error) {
    const {name} = error;

    if (this.errors.has(name))
      throw new Error(`Error ${name} already defined.`);

    this.errors.set(name, error);
  }

  addVar(name, type) {
    if (this.vars.has(name))
      throw new Error(`Variable already declared: ${name}`);

    if (this.consts.has(name))
      throw new Error(`Constant already defined: ${name}`);

    this.vars.set(name, type);
  }

  undefMacro(name) {
    for (const scope of this.scopes()) {
      if (scope.macros.delete(name))
        return true;
    }
    return false;
  }

  isLastNode(node) {
    if (this.node.type !== 'FunctionDefinition' &&
        this.node.type !== 'MethodDefinition') {
      return false;
    }

    const body = this.node.block.body;

    return body[body.length - 1] === node;
  }
}

/*
 * Transformer
 */

class Transformer {
  constructor(root, options, hasher = null) {
    let versions = { solc: null, yulc: null };
    let hardfork = 'london';
    let level = 2;
    let debug = false;
    let macros = [];
    let builtins;

    if (options != null) {
      if (options.builtins != null)
        level = options.builtins + 1;

      if (options.level != null)
        level = options.level;

      if (options.debug != null)
        debug = options.debug;

      if (options.macros != null)
        macros = options.macros;

      if (options.hardfork != null)
        hardfork = options.hardfork;

      if (options.versions != null)
        versions = options.versions;

      assert((level >>> 0) === level);
      assert(typeof debug === 'boolean');
      assert(Array.isArray(macros));
      assert(typeof hardfork === 'string');
      assert(hardforks[hardfork] != null, 'Unknown EVM version.');
      assert(hardforks[hardfork] < 300000, 'Invalid EVM version.');
      assert(versions && typeof versions === 'object');
      assert(versions.solc == null || typeof versions.solc === 'string');
      assert(versions.yulc == null || typeof versions.yulc === 'string');
    }

    switch (level) {
      case 0:
        builtins = new Builtins();
        break;
      case 1:
        builtins = Builtins.fromSupport();
        break;
      case 2:
        builtins = Builtins.fromBuiltins();
        break;
      default:
        throw new Error('Invalid builtin level.');
    }

    if (macros.length > 0)
      builtins = builtins.clone().inject(macros);

    this.root = root;
    this.level = level;
    this.debug = debug;
    this.hardfork = hardfork;
    this.versions = versions;
    this.scope = builtins.scope(root);
    this.object = -1;
    this.subobject = -1;
    this.abi = new ABI();
    this.deopt = new Set(['F']);
    this.hasher = hasher;
  }

  transform() {
    return this.rewrite(this.root);
  }

  generate(scope) {
    const nodes = [];

    for (const node of scope.depends.values()) {
      if (node.builtin)
        nodes.push(this.rewrite(node));
      else
        nodes.push(node);
    }

    for (const node of scope.data)
      nodes.push(node);

    return nodes;
  }

  push(child) {
    assert(child.parent === this.scope);
    this.scope = child;
  }

  pop() {
    assert(this.scope.parent);
    this.scope = this.scope.parent;
  }

  _block(node) {
    const scope = this.scope;
    const body = [];

    for (const child of node.body)
      body.push(this.rewrite(child));

    if (scope.depends.size > 0 || scope.data.length > 0)
      body.push(...this.generate(scope));

    if (this.hasher && scope.isDeployedObject())
      body.push(this.hasher.metadata);

    return Block(filter(body));
  }

  block(node, scope) {
    this.push(scope);

    const body = this._block(node);

    this.pop();

    return body;
  }

  params(node, scope) {
    const items = [];

    for (const [ident, kind] of node.items) {
      const name = this.rewrite(ident);
      const type = kind ? this.rewrite(kind) : null;

      scope.addVar(name.value, type ? type.value : 'u256');

      if (type && !scope.findStruct(type.value))
        items.push([name, type]);
      else
        items.push([name, null]);
    }

    return TypedIdentifierList(items);
  }

  prepare(node) {
    switch (node.type) {
      case 'StructDefinition': {
        const name = this.rewrite(node.name);
        const members = [];

        for (const member of node.members)
          members.push(this.prepare(member));

        return {
          type: 'StructDefinition',
          name,
          members
        };
      }

      case 'StructMember': {
        return {
          type: 'StructMember',
          kind: this.rewrite(node.kind),
          name: this.rewrite(node.name),
          value: this.rewrite(node.value)
        };
      }

      case 'Interface': {
        return {
          type: 'Interface',
          name: this.rewrite(node.name),
          ctor: node.ctor ? this.prepare(node.ctor) : null,
          decls: node.decls.map(n => this.prepare(n)),
          comment: node.comment
        };
      }

      case 'ConstructorDeclaration':
      case 'ConstructorDefinition': {
        return {
          type: 'ConstructorDeclaration',
          params: this.prepare(node.params),
          mutability: node.mutability,
          modifier: node.modifier,
          block: null,
          comment: node.comment
        };
      }

      case 'MethodDeclaration':
      case 'MethodDefinition': {
        return {
          type: 'MethodDeclaration',
          name: this.rewrite(node.name),
          params: this.prepare(node.params),
          visibility: node.visibility,
          mutability: node.mutability,
          modifier: node.modifier,
          returns: this.prepare(node.returns),
          block: null,
          comment: node.comment
        };
      }

      case 'MethodParams': {
        const items = [];

        for (const [type, name] of node.items) {
          if (name)
            items.push([type, this.rewrite(name)]);
          else
            items.push([type, null]);
        }

        return {
          type: 'MethodParams',
          items
        };
      }

      case 'EventDeclaration': {
        return {
          type: 'EventDeclaration',
          name: this.rewrite(node.name),
          params: this.prepare(node.params),
          anonymous: node.anonymous,
          packed: node.packed,
          modifier: node.modifier,
          comment: node.comment
        };
      }

      case 'EventParams': {
        const items = [];

        for (const [type, name, indexed] of node.items) {
          if (name)
            items.push([type, this.rewrite(name), indexed]);
          else
            items.push([type, null, indexed]);
        }

        return {
          type: 'EventParams',
          items
        };
      }

      case 'ErrorDeclaration': {
        return {
          type: 'ErrorDeclaration',
          name: this.rewrite(node.name),
          params: this.prepare(node.params),
          comment: node.comment
        };
      }

      case 'MemberIdentifier': {
        return {
          type: 'MemberIdentifier',
          name: this.rewrite(node.name),
          cast: node.cast ? this.rewrite(node.cast) : null,
          member: this.rewrite(node.member)
        };
      }

      default: {
        throw new Error('unreachable');
      }
    }
  }

  value(node) {
    const ident = this.rewrite(node);
    assert(ident.type === 'Identifier');
    return ident.value;
  }

  rewrite(node) {
    const scope = this.scope;

    switch (node.type) {
      case 'Root': {
        const nodes = [];

        for (const child of node.nodes)
          nodes.push(this.rewrite(child));

        if (!scope.parent && this.object < 0) {
          if (scope.depends.size > 0 || scope.data.length > 0)
            nodes.push(...this.generate(scope));
        }

        return Root(filter(nodes));
      }

      case 'Pragma': {
        switch (node.name) {
          case 'license': {
            if (scope.depth !== 0)
              throw new Error('Pragma "license" must be defined at the root.');

            this.abi.license = node.value;

            break;
          }

          case 'solc':
          case 'yulc': {
            const {name, value:theirs} = node;
            const ours = this.versions[name];

            if (scope.depth !== 0)
              throw new Error(`Pragma "${name}" must be defined at the root.`);

            if (ours != null && !semver.match(ours, theirs))
              throw new Error(`${name} ${ours} failed to match ${theirs}`);

            if (name === 'solc')
              this.abi.version = node.value;

            break;
          }

          case 'evm': {
            const ours = this.hardfork;
            const theirs = node.value;

            if (scope.depth !== 0)
              throw new Error('Pragma "evm" must be defined at the root.');

            if (hardforks[ours] < hardforks[theirs])
              throw new Error(`Invalid evm version (${ours} < ${theirs}).`);

            break;
          }

          case 'optimize':
          case 'deoptimize': {
            const {name, value} = node;

            if (scope.depth !== 0)
              throw new Error(`Pragma "${name}" must be defined at the root.`);

            if (name === 'optimize') {
              for (let i = 0; i < value.length; i++)
                this.deopt.delete(value[i]);
            } else {
              for (let i = 0; i < value.length; i++)
                this.deopt.add(value[i]);
            }

            break;
          }

          case 'lock': {
            if (scope.node.type !== 'CodeBlock')
              throw new Error('Pragma "lock" must be defined in a code block.');

            const bits = (node.value.length - 2) * 4;
            const value = BigInt(node.value) << BigInt(256 - bits);
            const func = FunctionConstant('__mutex_key', Literal(value));

            scope.funcs.set('__mutex_key', func);

            break;
          }

          default: {
            throw new Error('unreachable');
          }
        }

        return Null();
      }

      case 'Fold': {
        const branches = [
          [node.expr, node.block],
          ...node.branches
        ];

        for (const [expr, block] of branches) {
          const result = this.rewrite(expr);

          if (isLiteral(result) && toBigInt(result.value))
            return this.rewrite(block);
        }

        if (node.otherwise)
          return this.rewrite(node.otherwise);

        return Null();
      }

      case 'IncludeCall': {
        const filename = path.resolve(node.root, node.name);
        const input = fs.readFileSync(filename, 'utf8');

        if (this.hasher)
          this.hasher.update(filename, input);

        return this.rewrite(parse(input, filename));
      }

      case 'Enum': {
        let prefix = '';
        let counter = -1n;

        if (node.name)
          prefix = this.value(node.name) + '.';

        for (const [lhs, rhs] of node.members) {
          const name = prefix + this.value(lhs);

          if (rhs) {
            const expr = this.rewrite(rhs);

            if (!isLiteral(expr))
              throw new Error('Invalid enum member value.');

            counter = toBigInt(expr.value);
          } else {
            counter += 1n;
          }

          scope.addConst(name, Literal(counter));
        }

        return Null();
      }

      case 'StructDefinition': {
        const struct = new Struct(this.prepare(node));

        scope.addStruct(struct);

        return Null();
      }

      case 'Interface': {
        const iface = new Interface(this.prepare(node));

        scope.addInterface(iface);

        if (iface.ctor) {
          const name1 = `__icreate_${iface.name}`;
          const name2 = `__icreate2_${iface.name}`;
          const func1 = iface.ctor.generate(name1, false);
          const func2 = iface.ctor.generate(name2, true);

          scope.funcs.set(name1, func1);
          scope.funcs.set(name2, func2);
        }

        for (const method of iface.methods) {
          const fname1 = `__icall_${iface.name}_${method.name}`;
          const fname2 = `__itrycall_${iface.name}_${method.name}`;
          const func1 = method.generate(fname1, false);
          const func2 = method.generate(fname2, true);

          scope.funcs.set(fname1, func1);
          scope.funcs.set(fname2, func2);
        }

        return Null();
      }

      case 'Contract': {
        const name = this.value(node.name);
        const {modifier, block} = node;

        let subname = name + 'Runtime';

        if (modifier === 'optimize')
          subname += '_deployed';

        let defs = [];
        let ctor = null;
        let code = [];
        let objs = []; // eslint-disable-line
        let data = []; // eslint-disable-line

        if (scope.depth === 0) {
          const contracts = [node];

          for (let i = 0; i < contracts.length; i++) {
            const contract = contracts[i];

            const iface = {
              type: 'Interface',
              name: contract.name,
              ctor: ConstructorDefinition(),
              decls: [],
              comment: contract.comment
            };

            for (const node of contract.block.body) {
              switch (node.type) {
                case 'ConstructorDefinition':
                  iface.ctor = node;
                  break;
                case 'MethodDefinition':
                  iface.decls.push(node);
                  break;
                case 'Contract':
                  contracts.push(node);
                  break;
              }
            }

            defs.push(iface);
          }
        }

        for (const node of block.body) {
          switch (node.type) {
            case 'ConstructorDefinition': {
              if (ctor)
                throw new Error('Multiple constructors defined.');

              if (code.length > 0 || objs.length > 0 || data.length > 0)
                throw new Error('Constructor must precede code/objects/data.');

              ctor = node;

              break;
            }

            case 'Contract':
            case 'ObjectBlock': {
              if (data.length > 0)
                throw new Error('Objects must precede data.');

              objs.push(node);

              break;
            }

            case 'DataValue': {
              if (node.name === 'genesis')
                code.push(Call('datareference', [Literal('genesis')]));

              data.push(node);

              break;
            }

            default: {
              if (objs.length > 0 || data.length > 0)
                throw new Error('Code must precede objects/data.');

              switch (node.type) {
                case 'Pragma':
                case 'Enum':
                case 'StructDefinition':
                case 'Interface':
                case 'MacroConstant':
                case 'MacroDefinition':
                case 'EventDeclaration':
                case 'ErrorDeclaration':
                case 'ConstDeclaration':
                  if (ctor || code.length > 0)
                    code.push(node);
                  else
                    defs.push(node);
                  break;
                default:
                  code.push(node);
                  break;
              }

              break;
            }
          }
        }

        const call = Call('construct', [Literal(subname)]);

        if (!ctor) {
          ctor = ConstructorDefinition([call]);
          code = defs.concat(code);
          defs = [];
        } else {
          ctor.block.body.push(call);
        }

        code.push(Call('method.select'));

        return this.rewrite({
          type: 'ObjectBlock',
          name: name,
          block: Block([
            ...defs,
            ctor,
            {
              type: 'ObjectBlock',
              name: subname,
              block: Block([
                {
                  type: 'CodeBlock',
                  block: Block(code)
                },
                ...objs,
                ...data
              ]),
              comment: null
            }
          ]),
          comment: node.comment
        });
      }

      case 'ObjectBlock': {
        if (scope.depth > 0 && scope.node.type !== 'ObjectBlock')
          throw new Error('Object must be inside an object block.');

        if (scope.depth === 0 && ++this.object)
          throw new Error('Multiple top-level objects.');

        if (scope.depth === 1 && ++this.subobject)
          throw new Error('Multiple top-level subobjects.');

        if ((scope.depth & 1) === 0)
          this.abi.init(node);

        return {
          type: 'ObjectBlock',
          name: node.name,
          block: this.block(node.block, scope.child(node)),
          comment: null
        };
      }

      case 'CodeBlock': {
        if (scope.node.type !== 'ObjectBlock')
          throw new Error('Code block must be inside an object block.');

        return {
          type: 'CodeBlock',
          block: this.block(node.block, scope.child(node))
        };
      }

      case 'ConstructorDefinition': {
        if (scope.node.type !== 'ObjectBlock')
          throw new Error('Constructor must be inside an object block.');

        const ctor = new Constructor(this.prepare(node), scope.node.name);
        const child = scope.child(node);
        const check = ctor.check();

        ctor.addDeps(child);

        const block = this.block(node.block, child);

        this.abi.add(ctor, scope);

        return {
          type: 'CodeBlock',
          block: Block([
            ...check.nodes,
            ...block.body
          ])
        };
      }

      case 'DataValue': {
        if (scope.node.type !== 'ObjectBlock')
          throw new Error('Data must be inside an object block.');

        return {
          type: 'DataValue',
          name: node.name,
          value: this.rewrite(node.value)
        };
      }

      case 'Block': {
        return this.block(node, scope.child(node));
      }

      case 'MacroConstant':
      case 'MacroDefinition': {
        scope.addMacro(node);
        return Null();
      }

      case 'FunctionDefinition': {
        const child = scope.child(node);
        const name = this.rewrite(node.name);
        const params = this.params(node.params, child);
        const returns = this.params(node.returns, child);
        const block = this.block(node.block, child);

        const func = {
          type: 'FunctionDefinition',
          name,
          params,
          modifier: null,
          returns,
          block,
          builtin: false
        };

        if (node.modifier === 'noinline')
          return NoInline(func, false);

        return func;
      }

      case 'MethodDefinition': {
        if (scope.node.type !== 'CodeBlock')
          throw new Error('Methods must be inside a code block.');

        const method = new Method(this.prepare(node));
        const child = scope.child(node);

        child.calldata = method;

        scope.addMethod(method);

        this.abi.add(method, scope);

        return {
          type: 'FunctionDefinition',
          name: Identifier(`__method_${method.name}`),
          params: TypedIdentifierList(),
          modifier: null,
          returns: TypedIdentifierList(),
          block: this.block(node.block, child),
          builtin: false
        };
      }

      case 'EventDeclaration': {
        const event = new Event(this.prepare(node), scope.depth);

        scope.addEvent(event);

        if (event.modifier !== 'inline') {
          const func = event.generate(event.ident);
          scope.funcs.set(event.ident, func);
        }

        this.abi.add(event, scope);

        return Null();
      }

      case 'ErrorDeclaration': {
        const error = new VMError(this.prepare(node), scope.depth);
        const func = error.generate(error.ident);

        scope.addError(error);
        scope.funcs.set(error.ident, func);

        this.abi.add(error, scope);

        return Null();
      }

      case 'VariableDeclaration': {
        return {
          type: 'VariableDeclaration',
          vars: this.rewrite(node.vars),
          expr: node.expr ? this.rewrite(node.expr) : null
        };
      }

      case 'ConstDeclaration': {
        const name = this.value(node.name);
        const value = this.rewrite(node.expr);

        if (node.wrap) {
          const ident = `__const_${name}_${scope.depth}`;
          const func = FunctionConstant(ident, value);

          scope.addConst(name, {
            type: 'ConstWrapper',
            ident
          });

          scope.funcs.set(ident, func);
        } else {
          scope.addConst(name, value);
        }

        return Null();
      }

      case 'TypedIdentifierList': {
        return this.params(node, scope);
      }

      case 'MemberAssignment': {
        const lhs = this.prepare(node.lhs);
        const rhs = this.rewrite(node.rhs);
        const mem = scope.findMember(lhs);

        if (node.or)
          return mem.put(lhs.name, rhs);

        return mem.write(lhs.name, rhs);
      }

      case 'Assignment': {
        return {
          type: 'Assignment',
          lhs: this.rewrite(node.lhs),
          rhs: this.rewrite(node.rhs)
        };
      }

      case 'IdentifierList': {
        const items = [];

        for (const ident of node.items)
          items.push(this.rewrite(ident));

        return {
          type: 'IdentifierList',
          items
        };
      }

      case 'If': {
        const expr = this.rewrite(node.expr);
        const block = this.block(node.block, scope.child(node));

        if (node.branches.length > 0 || node.otherwise) {
          const branches = [[expr, block]];

          for (const [expr, block] of node.branches) {
            branches.push([
              this.rewrite(expr),
              this.block(block, scope.child(node))
            ]);
          }

          let otherwise = null;

          if (node.otherwise)
            otherwise = this.block(node.otherwise, scope.child(node));

          if (scope.isLastNode(node) && node.branches.length > 0) {
            const nodes = [];

            for (const [expr, block] of branches) {
              block.body.push(Leave());
              nodes.push(If(ocj(expr), block));
            }

            if (otherwise)
              nodes.push(otherwise);

            return Root(nodes);
          }

          let def = null;
          let next = null;

          if (otherwise) {
            def = {
              type: 'Default',
              block: otherwise
            };
          }

          for (let i = branches.length - 1; i >= 0; i--) {
            const [expr, block] = branches[i];

            if (def) {
              let check, value;

              if (isZeroCall(expr)) {
                check = expr.args[0];
                value = Literal(0);
              } else if (isEqLiteral(expr)) {
                [check, value] = expr.args;
              } else if (returnsBool(expr)) {
                check = expr;
                value = Literal(1);
              } else {
                check = IsZero(expr);
                value = Literal(0);
              }

              next = {
                type: 'Switch',
                expr: check,
                cases: [{
                  type: 'Case',
                  value,
                  block
                }],
                def
              };
            } else {
              next = If(ocj(expr), block);
            }

            def = {
              type: 'Default',
              block: Block([next])
            };
          }

          return next;
        }

        return {
          type: 'If',
          expr: ocj(expr),
          block,
          branches: [],
          otherwise: null
        };
      }

      case 'Switch': {
        const expr = this.rewrite(node.expr);
        const cases = [];

        let def = null;

        for (const case_ of node.cases)
          cases.push(this.rewrite(case_));

        if (node.def)
          def = this.rewrite(node.def);

        return {
          type: 'Switch',
          expr,
          cases,
          def
        };
      }

      case 'Case': {
        const child = scope.child(node);

        if (node.value.type === 'MethodSignature' && !node.value.params) {
          const name = this.value(node.value.name);
          const method = scope.findMethod(name);

          if (!method)
            throw new Error(`Method ${name} not found.`);

          child.calldata = method;
        }

        return {
          type: 'Case',
          value: this.rewrite(node.value),
          block: this.block(node.block, child)
        };
      }

      case 'Default': {
        return {
          type: 'Default',
          block: this.block(node.block, scope.child(node))
        };
      }

      case 'MethodSignature': {
        const name = this.value(node.name);

        if (node.params) {
          const types = [];

          for (const [type] of node.params.items)
            types.push(type.value);

          const signature = methodHash(name, types);

          return HexNumber(signature);
        }

        const method = scope.findMethod(name)
                    || scope.findDeclaration(name);

        if (!method)
          throw new Error(`Method ${name} not found.`);

        return HexNumber(method.signature);
      }

      case 'EventSignature': {
        const name = this.value(node.name);

        if (node.params) {
          const types = [];

          for (const [type] of node.params.items)
            types.push(type.value);

          const signature = eventHash(name, types);

          return HexNumber(signature);
        }

        const event = scope.findEvent(name);

        if (!event)
          throw new Error(`Event ${name} not found.`);

        return HexNumber(event.signature);
      }

      case 'ErrorSignature': {
        const name = this.value(node.name);

        if (node.params) {
          const types = [];

          for (const [type] of node.params.items)
            types.push(type.value);

          const signature = methodHash(name, types);

          return HexNumber(signature);
        }

        const error = scope.findError(name);

        if (!error)
          throw new Error(`Error ${name} not found.`);

        return HexNumber(error.signature);
      }

      case 'ForLoop': {
        this.push(scope.child(node));

        const result = {
          type: 'ForLoop',
          init: this._block(node.init),
          test: ocj(this.rewrite(node.test)),
          update: this._block(node.update),
          block: this._block(node.block)
        };

        this.pop();

        return result;
      }

      case 'While': {
        return {
          type: 'ForLoop',
          init: Block(),
          test: ocj(this.rewrite(node.test)),
          update: Block(),
          block: this.block(node.block, scope.child(node))
        };
      }

      case 'DoWhile': {
        const block = this.block(node.block, scope.child(node));
        const test = ocj(this.rewrite(node.test));

        if (test.type === 'Identifier') {
          const break_ = Block([{
            type: 'BreakContinue',
            value: 'break'
          }]);

          block.body.push(If(IsZero(test), break_));

          return {
            type: 'ForLoop',
            init: Block(),
            test: Literal(1),
            update: Block(),
            block
          };
        }

        const ok = Identifier(`__ok_${scope.depth}`);

        return {
          type: 'ForLoop',
          init: Block([Let(ok, Literal(1))]),
          test: ok,
          update: Block([Assign(ok, test)]),
          block
        };
      }

      case 'BreakContinue': {
        return {
          type: 'BreakContinue',
          value: node.value
        };
      }

      case 'Leave': {
        return {
          type: 'Leave'
        };
      }

      case 'Emit': {
        const name = this.value(node.name);
        const offset = this.rewrite(node.offset);
        const event = scope.findEvent(name);
        const args = [];

        if (!event)
          throw new Error(`Event ${name} not found.`);

        if (node.args.length !== event.params.length)
          throw new Error(`Invalid arguments for emit ${name}.`);

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        if (event.depth === 0)
          this.abi.add(event, scope);

        if (event.modifier !== 'inline') {
          scope.dependsOn(event.ident);
          args.unshift(offset);
          return Call(event.ident, args);
        }

        return event.emit(offset, args);
      }

      case 'Throw': {
        const name = this.value(node.name);
        const error = scope.findError(name);
        const args = [];

        if (!error) {
          if (node.args.length === 1) {
            const arg = this.rewrite(node.args[0]);

            if (name === 'Error' && isStringLiteral(arg))
              return this.revertString(arg, scope);

            if (name === 'ErrorCode' && isLiteral(arg))
              return this.revertInt(arg, scope);

            if (name === 'Panic' && isLiteral(arg))
              return this.revertPanic(arg, scope);
          }

          throw new Error(`Error ${name} not found.`);
        }

        if (node.args.length !== error.params.length)
          throw new Error(`Invalid arguments for throw ${name}.`);

        if (error.depth === 0)
          this.abi.add(error, scope);

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        scope.dependsOn(error.ident);

        return Call(error.ident, args);
      }

      case 'StructInitializer': {
        const name = this.value(node.name);
        const struct = scope.findStruct(name);

        if (struct == null)
          throw new Error(`Unknown struct: ${name}`);

        const args = [];

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        return struct.fold(args);
      }

      case 'InterfaceCall': {
        // addr := create Contract(pos, name, ...args, [amt])
        // addr := create2 Contract(pos, name, ...args, salt, [amt])
        // z1, z2 := call Contract.method(pos, addr, ...args, [amt])
        const iname = this.value(node.name);
        const iface = scope.findInterface(iname);

        if (!iface)
          throw new Error(`Interface ${iname} not found.`);

        if (node.kind === 'create' || node.kind === 'create2') {
          const method = iface.ctor;
          const fname = `__i${node.kind}_${iname}`;
          const func = scope.dependsOn(fname, true);

          if (!method || !func)
            throw new Error(`Constructor ${iname}() not found.`);

          if (node.args.length !== func.params.items.length - 1)
            throw new Error(`Invalid arguments for ${node.kind} ${iname}().`);

          const pos = this.rewrite(node.args[0]);
          const name = this.rewrite(node.args[1]);

          if (!isStringLiteral(name))
            throw new Error(`Invalid arguments for ${node.kind} ${iname}().`);

          const args = [
            pos,
            DataOffset(name),
            DataSize(name)
          ];

          for (let i = 2; i < node.args.length; i++)
            args.push(this.rewrite(node.args[i]));

          return Call(fname, args);
        }

        const mname = this.value(node.method);
        const method = iface.map.get(mname);
        const fname1 = `__icall_${iname}_${mname}`;
        const fname2 = `__itrycall_${iname}_${mname}`;
        const fname = node.attempt ? fname2 : fname1;
        const func = scope.dependsOn(fname, true);
        const args = [];

        if (!method || !func)
          throw new Error(`Method ${iname}.${mname}() not found.`);

        if (node.args.length !== func.params.items.length)
          throw new Error(`Invalid arguments for call ${iname}.${mname}().`);

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        method.addCallDeps(scope);

        return Call(fname, args);
      }

      case 'FunctionCall': {
        const macro = scope.findMacro(node.name.value);

        if (macro && macro.type === 'MacroDefinition')
          return this.rewrite(expand(macro, node.args));

        const name = this.rewrite(node.name);
        const result = this.builtin(name, node, scope);

        if (result != null)
          return result;

        const args = [];

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        // Might be able to fold this into a literal.
        const literal = fold(name, args);

        if (literal)
          return literal;

        scope.dependsOn(name.value, true);

        return {
          type: 'FunctionCall',
          name,
          args,
          filename: node.filename,
          line: node.line
        };
      }

      case 'Literal': {
        let subtype = node.subtype;
        let kind = node.kind ? this.rewrite(node.kind) : null;
        let value = node.value;

        if (kind) {
          let unit = 0n;

          switch (kind.value) {
            case 'wei':
              unit = 1n;
              break;
            case 'kwei':
              unit = 10n ** 3n;
              break;
            case 'mwei':
              unit = 10n ** 6n;
              break;
            case 'gwei':
              unit = 10n ** 9n;
              break;
            case 'twei':
              unit = 10n ** 12n;
              break;
            case 'pwei':
              unit = 10n ** 15n;
              break;
            case 'ether':
              unit = 10n ** 18n;
              break;
            case 'seconds':
              unit = 1n;
              break;
            case 'minutes':
              unit = 60n;
              break;
            case 'hours':
              unit = 60n * 60n;
              break;
            case 'days':
              unit = 24n * 60n * 60n;
              break;
            case 'weeks':
              unit = 7n * 24n * 60n * 60n;
              break;
          }

          if (unit && isLiteral(node)) {
            let amt = toBigInt(value);

            if (amt & I256_SIGN)
              amt = -(-amt & U256_MAX);

            amt *= unit;

            if (amt < -I256_SIGN || amt >= I256_SIGN)
              throw new Error(`Literal overflow: ${value}:${kind.value}`);

            if (amt < 0n) {
              subtype = 'HexNumber';
              value = '0x' + (amt & U256_MAX).toString(16);
            } else {
              subtype = 'DecimalNumber';
              value = amt.toString(10);
            }

            kind = null;
          } else {
            if (scope.findStruct(kind.value))
              kind = null;
          }
        }

        return {
          type: 'Literal',
          subtype,
          kind,
          value
        };
      }

      case 'MemberIdentifier': {
        const id = this.prepare(node);
        const mem = scope.findMember(id);
        return mem.read(id.name);
      }

      case 'CallDataIdentifier': {
        const method = scope.findCalldata();

        if (!method)
          throw new Error('No method available.');

        const name = this.value(node.member);
        const param = method.map.get(name);

        if (param == null)
          throw new Error(`Unknown method parameter: ${name}`);

        if (node.ref)
          return param.ref();

        return param.read();
      }

      case 'Identifier': {
        switch (node.value) {
          case 'EVM_VERSION':
            return Literal(hardforks[this.hardfork]);
        }

        const macro = scope.findMacro(node.value);

        if (macro && macro.type === 'MacroConstant')
          return this.rewrite(macro.expr);

        if (node.replaceable) {
          const const_ = scope.findConst(node.value);

          if (const_) {
            if (const_.type === 'ConstWrapper') {
              scope.dependsOn(const_.ident);
              return Call(const_.ident);
            }
            return const_;
          }
        }

        return {
          type: 'Identifier',
          value: node.value,
          replaceable: node.replaceable
        };
      }

      default: {
        throw new Error('unreachable');
      }
    }
  }

  builtin(name, node, scope) {
    let revert = null;

    {
      let length = -1;

      switch (name.value) {
        case 'assert':
        case 'require':
        case 'require.ok':
        case 'require.zero':
        case 'require.before':
        case 'require.after':
        case 'require.caller':
        case 'require.origin':
          length = 2;
          break;
        case 'require.eq':
        case 'require.neq':
        case 'require.lt':
        case 'require.lte':
        case 'require.gt':
        case 'require.gte':
        case 'require.slt':
        case 'require.slte':
        case 'require.sgt':
        case 'require.sgte':
        case 'require.width':
          length = 3;
          break;
        case 'require.owner':
        case 'revert':
          length = 1;
          break;
        case 'eth.transfer':
          length = node.args.length + 1;
          break;
      }

      if (length >= 0)
        revert = Revert();

      if (node.args.length === length) {
        const arg = this.rewrite(node.args[length - 1]);

        if (isStringLiteral(arg))
          revert = this.revertString(arg, scope);
        else if (isLiteral(arg))
          revert = this.revertInt(arg, scope);
        else
          throw new Error('Invalid type for revert msg/code.');
      }

      if (this.debug && node.line >= 0 && node.args.length === length - 1) {
        const msg = `${path.basename(node.filename)}:${node.line + 1}`;
        const arg = Literal(msg);

        revert = this.revertString(arg, scope);
      }
    }

    switch (name.value) {
      case 'method.check': {
        if (node.args.length !== 0)
          throw new Error('method.check() requires 0 arguments.');

        const method = scope.findCalldata();

        if (!method)
          throw new Error('No method available.');

        method.addDeps(scope);

        return method.check();
      }

      case 'method.select': {
        if (node.args.length !== 0)
          throw new Error('method.select() requires 0 arguments.');

        if (scope.methods.size === 0)
          return Stop();

        let fallback = Block([Revert()]);
        let receive = null;

        const cases = [];

        for (const method of scope.methods.values()) {
          const check = method.check();

          method.addDeps(scope);

          let block;

          if (method.modifier === 'locked') {
            scope.dependsOn('__mutex_key');
            scope.dependsOn('__mutex_lock');
            scope.dependsOn('__mutex_unlock');

            block = Block([
              ...check.nodes,
              Call('__mutex_lock'),
              Call(`__method_${method.name}`),
              Call('__mutex_unlock')
            ]);
          } else {
            block = Block([
              ...check.nodes,
              Call(`__method_${method.name}`)
            ]);
          }

          if (method.name === 'receive') {
            receive = block;
            continue;
          }

          if (method.name === 'fallback') {
            fallback = block;
            continue;
          }

          cases.push({
            type: 'Case',
            value: HexNumber(method.signature),
            block
          });
        }

        let either = fallback;

        if (receive) {
          either = Block([{
            type: 'Switch',
            expr: Eq(CallDataSize(), Literal(0)),
            cases: [{
              type: 'Case',
              value: Literal(1),
              block: receive
            }],
            def: {
              type: 'Default',
              block: fallback
            }
          }]);
        }

        return Root([
          {
            type: 'Switch',
            expr: Lt(CallDataSize(), Literal(4)),
            cases: [{
              type: 'Case',
              value: Literal(1),
              block: either
            }],
            def: {
              type: 'Default',
              block: Block([{
                type: 'Switch',
                expr: Shr(224, CallDataLoad(0)),
                cases,
                def: {
                  type: 'Default',
                  block: fallback
                }
              }])
            }
          },
          Stop()
        ]);
      }

      case 'method.call': {
        if (node.args.length !== 1)
          throw new Error('method.call(name) requires 1 argument.');

        const name = this.rewrite(node.args[0]);

        if (name.type !== 'Identifier')
          throw new Error('method.call(): argument 0 must be an identifier.');

        const method = scope.findMethod(name.value);

        if (!method)
          throw new Error(`Method ${name.value} not found.`);

        if (method.modifier === 'locked') {
          scope.dependsOn('__mutex_key');
          scope.dependsOn('__mutex_lock');
          scope.dependsOn('__mutex_unlock');

          return Root([
            Call('__mutex_lock'),
            Call(`__method_${name.value}`),
            Call('__mutex_unlock')
          ]);
        }

        return Call(`__method_${name.value}`);
      }

      case 'create.size':
      case 'create2.size':
      case 'method.size':
      case 'returns.size':
      case 'event.size':
      case 'error.size': {
        const prefix = `${name.value}(name)`;

        let ident = null;
        let type = null;
        let obj = null;

        if (name.value === 'returns.size' && node.args.length === 0) {
          const method = scope.findCalldata();

          if (!method)
            throw new Error('returns.size() must be called inside a method.');

          ident = Identifier(method.name);
        } else if (node.args.length === 1) {
          ident = this.rewrite(node.args[0]);

          if (ident.type !== 'Identifier')
            throw new Error(`${prefix}: argument 0 must be an identifier.`);
        } else {
          throw new Error(`${prefix} requires 1 argument.`);
        }

        switch (name.value) {
          case 'create.size':
          case 'create2.size':
            type = 'Constructor';
            obj = scope.findConstructor(ident.value);
            break;
          case 'method.size':
          case 'returns.size':
            type = 'Method';
            obj = scope.findMethod(ident.value)
               || scope.findDeclaration(ident.value);
            break;
          case 'event.size':
            type = 'Event';
            obj = scope.findEvent(ident.value);
            break;
          case 'error.size':
            type = 'Error';
            obj = scope.findError(ident.value);
            break;
        }

        if (!obj)
          throw new Error(`${name.value}(): ${type} ${ident.value} not found.`);

        if (obj.type === 'constructor') {
          const size = DataSize(Literal(obj.name));
          const len = Literal(obj.params.length * 32);
          return Add(size, len);
        }

        if (obj.type === 'event') {
          let size = 0;

          for (const param of obj.params) {
            if (obj.packed && param.array) {
              assert(param === obj.params[obj.params.length - 1]);
              break;
            }

            if (!param.indexed)
              size += (obj.packed ? param.bytes : 32);
          }

          return Literal(size);
        }

        if (name.value === 'returns.size')
          return Literal(obj.returns.length * 32);

        return Literal(4 + obj.params.length * 32);
      }

      case 'returns': {
        if (node.args.length < 1)
          throw new Error('returns() requires at least 1 argument.');

        const method = scope.findCalldata();

        if (!method)
          throw new Error('returns() must be called inside a method.');

        if (node.args.length !== method.returns.length + 1)
          throw new Error(`Invalid arguments for returns ${method.name}.`);

        const offset = this.rewrite(node.args[0]);
        const args = [];

        for (let i = 1; i < node.args.length; i++)
          args.push(this.rewrite(node.args[i]));

        return method.returnify(offset, args);
      }

      case 'mstores': {
        if (node.args.length < 2)
          throw new Error('mstores() requires at least 2 arguments.');

        const offset = this.rewrite(node.args[0]);
        const nodes = [];

        let pos = offset;

        if (hasSideEffects(pos)) {
          pos = Identifier('__mpos');
          nodes.push(Let(pos, offset));
        }

        for (let i = 1; i < node.args.length; i++) {
          const expr = this.rewrite(node.args[i]);

          nodes.push(MemStoreAdd(pos, (i - 1) * 32, expr));
        }

        if (pos !== offset)
          return Block(nodes);

        return Root(nodes);
      }

      case 'storeimmutable': {
        if (scope.node.type !== 'ConstructorDefinition')
          throw new Error('storeimmutable() must be inside a constructor.');

        if (node.args.length !== 2)
          throw new Error('storeimmutable(name, value) requires 2 arguments.');

        const name = this.rewrite(node.args[0]);
        const value = this.rewrite(node.args[1]);

        if (!isStringLiteral(name))
          throw new Error('storeimmutable(): argument 0 must be a string.');

        const ref = Identifier(`__immutable_${scope.immutable.length}`);

        scope.immutable.push([name, ref]);

        return Let(ref, value);
      }

      case 'construct': {
        if (scope.node.type !== 'ConstructorDefinition')
          throw new Error('construct() must be inside a constructor.');

        if (node.args.length !== 1)
          throw new Error('construct(name) requires 1 argument.');

        const name = this.rewrite(node.args[0]);

        if (!isStringLiteral(name))
          throw new Error('construct(): argument 0 must be a string.');

        const immutables = [];

        for (const [name, value] of scope.immutable)
          immutables.push(SetImmutable(Literal(0), name, value));

        return Root([
          DataCopy(Literal(0), DataOffset(name), DataSize(name)),
          ...immutables,
          Return(Literal(0), DataSize(name))
        ]);
      }

      case 'datareference': {
        if (node.args.length !== 1)
          throw new Error('datareference(name) requires 1 argument.');

        const name = this.rewrite(node.args[0]);

        if (!isStringLiteral(name))
          throw new Error('datareference(): argument 0 must be a string.');

        // Non-optimizable version of pop(dataoffset("name")).
        return PopAsm(DataOffset(name));
      }

      case 'sizeof':
      case 'bitsof': {
        if (node.args.length !== 1)
          throw new Error(`${name.value}(value) requires 1 argument.`);

        if (node.args[0].type === 'MemberIdentifier') {
          const ident = this.prepare(node.args[0]);
          const mem = scope.findMember(ident);

          if (name.value === 'sizeof') {
            const size = (mem.width + 7) >>> 3;
            return Literal(size);
          }

          return Literal(mem.width);
        }

        const arg = this.rewrite(node.args[0]);

        if (arg.type === 'Identifier') {
          const struct = scope.findStruct(arg.value);

          if (!struct)
            throw new Error(`Unknown struct: ${arg.value}`);

          if (name.value === 'sizeof') {
            const size = (struct.width + 7) >>> 3;
            return Literal(size);
          }

          return Literal(struct.width);
        }

        if (!isStringLiteral(arg) && !isHexLiteral(arg))
          throw new Error(`${name.value}(): argument 0 must be a string.`);

        let size;

        if (isStringLiteral(arg))
          size = JSON.parse(arg.value).length;
        else
          size = (arg.value.length - 5) / 2;

        if (name.value === 'bitsof')
          size *= 8;

        return Literal(size);
      }

      case 'offsetof': {
        if (node.args.length !== 1)
          throw new Error('offsetof(value) requires 1 argument.');

        if (node.args[0].type !== 'MemberIdentifier')
          throw new Error('offsetof(): argument 0 must be a member access.');

        const ident = this.prepare(node.args[0]);
        const mem = scope.findMember(ident);

        return Literal(mem.offset);
      }

      case 'defined':
      case 'undefined': {
        if (node.args.length !== 1)
          throw new Error(`${name.value}() requires 1 argument.`);

        const flip = Number(name.value === 'undefined');
        const ident = node.args[0];

        if (ident.type !== 'Identifier')
          throw new Error(`${name.value}() requires an identifier.`);

        let result;

        switch (ident.value) {
          case 'DEBUG':
            result = this.debug;
            break;
          case 'NDEBUG':
            result = !this.debug;
            break;
          case 'EVM_VERSION':
            result = true;
            break;
          default:
            result = scope.findMacro(ident.value) != null;
            break;
        }

        return Literal(result ^ flip);
      }

      case 'undefine': {
        if (node.args.length !== 1)
          throw new Error('undefine() requires 1 argument.');

        const ident = node.args[0];

        if (ident.type !== 'Identifier')
          throw new Error('undefine() requires an identifier.');

        scope.undefMacro(ident.value);

        return Null();
      }

      case 'andl':
      case 'orl': {
        if (node.args.length < 2)
          throw new Error(`${name.value}() requires arguments.`);

        const args = [];

        for (const arg of node.args) {
          let expr = this.rewrite(arg);

          if (!returnsBool(expr)) {
            if (isLiteral(expr))
              expr = Literal(Number(toBigInt(expr.value) !== 0n));
            else
              expr = IsZero(IsZero(expr));
          }

          if (name.value === 'andl') {
            if (isZero(expr))
              return Literal(0);

            if (isOne(expr))
              continue;
          } else {
            if (isOne(expr))
              return Literal(1);

            if (isZero(expr))
              continue;
          }

          args.push(expr);
        }

        if (args.length === 0) {
          if (name.value === 'andl')
            return Literal(1);
          return Literal(0);
        }

        let acc = args[0];

        for (let i = 1; i < args.length; i++) {
          if (name.value === 'andl')
            acc = And(acc, args[i]);
          else
            acc = Or(acc, args[i]);
        }

        return acc;
      }

      case 'bool': {
        if (node.args.length !== 1)
          throw new Error('bool() requires 1 argument.');

        const expr = this.rewrite(node.args[0]);

        if (returnsBool(expr))
          return expr;

        if (isLiteral(expr))
          return Literal(Number(toBigInt(expr.value) !== 0n));

        return IsZero(IsZero(expr));
      }

      case 'notl': {
        if (node.args.length !== 1)
          throw new Error('notl() requires 1 argument.');

        const expr = this.rewrite(node.args[0]);

        if (isLiteral(expr))
          return Literal(Number(toBigInt(expr.value) === 0n));

        return IsZero(expr);
      }

      case 'ripemd160':
      case 'sha256':
      case 'hash160':
      case 'hash256':
      case 'blake2b160':
      case 'blake2b256':
      case 'keccak160':
      case 'keccak256': {
        switch (node.args.length) {
          case 1: {
            const expr = this.rewrite(node.args[0]);

            if (expr.type === 'Literal') {
              let hash, data;

              switch (name.value) {
                case 'ripemd160':
                  hash = ripemd160;
                  break;
                case 'sha256':
                  hash = sha256;
                  break;
                case 'hash160':
                  hash = hash160;
                  break;
                case 'hash256':
                  hash = hash256;
                  break;
                case 'blake2b160':
                  hash = blake2b160;
                  break;
                case 'blake2b256':
                  hash = blake2b256;
                  break;
                case 'keccak160':
                  hash = keccak160;
                  break;
                case 'keccak256':
                  hash = keccak256;
                  break;
              }

              switch (expr.subtype) {
                case 'HexNumber':
                case 'DecimalNumber':
                case 'BoolLiteral': {
                  const str = toBigInt(expr.value).toString(16);

                  data = Buffer.from(str.padStart(64, '0'), 'hex');

                  break;
                }
                case 'StringLiteral': {
                  data = Buffer.from(JSON.parse(expr.value), 'utf8');
                  break;
                }
                case 'HexLiteral': {
                  data = Buffer.from(expr.value.slice(4, -1), 'hex');
                  break;
                }
                default: {
                  throw new Error(`Invalid argument for ${name.value}().`);
                }
              }

              return Literal(hash.digest(data));
            }

            const func = `__${name.value}_1`;

            scope.dependsOn(func);

            return Call(func, [expr]);
          }

          case 2: {
            if (name.value === 'keccak256')
              return null;

            const func = `__${name.value}_2`;
            const pos = this.rewrite(node.args[0]);
            const len = this.rewrite(node.args[1]);

            scope.dependsOn(func);

            return Call(func, [pos, len]);
          }

          case 3: {
            const func = `__${name.value}_3`;
            const dst = this.rewrite(node.args[0]);
            const src = this.rewrite(node.args[1]);
            const len = this.rewrite(node.args[2]);

            scope.dependsOn(func);

            return Call(func, [dst, src, len]);
          }

          default: {
            throw new Error(`${name.value}() requires 1-3 arguments.`);
          }
        }
      }

      case 'ecrecover': {
        if (node.args.length !== 2 && node.args.length !== 4)
          throw new Error('ecrecover() requires 2 or 4 arguments.');

        if (node.args.length === 2) {
          const dst = this.rewrite(node.args[0]);
          const src = this.rewrite(node.args[1]);

          scope.dependsOn('__ecrecover_2');

          return Call('__ecrecover_2', [dst, src]);
        }

        const m = this.rewrite(node.args[0]);
        const v = this.rewrite(node.args[1]);
        const r = this.rewrite(node.args[2]);
        const s = this.rewrite(node.args[3]);

        scope.dependsOn('__ecrecover_4');

        return Call('__ecrecover_4', [m, v, r, s]);
      }

      case 'ecverify': {
        if (node.args.length < 5 || node.args.length > 6)
          throw new Error('ecverify() requires 5-6 arguments.');

        const func = `__ecverify_${node.args.length}`;
        const args = [];

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        scope.dependsOn(func);

        return Call(func, args);
      }

      case 'revert': {
        if (node.args.length > 2)
          throw new Error('revert() requires 0-2 arguments.');

        if (node.args.length === 2)
          return null;

        return revert;
      }

      case 'revert.debug': {
        if (node.args.length !== 1)
          throw new Error('revert.debug() requires 1 argument.');

        if (!this.debug)
          return Revert();

        const msg = this.rewrite(node.args[0]);

        if (!isStringLiteral(msg))
          throw new Error('Invalid type for revert msg/code.');

        return this.revertString(msg, scope);
      }

      case 'assert':
      case 'require':
      case 'require.ok': {
        if (node.args.length < 1 || node.args.length > 2)
          throw new Error(`${name.value}() requires 1-2 arguments.`);

        if (name.value === 'assert' && !this.debug)
          return Null();

        const expr = this.rewrite(node.args[0]);

        return If(ocj(IsZero(expr)), Block([revert]));
      }

      case 'require.zero':
      case 'require.before':
      case 'require.after':
      case 'require.caller':
      case 'require.origin': {
        if (node.args.length < 1 || node.args.length > 2)
          throw new Error(`${name.value}() requires 1-2 arguments.`);

        const arg = this.rewrite(node.args[0]);

        let expr;

        switch (name.value) {
          case 'require.zero':
            expr = arg;
            break;
          case 'require.before':
            expr = IsZero(Lt(Timestamp(), arg));
            break;
          case 'require.after':
            expr = Lt(Timestamp(), arg);
            break;
          case 'require.caller':
            expr = Xor(Caller(), arg);
            break;
          case 'require.origin':
            expr = Xor(Origin(), arg);
            break;
        }

        return If(expr, Block([revert]));
      }

      case 'require.eq':
      case 'require.neq':
      case 'require.lt':
      case 'require.lte':
      case 'require.gt':
      case 'require.gte':
      case 'require.slt':
      case 'require.slte':
      case 'require.sgt':
      case 'require.sgte':
      case 'require.width': {
        if (node.args.length < 2 || node.args.length > 3)
          throw new Error(`${name.value}() requires 2-3 arguments.`);

        const x = this.rewrite(node.args[0]);
        const y = this.rewrite(node.args[1]);

        let expr;

        switch (name.value) {
          case 'require.eq':
            if (isZero(x))
              expr = y;
            else if (isZero(y))
              expr = x;
            else
              expr = Xor(x, y);
            break;
          case 'require.neq':
            if (isZero(x))
              expr = IsZero(y);
            else if (isZero(y))
              expr = IsZero(x);
            else
              expr = Eq(x, y);
            break;
          case 'require.lt':
            if (isZero(x))
              expr = IsZero(y);
            else
              expr = IsZero(Lt(x, y));
            break;
          case 'require.lte':
            expr = Gt(x, y);
            break;
          case 'require.gt':
            if (isZero(y))
              expr = IsZero(x);
            else
              expr = IsZero(Gt(x, y));
            break;
          case 'require.gte':
            expr = Lt(x, y);
            break;
          case 'require.slt':
            expr = IsZero(Slt(x, y));
            break;
          case 'require.slte':
            expr = Sgt(x, y);
            break;
          case 'require.sgt':
            expr = IsZero(Sgt(x, y));
            break;
          case 'require.sgte':
            expr = Slt(x, y);
            break;
          case 'require.width':
            expr = Call('shr', [y, x]);
            break;
        }

        return If(expr, Block([revert]));
      }

      case 'require.owner': {
        if (node.args.length > 1)
          throw new Error('require.owner() requires 0-1 arguments.');

        const owner = LoadImmutable(Literal('owner'));

        return If(Xor(Caller(), owner), Block([revert]));
      }

      case 'eth.send':
      case 'eth.transfer': {
        if (node.args.length < 2 || node.args.length > 3)
          throw new Error(`${name.value}() requires 2-3 arguments.`);

        const addr = this.rewrite(node.args[0]);
        const amt = this.rewrite(node.args[1]);

        let gas = Gas();

        if (node.args.length === 3)
          gas = this.rewrite(node.args[2]);

        const expr = EthSend(addr, amt, gas);

        if (name.value === 'eth.transfer')
          return If(IsZero(expr), Block([revert]));

        return expr;
      }

      case 'debug': {
        if (node.args.length < 1 || node.args.length > 3)
          throw new Error('debug() requires 1-3 arguments.');

        if (!this.debug)
          return Null();

        const args = [
          Literal(0),
          Literal(0),
          HexNumber(DEBUG_SIG)
        ];

        for (const arg of node.args)
          args.push(this.rewrite(arg));

        if (args.length === 4) {
          if (isLiteral(args[3])) {
            args[3] = Literal(args[3].value);
          } else if (!isStringLiteral(args[3])) {
            const expr = args.pop();
            args.push(Literal('%b'));
            args.push(expr);
          }
        }

        if (!isStringLiteral(args[3]))
          throw new Error('debug(): first argument must be a literal.');

        const log = `log${args.length - 2}`;

        return Call(log, args);
      }

      case 'revert.static': {
        if (node.args.length > 1)
          throw new Error('revert.static() requires 0-1 arguments.');

        let msg = 'Static revert';

        if (node.line >= 0) {
          const file = path.relative(process.cwd(), node.filename);
          msg += ` (${file}:${node.line + 1})`;
        }

        if (node.args.length > 0) {
          const arg = this.rewrite(node.args[0]);

          if (!isStringLiteral(arg))
            throw new Error('Invalid argument for revert.static().');

          msg += ': ' + JSON.parse(arg.value);
        }

        throw new Error(msg);
      }

      case 'assert.static': {
        if (node.args.length < 1 || node.args.length > 2)
          throw new Error('assert.static() requires 1-2 arguments.');

        const expr = this.rewrite(node.args[0]);

        if (isLiteral(expr) && toBigInt(expr.value))
          return Null();

        let msg = 'Static assertion failed';

        if (node.line >= 0) {
          const file = path.relative(process.cwd(), node.filename);
          msg += ` (${file}:${node.line + 1})`;
        }

        if (node.args.length > 1) {
          const arg = this.rewrite(node.args[1]);

          if (!isStringLiteral(arg))
            throw new Error('Invalid argument for assert.static().');

          msg += ': ' + JSON.parse(arg.value);
        }

        throw new Error(msg);
      }

      case 'mcopy': {
        if (node.args.length !== 3)
          throw new Error('mcopy() requires 3 arguments.');

        // https://eips.ethereum.org/EIPS/eip-5656
        if (hardforks[this.hardfork] >= hardforks.cancun)
          return null;

        const dst = this.rewrite(node.args[0]);
        const src = this.rewrite(node.args[1]);
        const len = this.rewrite(node.args[2]);

        scope.dependsOn('__mcopy');

        return Call('__mcopy', [dst, src, len]);
      }

      case 'log2': {
        if (node.args.length !== 1 || this.level < 2)
          return null;

        const arg = this.rewrite(node.args[0]);

        scope.dependsOn('__log2');

        return Call('__log2', [arg]);
      }

      default: {
        return null;
      }
    }
  }

  revertString(str, scope) {
    const msg = JSON.parse(str.value);

    if (msg.length <= 32) {
      scope.dependsOn('__revert32');
      return Call('__revert32', [str, Literal(msg.length)]);
    }

    if (msg.length <= 64) {
      const left = msg.substring(0, 32);
      const right = msg.substring(32);

      scope.dependsOn('__revert64');

      return Call('__revert64', [Literal(left),
                                 Literal(right),
                                 Literal(msg.length)]);
    }

    const name = scope.addData('revert', str);

    scope.dependsOn('__revert_data');

    return Call('__revert_data', [
      DataOffset(name),
      DataSize(name)
    ]);
  }

  revertInt(code, scope) {
    scope.dependsOn('__revert_int');
    return Call('__revert_int', [code]);
  }

  revertPanic(code, scope) {
    scope.dependsOn('__panic');
    return Call('__panic', [code]);
  }
}

/*
 * Serializer
 */

class Serializer {
  constructor(root) {
    this.root = root;
  }

  serialize() {
    return this.encode(this.root);
  }

  encode(node) {
    switch (node.type) {
      case 'Root': {
        const out = [];

        for (const child of node.nodes)
          out.push(this.encode(child));

        return out.join('\n');
      }

      case 'Pragma': {
        const value = JSON.stringify(node.value);
        return `pragma ${node.name} ${value}`;
      }

      case 'Fold': {
        let str = '@if';

        str += ' ';
        str += this.encode(node.expr);
        str += ' ';
        str += '{\n';
        str += indent(this.encode(node.block), 2);
        str += '\n}';

        for (const [expr, block] of node.branches) {
          str += ' ';
          str += 'elif';
          str += ' ';
          str += this.encode(expr);
          str += ' ';
          str += '{\n';
          str += indent(this.encode(block), 2);
          str += '\n}';
        }

        if (node.otherwise) {
          str += ' ';
          str += 'else';
          str += ' ';
          str += '{\n';
          str += indent(this.encode(node.otherwise), 2);
          str += '\n}';
        }

        return str;
      }

      case 'IncludeCall': {
        return `include(${JSON.stringify(node.name)})`;
      }

      case 'Enum': {
        let str = 'enum';

        if (node.name) {
          str += ' ';
          str += this.encode(node.name);
        }

        str += ' ';
        str += '{\n';

        for (const [name, expr] of node.members) {
          str += '  ';
          str += this.encode(name);

          if (expr) {
            str += ' := ';
            str += this.encode(expr);
          }

          str += '\n';
        }

        str += '}';

        return str;
      }

      case 'StructDefinition': {
        let str = `struct ${node.name.value} {\n`;

        for (const member of node.members)
          str += '  ' + this.encode(member) + '\n';

        str += '}';

        return str;
      }

      case 'StructMember': {
        let str = '';

        str += this.encode(node.kind);
        str += ' ';
        str += this.encode(node.name);

        if (!isZero(node.value)) {
          str += ' := ';
          str += this.encode(node.value);
        }

        return str;
      }

      case 'Interface': {
        let str = 'interface';

        str += ' ';
        str += this.encode(node.name);
        str += ' ';

        str += '{\n';

        if (node.ctor)
          str += '  ' + this.encode(node.ctor) + '\n';

        for (const decl of node.decls)
          str += '  ' + this.encode(decl) + '\n';

        str += '}';

        return str;
      }

      case 'Contract': {
        let str = 'contract';

        str += ' ';
        str += this.encode(node.name);
        str += ' ';

        if (node.modifier)
          str += node.modifier + ' ';

        str += this.encode(node.block);

        return str;
      }

      case 'ObjectBlock': {
        return 'object ' + JSON.stringify(node.name) + ' '
                         + this.encode(node.block);
      }

      case 'CodeBlock': {
        return 'code ' + this.encode(node.block);
      }

      case 'ConstructorDeclaration':
      case 'ConstructorDefinition': {
        let str = 'constructor';

        str += '(';
        str += this.encode(node.params);
        str += ')';

        if (node.mutability)
          str += ' ' + node.mutability;

        if (node.modifier)
          str += ' ' + node.modifier;

        if (node.block) {
          str += ' ';
          str += this.encode(node.block);
        }

        return str;
      }

      case 'DataValue': {
        return 'data ' + JSON.stringify(node.name) + ' '
                       + this.encode(node.value);
      }

      case 'Block': {
        const out = [];

        for (const child of node.body)
          out.push(this.encode(child));

        if (out.length === 0)
          return '{}';

        const body = indent(out.join('\n'), 2);

        return `{\n${body}\n}`;
      }

      case 'MacroConstant': {
        let str = `macro ${node.name} := `;
        str += this.encode(node.expr);
        return str;
      }

      case 'MacroDefinition': {
        let str = `macro ${node.name}`;

        str += '(' + node.params.join(', ') + ')';

        if (node.block.body.length === 1 &&
            isExpression(node.block.body[0])) {
          str += ' := ';
          str += this.encode(node.block.body[0]);
        } else {
          str += ' ';
          str += this.encode(node.block);
        }

        return str;
      }

      case 'FunctionDefinition': {
        let str = 'function';

        str += ' ';
        str += this.encode(node.name);
        str += '(';
        str += this.encode(node.params);
        str += ')';

        if (node.modifier)
          str += ' ' + node.modifier;

        if (node.returns.items.length > 0)
          str += ' -> ' + this.encode(node.returns);

        str += ' ';
        str += this.encode(node.block);

        return str;
      }

      case 'MethodDeclaration':
      case 'MethodDefinition': {
        let str = 'method';

        str += ' ';
        str += this.encode(node.name);
        str += '(';
        str += this.encode(node.params);
        str += ')';

        if (node.visibility)
          str += ' ' + node.visibility;

        if (node.mutability)
          str += ' ' + node.mutability;

        if (node.modifier)
          str += ' ' + node.modifier;

        if (node.returns.items.length > 0)
          str += ' returns (' + this.encode(node.returns) + ')';

        if (node.block) {
          str += ' ';
          str += this.encode(node.block);
        }

        return str;
      }

      case 'MethodParams': {
        const params = [];

        for (const [type, name] of node.items) {
          if (name)
            params.push([this.encode(type), this.encode(name)].join(' '));
          else
            params.push(this.encode(type));
        }

        return params.join(', ');
      }

      case 'EventDeclaration': {
        let str = 'event';

        str += ' ';
        str += this.encode(node.name);
        str += '(';
        str += this.encode(node.params);
        str += ')';

        if (node.anonymous)
          str += ' anonymous';

        if (node.packed)
          str += ' packed';

        if (node.modifier)
          str += ' ' + node.modifier;

        return str;
      }

      case 'EventParams': {
        const params = [];

        for (const [type, name, indexed] of node.items) {
          let param = this.encode(type);

          if (indexed)
            param += ' indexed';

          if (name)
            param += ' ' + this.encode(name);

          params.push(param);
        }

        return params.join(', ');
      }

      case 'ErrorDeclaration': {
        let str = 'error';

        str += ' ';
        str += this.encode(node.name);
        str += '(';
        str += this.encode(node.params);
        str += ')';

        return str;
      }

      case 'ABIType': {
        return node.value;
      }

      case 'VariableDeclaration': {
        let str = 'let';

        str += ' ';
        str += this.encode(node.vars);

        if (node.expr) {
          str += ' := ';
          str += this.encode(node.expr);
        }

        return str;
      }

      case 'ConstDeclaration': {
        let str = 'const';
        str += ' ';
        str += this.encode(node.name);
        if (node.wrap)
          str += '()';
        str += ' := ';
        str += this.encode(node.expr);
        return str;
      }

      case 'TypedIdentifierList': {
        const idents = [];

        for (const [ident, kind] of node.items) {
          const name = this.encode(ident);
          const type = kind ? this.encode(kind) : null;

          if (type)
            idents.push([name, type].join(':'));
          else
            idents.push(name);
        }

        return idents.join(', ');
      }

      case 'MemberAssignment': {
        let str = '';
        str += this.encode(node.lhs);
        str += node.or ? ' |= ' : ' := ';
        str += this.encode(node.rhs);
        return str;
      }

      case 'Assignment': {
        let str = '';
        str += this.encode(node.lhs);
        str += ' := ';
        str += this.encode(node.rhs);
        return str;
      }

      case 'IdentifierList': {
        const idents = [];

        for (const ident of node.items)
          idents.push(this.encode(ident));

        return idents.join(', ');
      }

      case 'If': {
        let str = 'if';

        str += ' ';
        str += this.encode(node.expr);
        str += ' ';
        str += this.encode(node.block);

        for (const [expr, block] of node.branches) {
          str += ' ';
          str += 'elif';
          str += ' ';
          str += this.encode(expr);
          str += ' ';
          str += this.encode(block);
        }

        if (node.otherwise) {
          str += ' ';
          str += 'else';
          str += ' ';
          str += this.encode(node.otherwise);
        }

        return str;
      }

      case 'Switch': {
        let str = 'switch';

        str += ' ';
        str += this.encode(node.expr);
        str += '\n';

        for (const case_ of node.cases)
          str += this.encode(case_) + '\n';

        if (node.def)
          str += this.encode(node.def) + '\n';

        return str.slice(0, -1);
      }

      case 'Case': {
        let str = 'case';

        str += ' ';
        str += this.encode(node.value);
        str += ' ';
        str += this.encode(node.block);

        return str;
      }

      case 'Default': {
        let str = 'default';
        str += ' ';
        str += this.encode(node.block);
        return str;
      }

      case 'MethodSignature':
      case 'EventSignature':
      case 'ErrorSignature': {
        let str = 'method';

        if (node.type === 'EventSignature')
          str = 'event';
        else if (node.type === 'ErrorSignature')
          str = 'error';

        str += '(';
        str += this.encode(node.name);

        if (node.params)
          str += '(' + this.encode(node.params) + ')';

        str += ')';

        return str;
      }

      case 'ForLoop': {
        let str = 'for';

        str += ' ' + this.encode(node.init);
        str += ' ' + this.encode(node.test);
        str += ' ' + this.encode(node.update);
        str += ' ' + this.encode(node.block);

        return str;
      }

      case 'While': {
        let str = 'while';

        str += ' ' + this.encode(node.test);
        str += ' ' + this.encode(node.block);

        return str;
      }

      case 'DoWhile': {
        let str = 'do';

        str += ' ' + this.encode(node.block);
        str += ' while';
        str += ' ' + this.encode(node.test);

        return str;
      }

      case 'BreakContinue': {
        return node.value;
      }

      case 'Leave': {
        return 'leave';
      }

      case 'Emit':
      case 'Throw': {
        const type = node.type.toLowerCase();
        const name = this.encode(node.name);
        const offset = this.encode(node.offset);
        const args = [];

        for (const arg of node.args)
          args.push(this.encode(arg));

        return `${type} ${name}(${offset}, ${args.join(', ')})`;
      }

      case 'StructInitializer': {
        let str = 'struct(';

        str += this.encode(node.name);

        if (node.args.length > 0) {
          const args = [];

          str += ', ';

          for (const arg of node.args)
            args.push(this.encode(arg));

          str += args.join(', ');
        }

        str += ')';

        return str;
      }

      case 'InterfaceCall': {
        let str = '';

        str += node.kind;

        if (node.attempt)
          str += '?';

        str += ' ';
        str += this.encode(node.name);

        if (node.method)
          str += '.' + this.encode(node.method);

        str += '(';

        const args = [];

        for (const arg of node.args)
          args.push(this.encode(arg));

        str += args.join(', ');
        str += ')';

        return str;
      }

      case 'FunctionCall': {
        const name = this.encode(node.name);
        const args = [];

        for (const arg of node.args)
          args.push(this.encode(arg));

        return `${name}(${args.join(', ')})`;
      }

      case 'Literal': {
        if (node.kind)
          return node.value + ':' + this.encode(node.kind);

        return node.value;
      }

      case 'MemberIdentifier': {
        let str = this.encode(node.name);

        if (node.cast)
          str += ':' + this.encode(node.cast);

        str += '->' + this.encode(node.member);

        return str;
      }

      case 'CallDataIdentifier': {
        let str = node.ref ? '&' : '';
        str += 'calldata.';
        str += this.encode(node.member);
        return str;
      }

      case 'Identifier': {
        return node.value;
      }

      default: {
        throw new Error('unreachable');
      }
    }
  }
}

/*
 * Hasher
 */

class Hasher {
  constructor(root) {
    this.root = root;
    this.hash = sha256.hash();
    this.seen = new Set();
    this.metadata = DataValue('.metadata', HexLiteral(''));
  }

  init(filename, code) {
    this.hash.init();
    this.seen.clear();
    this.update(filename, code);
  }

  update(filename, code) {
    if (this.seen.has(filename))
      return;

    const name = path.relative(this.root, filename);
    const chunk1 = Buffer.from(name, 'utf8');
    const chunk2 = Buffer.from(code, 'utf8');

    this.hash.update(sha256.digest(chunk1));
    this.hash.update(sha256.digest(chunk2));

    this.seen.add(filename);
  }

  final() {
    const hash = this.hash.final();

    this.metadata.value = HexLiteral(hash.toString('hex'));

    return hash;
  }
}

/*
 * ABI
 */

class ABI {
  constructor() {
    this.contracts = Object.create(null);
    this.license = 'UNLICENSED';
    this.version = '>=0.8.0';
  }

  init(block) {
    const {name, comment} = block;

    if (this.contracts[name])
      throw new Error(`Duplicate contract name: ${name}`);

    this.contracts[name] = {
      items: new Set(),
      names: new Set(),
      signatures: new Map(),
      comment
    };
  }

  add(object, scope) {
    const block = scope.findContractBlock();

    if (!block)
      return;

    const contract = this.contracts[block.name];

    assert(contract != null);

    if (contract.items.has(object))
      return;

    contract.items.add(object);

    this._addName(contract, object);

    if (object.signature)
      this._addSignature(contract, object, object.signature);
  }

  _addName(contract, object) {
    const {type, name} = object;
    const key =`${type}:${name}`;

    if (contract.names.has(key))
      throw new Error(`${type} ${name} already defined.`);

    contract.names.add(key);
  }

  _addSignature(contract, object, signature) {
    const {type, name} = object;
    const key =`${type}:${signature}`;

    if (contract.signatures.has(key)) {
      const other = contract.signatures.get(key);
      throw new Error(`${type} ${name} collides with ${other}.`);
    }

    contract.signatures.set(key, name);
  }

  _sort(items) {
    const ctors = [];
    const funcs = [];
    const events = [];
    const errors = [];

    for (const item of items) {
      switch (item.type) {
        case 'constructor':
          ctors.push(item);
          break;
        case 'function':
          funcs.push(item);
          break;
        case 'event':
          events.push(item);
          break;
        case 'error':
          errors.push(item);
          break;
      }
    }

    return [
      ...ctors,
      ...funcs,
      ...events,
      ...errors
    ];
  }

  toStrings() {
    const result = Object.create(null);

    for (const name of Object.keys(this.contracts)) {
      const {items} = this.contracts[name];
      const out = [];

      for (const item of this._sort(items))
        out.push(item.toString());

      result[name] = out;
    }

    return result;
  }

  toObjects() {
    const result = Object.create(null);

    for (const name of Object.keys(this.contracts)) {
      const {items} = this.contracts[name];
      const out = [];

      for (const item of this._sort(items))
        out.push(item.toObject());

      result[name] = out;
    }

    return result;
  }

  toJSON(solabi) {
    if (solabi)
      return this.toObjects();
    return this.toStrings();
  }

  toHashes() {
    const result = [];

    for (const name of Object.keys(this.contracts)) {
      const {items} = this.contracts[name];
      const funcs = [];
      const events = [];
      const errors = [];

      for (const item of items) {
        if (item.type === 'function')
          funcs.push([item.name, item.signature]);
        else if (item.type === 'event')
          events.push([item.name, item.signature]);
        else if (item.type === 'error')
          errors.push([item.name, item.signature]);
      }

      result.push({
        name,
        funcs,
        events,
        errors
      });
    }

    return result;
  }

  toCode() {
    const result = Object.create(null);

    for (const name of Object.keys(this.contracts)) {
      const {items, comment} = this.contracts[name];

      let out = '';

      out += eol(comment);
      out += `interface ${name} {`;

      for (const item of this._sort(items)) {
        if (item.type === 'function' && !item.isFunction())
          continue;

        if (item.type === 'event')
          continue;

        if (item.type === 'error')
          continue;

        out += '\n';
        out += indent(item.toCode(), 2) + '\n';
      }

      out += '}';

      result[name] = out;
    }

    return result;
  }

  toSolidity() {
    const result = Object.create(null);

    for (const name of Object.keys(this.contracts)) {
      const {items, comment} = this.contracts[name];

      let out = '';

      out += `// SPDX-License-Identifier: ${this.license}\n`;
      out += '\n';
      out += `pragma solidity ${this.version};\n`;
      out += '\n';

      out += eol(comment);
      out += `interface ${name} {`;

      for (const item of this._sort(items)) {
        if (item.type === 'function' && !item.isFunction())
          continue;

        out += '\n';
        out += indent(item.toSolidity(), 2) + '\n';
      }

      out += '}';

      result[name] = out;
    }

    return result;
  }
}

/*
 * Rewriter
 */

class Rewriter {
  constructor(root, callback) {
    this.root = root;
    this.callback = callback;
  }

  serialize() {
    return this.encode(this.root);
  }

  rewrite(node) {
    return this.callback(node);
  }

  encode(node) {
    if (node === null)
      return null;

    switch (node.type) {
      case 'Root': {
        return this.rewrite({
          type: 'Root',
          nodes: filter(node.nodes.map(n => this.encode(n)))
        });
      }

      case 'Pragma': {
        return this.rewrite({
          type: 'Pragma',
          name: node.name,
          value: node.value
        });
      }

      case 'IncludeCall': {
        return this.rewrite({
          type: 'IncludeCall',
          root: node.root,
          name: node.name
        });
      }

      case 'Enum': {
        return this.rewrite({
          type: 'Enum',
          name: this.encode(node.name),
          members: node.members.map(([name, expr]) => {
            return [this.encode(name), this.encode(expr)];
          })
        });
      }

      case 'StructDefinition': {
        return this.rewrite({
          type: 'StructDefinition',
          name: this.encode(node.name),
          members: node.members.map(m => this.encode(m))
        });
      }

      case 'StructMember': {
        return this.rewrite({
          type: 'StructMember',
          kind: this.encode(node.kind),
          name: this.encode(node.name),
          value: this.encode(node.value)
        });
      }

      case 'Interface': {
        return this.rewrite({
          type: 'Interface',
          name: this.encode(node.name),
          ctor: this.encode(node.ctor),
          decls: node.decls.map(n => this.encode(n)),
          comment: node.comment
        });
      }

      case 'Contract': {
        return this.rewrite({
          type: 'Contract',
          name: this.encode(node.name),
          modifier: node.modifier,
          block: this.encode(node.block),
          comment: node.comment
        });
      }

      case 'ObjectBlock': {
        return this.rewrite({
          type: 'ObjectBlock',
          name: node.name,
          block: this.encode(node.block),
          comment: node.comment
        });
      }

      case 'CodeBlock': {
        return this.rewrite({
          type: 'CodeBlock',
          block: this.encode(node.block)
        });
      }

      case 'ConstructorDeclaration':
      case 'ConstructorDefinition': {
        return this.rewrite({
          type: node.type,
          params: this.encode(node.params),
          mutability: node.mutability,
          modifier: node.modifier,
          block: this.encode(node.block),
          comment: node.comment
        });
      }

      case 'DataValue': {
        return this.rewrite({
          type: 'DataValue',
          name: node.name,
          value: this.encode(node.value)
        });
      }

      case 'Block': {
        return this.rewrite({
          type: 'Block',
          body: filter(node.body.map(n => this.encode(n)))
        });
      }

      case 'MacroConstant': {
        return {
          type: 'MacroConstant',
          name: node.name,
          expr: this.encode(node.expr)
        };
      }

      case 'MacroDefinition': {
        return this.rewrite({
          type: 'MacroDefinition',
          name: node.name,
          params: node.params,
          block: this.encode(node.block)
        });
      }

      case 'FunctionDefinition': {
        return this.rewrite({
          type: 'FunctionDefinition',
          name: this.encode(node.name),
          params: this.encode(node.params),
          modifier: node.modifier,
          returns: this.encode(node.returns),
          block: this.encode(node.block),
          builtin: node.builtin
        });
      }

      case 'MethodDeclaration':
      case 'MethodDefinition': {
        return this.rewrite({
          type: node.type,
          name: this.encode(node.name),
          params: this.encode(node.params),
          visibility: node.visibility,
          mutability: node.mutability,
          modifier: node.modifier,
          returns: this.encode(node.returns),
          block: this.encode(node.block),
          comment: node.comment
        });
      }

      case 'MethodParams': {
        return this.rewrite({
          type: 'MethodParams',
          items: node.items.map(([type, name]) => {
            return [this.encode(type), this.encode(name)];
          })
        });
      }

      case 'EventDeclaration': {
        return this.rewrite({
          type: 'EventDeclaration',
          name: this.encode(node.name),
          params: this.encode(node.params),
          anonymous: node.anonymous,
          packed: node.packed,
          modifier: node.modifier,
          comment: node.comment
        });
      }

      case 'EventParams': {
        return this.rewrite({
          type: 'EventParams',
          items: node.items.map(([type, name, indexed]) => {
            return [this.encode(type), this.encode(name), indexed];
          })
        });
      }

      case 'ErrorDeclaration': {
        return this.rewrite({
          type: 'ErrorDeclaration',
          name: this.encode(node.name),
          params: this.encode(node.params),
          comment: node.comment
        });
      }

      case 'ABIType': {
        return this.rewrite({
          type: 'ABIType',
          value: node.value,
          base: node.base,
          width: node.width,
          array: node.array
        });
      }

      case 'VariableDeclaration': {
        return this.rewrite({
          type: 'VariableDeclaration',
          vars: this.encode(node.vars),
          expr: this.encode(node.expr)
        });
      }

      case 'ConstDeclaration': {
        return this.rewrite({
          type: 'ConstDeclaration',
          name: this.encode(node.name),
          expr: this.encode(node.expr),
          wrap: node.wrap
        });
      }

      case 'TypedIdentifierList': {
        return this.rewrite({
          type: 'TypedIdentifierList',
          items: node.items.map(([name, type]) => {
            return [this.encode(name), this.encode(type)];
          })
        });
      }

      case 'MemberAssignment': {
        return this.rewrite({
          type: 'MemberAssignment',
          or: node.or,
          lhs: this.encode(node.lhs),
          rhs: this.encode(node.rhs)
        });
      }

      case 'Assignment': {
        return this.rewrite({
          type: 'Assignment',
          lhs: this.encode(node.lhs),
          rhs: this.encode(node.rhs)
        });
      }

      case 'IdentifierList': {
        return this.rewrite({
          type: 'IdentifierList',
          items: node.items.map(n => this.encode(n))
        });
      }

      case 'Fold':
      case 'If': {
        return this.rewrite({
          type: node.type,
          expr: this.encode(node.expr),
          block: this.encode(node.block),
          branches: node.branches.map(([expr, block]) => {
            return [this.encode(expr), this.encode(block)];
          }),
          otherwise: this.encode(node.otherwise)
        });
      }

      case 'Switch': {
        return this.rewrite({
          type: 'Switch',
          expr: this.encode(node.expr),
          cases: node.cases.map(n => this.encode(n)),
          def: this.encode(node.def)
        });
      }

      case 'Case': {
        return this.rewrite({
          type: 'Case',
          value: this.encode(node.value),
          block: this.encode(node.block)
        });
      }

      case 'Default': {
        return this.rewrite({
          type: 'Default',
          block: this.encode(node.block)
        });
      }

      case 'MethodSignature':
      case 'EventSignature':
      case 'ErrorSignature': {
        return this.rewrite({
          type: node.type,
          name: this.encode(node.name),
          params: this.encode(node.params)
        });
      }

      case 'ForLoop': {
        return this.rewrite({
          type: 'ForLoop',
          init: this.encode(node.init),
          test: this.encode(node.test),
          update: this.encode(node.update),
          block: this.encode(node.block)
        });
      }

      case 'While':
      case 'DoWhile': {
        return this.rewrite({
          type: node.type,
          test: this.encode(node.test),
          block: this.encode(node.block)
        });
      }

      case 'BreakContinue': {
        return this.rewrite({
          type: 'BreakContinue',
          value: node.value
        });
      }

      case 'Leave': {
        return this.rewrite({
          type: 'Leave'
        });
      }

      case 'Emit':
      case 'Throw': {
        return this.rewrite({
          type: node.type,
          name: this.encode(node.name),
          offset: this.encode(node.offset),
          args: node.args.map(n => this.encode(n))
        });
      }

      case 'StructInitializer': {
        return this.rewrite({
          type: 'StructInitializer',
          name: this.encode(node.name),
          args: node.args.map(n => this.encode(n))
        });
      }

      case 'InterfaceCall': {
        return this.rewrite({
          type: 'InterfaceCall',
          kind: node.kind,
          attempt: node.attempt,
          name: this.encode(node.name),
          method: this.encode(node.method),
          args: node.args.map(n => this.encode(n))
        });
      }

      case 'FunctionCall': {
        return this.rewrite({
          type: 'FunctionCall',
          name: this.encode(node.name),
          args: node.args.map(n => this.encode(n)),
          filename: node.filename,
          line: node.line
        });
      }

      case 'Literal': {
        return this.rewrite({
          type: 'Literal',
          subtype: node.subtype,
          kind: this.encode(node.kind),
          value: node.value
        });
      }

      case 'MemberIdentifier': {
        return this.rewrite({
          type: 'MemberIdentifier',
          name: this.encode(node.name),
          cast: this.encode(node.cast),
          member: this.encode(node.member)
        });
      }

      case 'CallDataIdentifier': {
        return this.rewrite({
          type: 'CallDataIdentifier',
          member: this.encode(node.member),
          ref: node.ref
        });
      }

      case 'Identifier': {
        return this.rewrite({
          type: 'Identifier',
          value: node.value,
          replaceable: node.replaceable
        });
      }

      default: {
        throw new Error('unreachable');
      }
    }
  }
}

/*
 * Visitor
 */

function* traverse(node) {
  switch (node.type) {
    case 'Root': {
      yield node;
      for (const child of node.nodes)
        yield* traverse(child);
      break;
    }

    case 'Pragma': {
      yield node;
      break;
    }

    case 'IncludeCall': {
      yield node;
      break;
    }

    case 'Enum': {
      yield node;
      if (node.name)
        yield* traverse(node.name);
      for (const [name, expr] of node.members) {
        yield* traverse(name);
        if (expr)
          yield* traverse(expr);
      }
      break;
    }

    case 'StructDefinition': {
      yield node;
      yield* traverse(node.name);
      for (const member of node.members)
        yield* traverse(member);
      break;
    }

    case 'StructMember': {
      yield node;
      yield* traverse(node.kind);
      yield* traverse(node.name);
      yield* traverse(node.value);
      break;
    }

    case 'Interface': {
      yield node;
      yield* traverse(node.name);
      if (node.ctor)
        yield* traverse(node.ctor);
      for (const decl of node.decls)
        yield* traverse(decl);
      break;
    }

    case 'Contract': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.block);
      yield { type: 'ContractEnd' };
      break;
    }

    case 'ObjectBlock': {
      yield node;
      yield* traverse(node.block);
      yield { type: 'ObjectEnd' };
      break;
    }

    case 'CodeBlock': {
      yield node;
      yield* traverse(node.block);
      yield { type: 'CodeEnd' };
      break;
    }

    case 'ConstructorDeclaration':
    case 'ConstructorDefinition': {
      yield node;
      yield* traverse(node.params);
      if (node.block)
        yield* traverse(node.block);
      if (node.type === 'ConstructorDefinition')
        yield { type: 'ConstructorEnd' };
      break;
    }

    case 'DataValue': {
      yield node;
      yield* traverse(node.value);
      break;
    }

    case 'Block': {
      yield node;
      for (const child of node.body)
        yield* traverse(child);
      yield { type: 'BlockEnd' };
      break;
    }

    case 'MacroConstant': {
      yield node;
      yield* traverse(node.expr);
      break;
    }

    case 'MacroDefinition': {
      yield node;
      yield* traverse(node.block);
      break;
    }

    case 'FunctionDefinition':
    case 'MethodDeclaration':
    case 'MethodDefinition': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.params);
      yield* traverse(node.returns);
      if (node.block)
        yield* traverse(node.block);
      if (node.type === 'FunctionDefinition')
        yield { type: 'FunctionEnd' };
      else if (node.type === 'MethodDefinition')
        yield { type: 'MethodEnd' };
      break;
    }

    case 'MethodParams': {
      yield node;
      for (const [type, name] of node.items) {
        yield* traverse(type);
        if (name)
          yield* traverse(name);
      }
      break;
    }

    case 'EventDeclaration': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.params);
      break;
    }

    case 'EventParams': {
      yield node;
      for (const [type,, name] of node.items) {
        yield* traverse(type);
        if (name)
          yield* traverse(name);
      }
      break;
    }

    case 'ErrorDeclaration': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.params);
      break;
    }

    case 'ABIType': {
      yield node;
      break;
    }

    case 'VariableDeclaration': {
      yield node;
      yield* traverse(node.vars);
      if (node.expr)
        yield* traverse(node.expr);
      break;
    }

    case 'ConstDeclaration': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.expr);
      break;
    }

    case 'TypedIdentifierList': {
      yield node;
      for (const [name, type] of node.items) {
        yield* traverse(name);
        if (type)
          yield* traverse(type);
      }
      break;
    }

    case 'MemberAssignment':
    case 'Assignment': {
      yield node;
      yield* traverse(node.lhs);
      yield* traverse(node.rhs);
      break;
    }

    case 'IdentifierList': {
      yield node;
      for (const ident of node.items)
        yield* traverse(ident);
      break;
    }

    case 'Fold':
    case 'If': {
      yield node;
      yield* traverse(node.expr);
      yield* traverse(node.block);
      for (const [expr, block] of node.branches) {
        yield* traverse(expr);
        yield* traverse(block);
      }
      if (node.otherwise)
        yield* traverse(node.otherwise);
      break;
    }

    case 'Switch': {
      yield node;
      yield* traverse(node.expr);
      for (const case_ of node.cases)
        yield* traverse(case_);
      if (node.def)
        yield* traverse(node.def);
      break;
    }

    case 'Case': {
      yield node;
      yield* traverse(node.value);
      yield* traverse(node.block);
      break;
    }

    case 'Default': {
      yield node;
      yield* traverse(node.block);
      break;
    }

    case 'MethodSignature':
    case 'EventSignature':
    case 'ErrorSignature': {
      yield node;
      yield* traverse(node.name);
      if (node.params)
        yield* traverse(node.params);
      break;
    }

    case 'ForLoop': {
      yield node;
      yield* traverse(node.init);
      yield* traverse(node.test);
      yield* traverse(node.update);
      yield* traverse(node.block);
      break;
    }

    case 'While':
    case 'DoWhile': {
      yield node;
      yield* traverse(node.test);
      yield* traverse(node.block);
      break;
    }

    case 'BreakContinue': {
      yield node;
      break;
    }

    case 'Leave': {
      yield node;
      break;
    }

    case 'Emit':
    case 'Throw': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.offset);
      for (const arg of node.args)
        yield* traverse(arg);
      break;
    }

    case 'StructInitializer': {
      yield node;
      yield* traverse(node.name);
      for (const arg of node.args)
        yield* traverse(arg);
      break;
    }

    case 'InterfaceCall': {
      yield node;
      yield* traverse(node.name);
      if (node.method)
        yield* traverse(node.method);
      for (const arg of node.args)
        yield* traverse(arg);
      break;
    }

    case 'FunctionCall': {
      yield node;
      yield* traverse(node.name);
      for (const arg of node.args)
        yield* traverse(arg);
      break;
    }

    case 'Literal': {
      yield node;
      if (node.kind)
        yield* traverse(node.kind);
      break;
    }

    case 'MemberIdentifier': {
      yield node;
      yield* traverse(node.name);
      yield* traverse(node.member);
      break;
    }

    case 'CallDataIdentifier': {
      yield node;
      yield* traverse(node.member);
      break;
    }

    case 'Identifier': {
      yield node;
      break;
    }

    default: {
      throw new Error('unreachable');
    }
  }
}

/*
 * Macro Expansion
 */

const mapCache = new WeakMap();

function expand(macro, args) {
  assert(macro.type === 'MacroDefinition');

  if (args.length !== macro.params.length)
    throw new Error(`Invalid arguments for macro: ${macro.name}`);

  if (!mapCache.has(macro)) {
    const map = new Map();

    for (let i = 0; i < macro.params.length; i++)
      map.set(macro.params[i], i);

    mapCache.set(macro, map);
  }

  const map = mapCache.get(macro);

  const block = rewrite(macro.block, (node) => {
    if (node.type === 'Identifier') {
      const index = map.get(node.value);

      if (index != null)
        return args[index];
    }

    return node;
  });

  if (block.body.length === 1)
    return block.body[0];

  return Root(block.body);
}

/*
 * Expression Folding
 */

function fold(name, args) {
  switch (name.value) {
    case 'add': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]))
        return args[1];

      if (isZero(args[1]))
        return args[0];

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x + y);
    }

    case 'sub': {
      if (args.length !== 2)
        return null;

      if (isZero(args[1]))
        return args[0];

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x - y);
    }

    case 'mul': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]) || isZero(args[1]))
        return Literal(0);

      if (isOne(args[0]))
        return args[1];

      if (isOne(args[1]))
        return args[0];

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x * y);
    }

    case 'div':
    case 'sdiv': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]) || isZero(args[1]))
        return Literal(0);

      if (name.value === 'div' && isOne(args[1]))
        return args[0];

      if (!isLiterals(args))
        return null;

      let x = toBigInt(args[0].value);
      let y = toBigInt(args[1].value);

      if (name.value === 'sdiv') {
        if (x & I256_SIGN)
          x = -(-x & U256_MAX);
        if (y & I256_SIGN)
          y = -(-y & U256_MAX);
      }

      return Literal(x / y);
    }

    case 'mod':
    case 'smod': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]) || isZero(args[1]))
        return Literal(0);

      if (isOne(args[1]))
        return Literal(0);

      if (!isLiterals(args))
        return null;

      let x = toBigInt(args[0].value);
      let y = toBigInt(args[1].value);

      if (name.value === 'smod') {
        if (x & I256_SIGN)
          x = -(-x & U256_MAX);
        if (y & I256_SIGN)
          y = -(-y & U256_MAX);
      }

      return Literal(x % y);
    }

    case 'exp': {
      if (args.length !== 2)
        return null;

      if (isZero(args[1]))
        return Literal(1);

      if (isOne(args[1]))
        return args[0];

      if (isZero(args[0]))
        return Literal(0);

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x ** y);
    }

    case 'addmod': {
      if (args.length !== 3)
        return null;

      if (isZero(args[2]))
        return Literal(0);

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);
      const m = toBigInt(args[2].value);

      return Literal((x + y) % m);
    }

    case 'mulmod': {
      if (args.length !== 3)
        return null;

      if (isZero(args[0]) || isZero(args[1]) || isZero(args[2]))
        return Literal(0);

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);
      const m = toBigInt(args[2].value);

      return Literal((x * y) % m);
    }

    case 'not': {
      if (args.length !== 1)
        return null;

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);

      return Literal(x ^ U256_MAX);
    }

    case 'and': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]))
        return Literal(0);

      if (isZero(args[1]))
        return Literal(0);

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x & y);
    }

    case 'or': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]))
        return args[1];

      if (isZero(args[1]))
        return args[0];

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x | y);
    }

    case 'xor': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]))
        return args[1];

      if (isZero(args[1]))
        return args[0];

      if (!isLiterals(args))
        return null;

      const x = toBigInt(args[0].value);
      const y = toBigInt(args[1].value);

      return Literal(x ^ y);
    }

    case 'shl': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]))
        return args[1];

      if (!isLiterals(args))
        return null;

      const shift = toBigInt(args[0].value);
      const num = toBigInt(args[1].value);

      return Literal(num << shift);
    }

    case 'shr':
    case 'sar': {
      if (args.length !== 2)
        return null;

      if (isZero(args[0]))
        return args[1];

      if (!isLiterals(args))
        return null;

      const shift = toBigInt(args[0].value);

      let num = toBigInt(args[1].value);

      if (name.value === 'sar') {
        if (num & I256_SIGN)
          num = -(-num & U256_MAX);
      }

      return Literal(num >> shift);
    }

    case 'signextend': {
      if (args.length !== 2)
        return null;

      if (!isLiterals(args))
        return null;

      const b = toBigInt(args[0].value);
      const x = toBigInt(args[1].value);

      if (b > 31n)
        return Literal(x);

      const bit = b * 8n + 7n;
      const mask = (1n << bit) - 1n;

      if (x & (1n << bit))
        return Literal(x | (mask ^ U256_MAX));

      return Literal(x & mask);
    }

    case 'byte': {
      if (args.length !== 2)
        return null;

      if (!isLiterals(args))
        return null;

      const pos = toBigInt(args[0].value);
      const num = toBigInt(args[1].value);

      if (pos > 31n)
        return Literal(0);

      const shift = (31n - pos) << 3n;

      return Literal((num >> shift) & 0xffn);
    }

    case 'iszero': {
      if (args.length !== 1)
        return null;

      if (isLtCall(args[0])) { // gte(x, y)
        const [x, y] = args[0].args;

        if (isLiteral(y)) {
          const n = toBigInt(y.value);

          if (n === 0n)
            return Literal(1);

          return Gt(x, Literal(n - 1n));
        }
      }

      if (isGtCall(args[0])) { // lte(x, y)
        const [x, y] = args[0].args;

        if (isLiteral(y)) {
          const n = toBigInt(y.value);

          if (n === U256_MAX)
            return Literal(1);

          return Lt(x, Literal(n + 1n));
        }
      }

      if (!isLiteral(args[0]))
        return null;

      const x = toBigInt(args[0].value);

      return Literal(Number(x === 0n));
    }

    case 'eq': {
      if (args.length !== 2)
        return null;

      if (isStringLiteral(args[0]) && isStringLiteral(args[1])) {
        const lhs = JSON.parse(args[0].value);
        const rhs = JSON.parse(args[1].value);

        return Literal(Number(lhs === rhs));
      }

      if (isLiterals(args)) {
        const lhs = toBigInt(args[0].value);
        const rhs = toBigInt(args[1].value);

        return Literal(Number(lhs === rhs));
      }

      if (isZero(args[0]))
        return IsZero(args[1]);

      if (isZero(args[1]))
        return IsZero(args[0]);

      return null;
    }

    case 'lt':
    case 'slt': {
      if (args.length !== 2)
        return null;

      if (!isLiterals(args))
        return null;

      let lhs = toBigInt(args[0].value);
      let rhs = toBigInt(args[1].value);

      if (name.value === 'slt') {
        if (lhs & I256_SIGN)
          lhs = -(-lhs & U256_MAX);
        if (rhs & I256_SIGN)
          rhs = -(-rhs & U256_MAX);
      }

      return Literal(Number(lhs < rhs));
    }

    case 'gt':
    case 'sgt': {
      if (args.length !== 2)
        return null;

      if (!isLiterals(args))
        return null;

      let lhs = toBigInt(args[0].value);
      let rhs = toBigInt(args[1].value);

      if (name.value === 'sgt') {
        if (lhs & I256_SIGN)
          lhs = -(-lhs & U256_MAX);
        if (rhs & I256_SIGN)
          rhs = -(-rhs & U256_MAX);
      }

      return Literal(Number(lhs > rhs));
    }

    case '__bswap16':
    case '__bswap32':
    case '__bswap64': {
      if (args.length !== 1)
        return null;

      if (!isLiterals(args))
        return null;

      let x = toBigInt(args[0].value);

      switch (name.value) {
        case '__bswap16':
          x = bswap16(x);
          break;
        case '__bswap32':
          x = bswap32(x);
          break;
        case '__bswap64':
          x = bswap64(x);
          break;
      }

      return Literal(x);
    }
  }

  return null;
}

function tryFold(node) {
  if (node.type === 'FunctionCall')
    return fold(node.name, node.args) || node;
  return node;
}

// eslint-disable-next-line
function foldAll(root) {
  return rewrite(root, tryFold);
}

/*
 * Mangling
 */

function mangle(func) {
  // Have to do this because yul disallows shadowing.
  assert(func.type === 'FunctionDefinition');

  const names = new Set();

  for (const node of traverse(func)) {
    if (node.type === 'TypedIdentifierList') {
      for (const [name] of node.items)
        names.add(name.value);
    }
  }

  return rewrite(func, (node) => {
    if (node.type === 'Identifier' && names.has(node.value))
      node.value += '$';

    return node;
  });
}

/*
 * Builtins
 */

class Builtins {
  constructor(root) {
    this.macros = new Map();
    this.consts = new Map();
    this.funcs = new Map();

    if (root != null)
      this.init(root);
  }

  init(root) {
    for (const node of root.nodes) {
      switch (node.type) {
        case 'Root': {
          this.init(node);
          break;
        }

        case 'IncludeCall': {
          const filename = path.resolve(node.root, node.name);
          const input = fs.readFileSync(filename, 'utf8');

          this.init(parse(input, filename));

          break;
        }

        case 'MacroConstant':
        case 'MacroDefinition': {
          this.macros.set(node.name, node);
          break;
        }

        case 'ConstDeclaration': {
          this.consts.set(node.name.value, node.expr);
          break;
        }

        case 'FunctionDefinition': {
          node.builtin = true;
          this.funcs.set(node.name.value, mangle(node));
          break;
        }
      }
    }
  }

  clone() {
    const builtins = new Builtins();
    builtins.macros = new Map([...this.macros]);
    builtins.consts = new Map([...this.consts]);
    builtins.funcs = new Map([...this.funcs]);
    return builtins;
  }

  inject(macros) {
    for (const [name, expr] of macros) {
      const root = parse(`macro ${name} := ${expr}`);

      if (root.nodes.length !== 1)
        throw new Error(`Invalid macro "${name}"`);

      const node = root.nodes[0];

      this.macros.set(node.name, node);
    }

    return this;
  }

  scope(root) {
    const scope = new Scope(root);
    scope.macros = new Map([...this.macros]);
    scope.consts = new Map([...this.consts]);
    scope.funcs = new Map([...this.funcs]);
    return scope;
  }

  static fromCode(code, filename) {
    const root = parse(code, filename);
    return new Builtins(root);
  }

  static fromFile(filename) {
    const code = fs.readFileSync(filename, 'utf8');
    return this.fromCode(code, filename);
  }

  static fromSupport() {
    if (!this._support)
      this._support = this.fromFile(SUPPORT_FILE);
    return this._support;
  }

  static fromBuiltins() {
    if (!this._builtins)
      this._builtins = this.fromFile(BUILTINS_FILE);
    return this._builtins;
  }
}

Builtins._support = null;
Builtins._builtins = null;

/*
 * Parse/Serialize Functions
 */

function parse(input, filename) {
  return new Parser(input, filename).parse();
}

function transform(root, options) {
  return new Transformer(root, options).transform();
}

function serialize(root) {
  return new Serializer(root).serialize();
}

function rewrite(root, callback) {
  return new Rewriter(root, callback).serialize();
}

function prettify(input, filename) {
  return serialize(parse(input, filename));
}

function transpile(input, filename, options) {
  const parser = new Parser(input, filename);
  const ast = parser.parse();

  let hasher = null;
  let hash = null;

  if (options && options.metadata) {
    hasher = new Hasher(parser.root);
    hasher.init(parser.filename, input);
  }

  const trans = new Transformer(ast, options, hasher);

  let root = trans.transform();

  if (hasher)
    hash = hasher.final();

  if (options.pick) {
    let object = null;

    for (const node of traverse(root)) {
      if (node.type === 'ObjectBlock' && node.name === options.pick) {
        object = node;
        break;
      }
    }

    if (!object)
      throw new Error(`Object "${options.pick}" not found.`);

    root = Root([object]);
  }

  return {
    abi: trans.abi,
    ast,
    code: serialize(root),
    deopt: [...trans.deopt].join(''),
    hash,
    root
  };
}

/*
 * Struct
 */

class Struct {
  constructor(node) {
    this.name = node.name.value;
    this.members = [];
    this.map = new Map();
    this.value = Literal(0);
    this.width = 0;
    this.init(node);
  }

  init(node) {
    let offset = 0;
    let n = 0n;

    for (const member of node.members) {
      const type = member.kind.value;
      const name = member.name.value;
      const id = `${this.name}->${name}`;

      let width = 0;

      if (/^uint\d{1,3}$/.test(type))
        width = parseInt(type.substring(4), 10);
      else if (/^int\d{1,3}$/.test(type))
        width = parseInt(type.substring(3), 10);
      else if (type === 'address')
        width = 160;
      else if (type === 'bool')
        width = 1;
      else if (/^bytes\d{1,2}$/.test(type))
        width = parseInt(type.substring(5), 10) * 8;
      else if (type === 'function')
        width = 192;
      else
        throw new Error(`Invalid struct type: ${id}:${type}`);

      if (name === '+') {
        // Padding.
        offset += width;
        continue;
      }

      if (this.map.has(name))
        throw new Error(`Duplicate struct member name: ${id}`);

      if (!isLiteral(member.value))
        throw new Error(`Default value for ${id} must be a literal.`);

      const value = member.value.value;
      const mem = new StructMember(name, offset, width, value);

      n |= mem.value << BigInt(mem.shift);

      this.members.push(mem);
      this.map.set(name, mem);

      offset += width;
    }

    if (offset === 0 || offset > 256)
      throw new Error(`Invalid struct size: ${this.name}`);

    this.value = Literal(n);
    this.width = offset;
  }

  fold(args) {
    if (args.length === 0)
      return this.value;

    if (args.length > this.members.length)
      throw new Error(`Too many arguments passed to struct(${this.name})`);

    const stack = [];

    let n = 0n;

    for (let i = 0; i < args.length; i++) {
      const mem = this.members[i];
      const arg = args[i];

      if (isDefaultIdentifier(arg)) {
        n |= mem.value << BigInt(mem.shift);
        continue;
      }

      if (isLiteral(arg)) {
        n |= (toBigInt(arg.value) & mem.mod) << BigInt(mem.shift);
        continue;
      }

      stack.push([mem, arg]);
    }

    for (let i = args.length; i < this.members.length; i++) {
      const mem = this.members[i];

      n |= mem.value << BigInt(mem.shift);
    }

    let expr = Literal(n);

    for (const [mem, arg] of stack)
      expr = mem.accumulate(expr, arg);

    return expr;
  }
}

/*
 * Struct Member
 */

class StructMember {
  constructor(name, offset, width, value) {
    const shift = 256 - (offset + width);
    const mask = (1n << BigInt(width)) - 1n;
    const imask = (mask << BigInt(shift)) ^ U256_MAX;

    this.name = name;
    this.offset = offset;
    this.width = width;
    this.value = toBigInt(value) & mask;
    this.shift = shift;
    this.mask = Literal(mask);
    this.imask = Literal(imask);
    this.mod = mask;
  }

  read(name) {
    const {offset, width, shift, mask} = this;

    // At the end.
    if (shift === 0)
      return And(name, mask);

    // At the beginning.
    if (offset === 0)
      return Shr(shift, name);

    // Byte aligned.
    if (width === 8 && (offset & 7) === 0)
      return Byte(offset / 8, name);

    return And(Shr(shift, name), mask);
  }

  put(name, value) {
    const {shift} = this;

    if (isLiteral(value)) {
      const num = toBigInt(value.value);

      if (num === 0n)
        return Null();

      value = Literal(num << BigInt(shift));

      return Assign(name, Or(name, value));
    }

    // At the end.
    if (shift === 0)
      return Assign(name, Or(name, value));

    return Assign(name, Or(name, Shl(shift, value)));
  }

  write(name, value) {
    const {shift, imask} = this;

    if (isLiteral(value)) {
      const num = toBigInt(value.value);

      if (num === 0n)
        return Assign(name, And(name, imask));

      value = Literal(num << BigInt(shift));

      if (num === this.mod)
        return Assign(name, Or(name, value));

      return Assign(name, Or(And(name, imask), value));
    }

    // At the end.
    if (shift === 0)
      return Assign(name, Or(And(name, imask), value));

    return Assign(name, Or(And(name, imask), Shl(shift, value)));
  }

  accumulate(acc, value) {
    const {shift} = this;

    if (isZero(acc)) {
      if (shift === 0)
        return value;

      return Shl(shift, value);
    }

    if (shift === 0)
      return Or(acc, value);

    return Or(acc, Shl(shift, value));
  }
}

/*
 * Interface
 */

class Interface {
  constructor(node) {
    this.type = 'interface';
    this.name = node.name.value;
    this.ctor = null;
    this.methods = [];
    this.comment = node.comment;
    this.map = new Map();
    this.init(node);
  }

  init(node) {
    if (node.ctor)
      this.ctor = new Constructor(node.ctor, this.name);

    for (const decl of node.decls) {
      const method = new Method(decl);

      if (this.map.has(method.name))
        throw new Error(`Duplicate method name: ${this.name}.${method.name}`);

      this.methods.push(method);
      this.map.set(method.name, method);
    }
  }
}

/*
 * Constructor
 */

class Constructor {
  constructor(node, name) {
    this.type = 'constructor';
    this.name = name;
    this.params = [];
    this.mutability = node.mutability;
    this.modifier = node.modifier;
    this.comment = node.comment;
    this.signature = null;
    this.array = false;
    this.signed = false;
    this.init(node);
  }

  init(node) {
    const names = new Set();

    let offset = 0;

    for (const [type, ident] of node.params.items) {
      const name = ident ? ident.value : null;
      const param = new MethodParam(name, type, offset);

      if (name) {
        if (names.has(name))
          throw new Error(`Duplicate parameter name: ${name}`);

        names.add(name);
      }

      this.params.push(param);

      if (type.array)
        this.array = true;
      else if (type.base === 'int' && type.width < 256)
        this.signed = true;

      offset += 32;
    }
  }

  addDeps(scope) {
    if (this.modifier !== 'unchecked') {
      if (this.array)
        scope.dependsOn('__check_memory_array');

      if (this.signed)
        scope.dependsOn('__check_int');
    }
  }

  generate(name, create2 = false) {
    const pos = Identifier('__pos');
    const off = Identifier('__off');
    let size = Identifier('__size');
    const salt = Identifier('__salt');
    const addr = Identifier('__addr');
    const ptr = Identifier('__ptr');
    const args = [[pos, null], [off, null], [size, null]];
    const len = this.params.length * 32;
    const body = [];

    body.push(DataCopy(pos, off, size));

    if (this.params.length > 0)
      body.push(Let(ptr, Add(pos, size)));

    let last = null;

    for (let i = 0; i < this.params.length; i++) {
      const param = this.params[i];
      const arg = Identifier(dollar(param.name) || `__arg${i}`);

      if (param.array) {
        body.push(MemStoreAdd(ptr, param.offset, Sub(arg, ptr)));
        last = [arg, param.unit()];
      } else {
        body.push(MemStoreAdd(ptr, param.offset, param.encode(arg)));
      }

      args.push([arg, null]);
    }

    if (last)
      size = Sub(ArrayLast(last), pos);
    else if (len > 0)
      size = Add(size, Literal(len));

    if (create2)
      args.push([salt, null]);

    let amt = Literal(0);

    if (this.mutability === 'payable') {
      amt = Identifier('__amt');
      args.push([amt, null]);
    }

    if (create2) {
      body.push(Assign(addr, Call('create2', [
        amt,
        pos,
        size,
        salt
      ])));
    } else {
      body.push(Assign(addr, Call('create', [
        amt,
        pos,
        size
      ])));
    }

    body.push(If(IsZero(addr), Block([RevertReturnData()])));

    return {
      type: 'FunctionDefinition',
      name: Identifier(name),
      params: TypedIdentifierList(args),
      modifier: null,
      returns: TypedIdentifierList([[addr, null]]),
      block: Block(body),
      builtin: false
    };
  }

  check() {
    const object = Literal(this.name);
    const nodes = [];

    if (this.modifier === 'unchecked') {
      const size = Sub(CodeSize(), DataSize(object));

      if (this.params.length > 0)
        nodes.push(DataCopy(Literal(0), DataSize(object), size));

      for (const param of this.params) {
        const {name, offset} = param;

        if (name) {
          const ident = Identifier(name);
          const load = MemLoadN(offset);

          nodes.push(Let(ident, param.decode(load)));
        }
      }

      return Root(nodes);
    }

    if (this.mutability !== 'payable')
      nodes.push(RequireZero(CallValue()));

    if (this.params.length > 0) {
      const size = Literal(this.params.length * 32);
      const ident = Identifier('__argsz');
      const body = [];

      body.push(RequireGte(CodeSize(), DataSize(object)));
      body.push(Let(ident, Sub(CodeSize(), DataSize(object))));

      if (this.array)
        body.push(RequireGte(ident, size));
      else
        body.push(RequireEq(ident, size));

      body.push(DataCopy(Literal(0), DataSize(object), ident));

      nodes.push(Block(body));
    } else {
      nodes.push(RequireEq(CodeSize(), DataSize(object)));
    }

    for (let i = 0; i < this.params.length; i++) {
      const param = this.params[i];
      const {name, offset} = param;
      const ident = Identifier(name || `__carg${i}`);
      const check = param.check(ident);

      nodes.push(Let(ident, MemLoadN(offset)));

      if (!isNull(check))
        nodes.push(check);

      if (param.isPadded())
        nodes.push(Assign(ident, param.decode(ident)));
    }

    return Root(nodes);
  }

  toString() {
    let str = `constructor(${this.params.join(', ')})`;

    if (this.mutability)
      str += ' ' + this.mutability;

    return str;
  }

  toObject() {
    return {
      type: 'constructor',
      stateMutability: this.mutability || 'nonpayable',
      inputs: this.params.map(x => x.toObject())
    };
  }

  toCode() {
    let str = pretty('constructor', this.params);

    if (this.mutability) {
      str += '\n';
      str += '  ' + this.mutability;
    }

    return eol(this.comment) + str;
  }

  toSolidity() {
    const params = this.params.map(x => x.toSolidity('memory'));

    let str = pretty('constructor', params);

    if (this.mutability) {
      str += '\n';
      str += '  ' + this.mutability;
    }

    str += ';';

    return eol(this.comment) + str.replace(/^/gm, '// ');
  }
}

/*
 * Method
 */

class Method {
  constructor(node) {
    this.type = 'function';
    this.name = node.name.value;
    this.params = [];
    this.map = new Map();
    this.visibility = node.visibility;
    this.mutability = node.mutability;
    this.modifier = node.modifier;
    this.returns = [];
    this.comment = node.comment;
    this.signature = null;
    this.array = false;
    this.signed = false;
    this.retArray = false;
    this.retSigned = false;
    this.init(node);
  }

  init(node) {
    let offset = 4;

    if (this.name.includes('.'))
      throw new Error(`${this.name}() has invalid name.`);

    if (this.name === 'receive' || this.name === 'fallback') {
      if (node.params.items.length > 0 || node.returns.items.length > 0)
        throw new Error(`${this.name}() cannot have params/returns.`);

      if (this.visibility && this.visibility !== 'external')
        throw new Error(`${this.name}() must be defined as external.`);

      if (this.name === 'receive' && this.mutability !== 'payable')
        throw new Error(`${this.name}() must be payable.`);

      this.type = this.name;
    }

    for (const [type, ident] of node.params.items) {
      const name = ident ? ident.value : null;
      const param = new MethodParam(name, type, offset);

      if (name) {
        if (this.map.has(name))
          throw new Error(`Duplicate parameter name: ${name}`);

        this.map.set(name, param);
      }

      this.params.push(param);

      if (type.array)
        this.array = true;
      else if (type.base === 'int' && type.width < 256)
        this.signed = true;

      offset += 32;
    }

    offset = 0;

    for (const [type, ident] of node.returns.items) {
      const name = ident ? ident.value : null;
      const param = new MethodParam(name, type, offset);

      this.returns.push(param);

      if (type.array)
        this.retArray = true;
      else if (type.base === 'int' && type.width < 256)
        this.retSigned = true;

      offset += 32;
    }

    const types = [];

    for (const [type] of node.params.items)
      types.push(type.value);

    this.signature = methodHash(this.name, types);
  }

  addDeps(scope) {
    if (this.array)
      scope.dependsOn('__check_calldata_array');

    if (this.signed)
      scope.dependsOn('__check_int');
  }

  addCallDeps(scope) {
    if (this.retArray)
      scope.dependsOn('__check_memory_array');

    if (this.retSigned)
      scope.dependsOn('__check_int');
  }

  isView() {
    return this.mutability === 'view'
        || this.mutability === 'pure';
  }

  generate(name, attempt = false) {
    const sig = Shl(224, HexNumber(this.signature));
    const pos = Identifier('__pos');
    const addr = Identifier('__addr');
    const args = [[pos, null], [addr, null]];
    const body = [MemStore(pos, sig)];
    const rets = [];

    let srclen = Literal(4 + this.params.length * 32);
    let dstlen = Literal(this.returns.length * 32); // eslint-disable-line
    let last = null;

    if (this.returns.length === 0)
      body.push(Require(ExtCodeSize(addr)));

    for (let i = 0; i < this.params.length; i++) {
      const param = this.params[i];
      const arg = Identifier(dollar(param.name) || `__arg${i}`);

      if (param.array) {
        body.push(MemStoreAdd(pos, param.offset, Sub(arg, pos)));
        last = [arg, param.unit()];
      } else {
        body.push(MemStoreAdd(pos, param.offset, param.encode(arg)));
      }

      args.push([arg, null]);
    }

    if (last)
      srclen = Sub(ArrayLast(last), pos);

    let amt = Literal(0);

    if (this.mutability === 'payable') {
      amt = Identifier('__amt');
      args.push([amt, null]);
    }

    let call = null;

    if (this.isView()) {
      call = Call('staticcall', [
        Gas(),
        addr,
        pos,
        srclen,
        this.retArray ? Literal(0) : pos,
        this.retArray ? Literal(0) : dstlen
      ]);
    } else {
      call = Call('call', [
        Gas(),
        addr,
        amt,
        pos,
        srclen,
        this.retArray ? Literal(0) : pos,
        this.retArray ? Literal(0) : dstlen
      ]);
    }

    if (attempt) {
      const ok = Identifier('__ok');

      body.push(Assign(ok, call));
      body.push(If(IsZero(ok), Block([Leave()])));
      rets.push([ok, null]);
    } else {
      body.push(If(IsZero(call), Block([RevertReturnData()])));
    }

    if (this.retArray)
      body.push(RequireGte(ReturnDataSize(), dstlen));
    else if (this.returns.length > 0)
      body.push(RequireEq(ReturnDataSize(), dstlen));
    else
      body.push(RequireZero(ReturnDataSize()));

    if (this.retArray)
      body.push(ReturnDataCopy(pos, Literal(0), ReturnDataSize()));

    for (let i = 0; i < this.returns.length; i++) {
      const param = this.returns[i];
      const ret = Identifier(dollar(param.name) || `__ret${i}`);
      const check = param.check(ret, pos);

      body.push(Assign(ret, MemLoadAdd(pos, i * 32)));

      if (!isNull(check))
        body.push(check);

      if (param.isPadded())
        body.push(Assign(ret, param.decode(ret)));

      rets.push([ret, null]);
    }

    return {
      type: 'FunctionDefinition',
      name: Identifier(name),
      params: TypedIdentifierList(args),
      modifier: null,
      returns: TypedIdentifierList(rets),
      block: Block(body),
      builtin: false
    };
  }

  check() {
    const nodes = [];

    if (this.mutability !== 'payable')
      nodes.push(RequireZero(CallValue()));

    if (!this.isFunction())
      return Root(nodes);

    const size = Literal(4 + this.params.length * 32);

    if (this.array)
      nodes.push(RequireGte(CallDataSize(), size));
    else
      nodes.push(RequireEq(CallDataSize(), size));

    for (const param of this.params) {
      const expr = CallDataLoad(param.offset);
      const check = param.check(expr);

      if (!isNull(check))
        nodes.push(check);
    }

    return Root(nodes);
  }

  returnify(offset, args) {
    const body = [];

    let size = Literal(this.returns.length * 32);
    let pos = offset;
    let last = null;

    assert(args.length === this.returns.length);

    if (hasSideEffects(pos)) {
      pos = Identifier('__rpos');
      body.push(Let(pos, offset));
    }

    for (let i = 0; i < this.returns.length; i++) {
      const param = this.returns[i];
      const arg = args[i];

      if (param.array) {
        body.push(MemStoreAdd(pos, param.offset, Sub(arg, pos)));
        last = [arg, param.unit()];
      } else {
        body.push(MemStoreAdd(pos, param.offset, param.encode(arg)));
      }
    }

    if (last)
      size = Sub(ArrayLast(last), pos);

    body.push(Return(pos, size));

    if (pos !== offset)
      return Block(body);

    return Root(body);
  }

  isFunction() {
    return this.type === 'function';
  }

  toString() {
    let str = '';

    if (this.isFunction())
      str += 'function ';

    str += `${this.name}(${this.params.join(', ')})`;

    if (this.visibility)
      str += ' ' + this.visibility;
    else
      str += ' external';

    if (this.mutability)
      str += ' ' + this.mutability;

    if (this.returns.length > 0)
      str += ` returns (${this.returns.join(', ')})`;

    return str;
  }

  toObject() {
    if (!this.isFunction()) {
      return {
        type: this.name,
        stateMutability: this.mutability || 'nonpayable'
      };
    }

    return {
      type: 'function',
      name: this.name,
      stateMutability: this.mutability || 'nonpayable',
      inputs: this.params.map(x => x.toObject()),
      outputs: this.returns.map(x => x.toObject())
    };
  }

  toCode() {
    assert(this.isFunction());

    let str = pretty(`function ${this.name}`, this.params) + '\n';

    if (this.visibility)
      str += '  ' + this.visibility;
    else
      str += '  external';

    if (this.mutability)
      str += ' ' + this.mutability;

    if (this.returns.length > 0) {
      str += '\n';
      str += pretty('  returns ', this.returns);
    }

    return eol(this.comment) + str;
  }

  toSolidity() {
    const params = this.params.map(x => x.toSolidity('calldata'));
    const returns = this.returns.map(x => x.toSolidity('memory'));
    const prefix = this.isFunction() ? 'function ' : '';

    let str = pretty(`${prefix}${this.name}`, params) + '\n';

    str += '  external';

    if (this.mutability)
      str += ' ' + this.mutability;

    if (this.returns.length > 0) {
      str += '\n';
      str += pretty('  returns ', returns);
    }

    str += ';';

    return eol(this.comment) + str;
  }
}

/*
 * Method Parameter
 */

class MethodParam {
  constructor(name, type, offset) {
    this.name = name;
    this.type = type.value;
    this.base = type.base;
    this.width = type.width;
    this.array = type.array;
    this.offset = offset;
  }

  unit() {
    assert(this.array);

    if (this.width === 0)
      return 1;

    return 32;
  }

  ref() {
    return Literal(this.offset);
  }

  check(expr, pos = null) {
    if (this.array) {
      const unit = Literal(this.unit());

      if (expr.type === 'FunctionCall' && expr.name.value === 'calldataload')
        return Call('__check_calldata_array', [expr.args[0], unit]);

      if (expr.type === 'Identifier') {
        if (pos == null)
          pos = Literal(0);

        return Call('__check_memory_array', [expr, unit, pos]);
      }

      throw new Error('Invalid expression for check().');
    }

    assert(this.width > 0);

    if (this.width === 256)
      return Null();

    if (this.base === 'int')
      return Call('__check_int', [expr, Literal(this.width)]);

    if (this.base === 'bytes' || this.base === 'function')
      return RequireZero(Shl(this.width, expr));

    return RequireZero(Shr(this.width, expr));
  }

  isPadded() {
    if (this.array || this.width === 256)
      return false;

    return this.base === 'bytes' || this.base === 'function';
  }

  encode(expr) {
    if (this.isPadded())
      return Shl(256 - this.width, expr);

    return expr;
  }

  decode(expr) {
    if (this.isPadded())
      return Shr(256 - this.width, expr);

    return expr;
  }

  read() {
    if (this.array)
      return Add(CallDataLoad(this.offset), Literal(4));

    return this.decode(CallDataLoad(this.offset));
  }

  toString() {
    if (this.name)
      return `${this.type} ${this.name}`;

    return this.type;
  }

  toObject() {
    return {
      internalType: this.type,
      type: this.type,
      name: this.name || ''
    };
  }

  toSolidity(locality) {
    let str = this.type;

    if (this.array && locality)
      str += ' ' + locality;

    if (this.name)
      str += ` _${this.name}`;

    return str;
  }
}

/*
 * Event
 */

class Event {
  constructor(node, depth) {
    this.type = 'event';
    this.name = node.name.value;
    this.ident = `__emit_${this.name}_${depth}`;
    this.params = [];
    this.packed = node.packed;
    this.anonymous = node.anonymous;
    this.modifier = node.modifier;
    this.comment = node.comment;
    this.depth = depth;
    this.signature = null;
    this.array = false;
    this.init(node);
  }

  init(node) {
    const heap = [];

    let total = 0;

    for (const [type, ident, indexed] of node.params.items) {
      const name = ident ? ident.value : null;

      if (type.array && !indexed)
        this.array = true;

      const param = new EventParam(name, type, indexed);

      this.params.push(param);

      if (this.packed && !indexed)
        heap.push(param);

      total += (indexed | 0);
    }

    for (let i = 0; i < heap.length; i++) {
      const param = heap[i];

      if (param.array && i !== heap.length - 1)
        throw new Error(`Event ${this.name} misuses array type.`);
    }

    if (total > 3 + Number(this.anonymous))
      throw new Error(`Event ${this.name} has too many indexed parameters`);

    const types = [];

    for (const [type] of node.params.items)
      types.push(type.value);

    this.signature = eventHash(this.name, types);
  }

  _emit(offset, args) {
    const stack = [];
    const heap = [];
    const nodes = [];

    assert(args.length === this.params.length);

    if (!this.anonymous)
      stack.push(HexNumber(this.signature));

    for (let i = 0; i < this.params.length; i++) {
      const param = this.params[i];
      const arg = args[i];

      if (param.indexed)
        stack.push(param.encode(arg));
      else
        heap.push([param, arg]);
    }

    let pos = offset;
    let last = null;
    let size = 0;

    if (hasSideEffects(pos)) {
      pos = Identifier('__epos');
      nodes.push(Let(pos, offset));
    }

    for (let i = 0; i < heap.length; i++) {
      const [param, arg] = heap[i];

      if (this.packed) {
        if (param.array) {
          assert(i === heap.length - 1);
          break;
        }

        if (param.width === 8) {
          nodes.push(MemStoreAdd8(pos, size, arg));
        } else if (param.width < 256) {
          const expr = Shl(256 - param.width, arg);
          nodes.push(MemStoreAdd(pos, size, expr));
        } else {
          nodes.push(MemStoreAdd(pos, size, arg));
        }

        size += param.bytes;
      } else {
        if (param.array) {
          nodes.push(MemStoreAdd(pos, size, Sub(arg, pos)));
          last = [arg, param.unit()];
        } else {
          nodes.push(MemStoreAdd(pos, size, param.encode(arg)));
        }

        size += 32;
      }
    }

    if (this.packed && this.array) {
      const [param, arg] = heap[heap.length - 1];
      const len = Mul(arg, Literal(param.bytes));

      size = Add(Literal(size), tryFold(len));
    } else if (last) {
      size = Sub(ArrayLast(last), pos);
    } else {
      size = Literal(size);
    }

    const logName = 'log' + stack.length.toString(10);

    const logArgs = [
      pos,
      tryFold(size),
      ...stack
    ];

    nodes.push(Call(logName, logArgs));

    if (pos !== offset)
      return [Block(nodes)];

    return nodes;
  }

  emit(offset, args) {
    const nodes = this._emit(offset, args);

    if (nodes.length === 1)
      return nodes[0];

    return Root(nodes);
  }

  generate(name) {
    const off = Identifier('__off');
    const params = [[off, null]];
    const args = [];

    for (let i = 0; i < this.params.length; i++) {
      const param = this.params[i];
      const arg = Identifier(dollar(param.name) || `__arg${i}`);

      params.push([arg, null]);
      args.push(arg);
    }

    const body = this._emit(off, args);

    const func = {
      type: 'FunctionDefinition',
      name: Identifier(name),
      params: TypedIdentifierList(params),
      modifier: null,
      returns: TypedIdentifierList(),
      block: Block(body),
      builtin: false
    };

    if (this.modifier === 'noinline')
      return NoInline(func);

    return func;
  }

  toString() {
    let str = `event ${this.name}(${this.params.join(', ')})`;

    if (this.anonymous)
      str += ' anonymous';

    if (this.packed)
      str += ' packed';

    return str;
  }

  toObject() {
    const inputs = [];

    for (const {type, name, indexed} of this.params) {
      inputs.push({
        internalType: type,
        type,
        name: name || '',
        indexed
      });
    }

    return {
      type: 'event',
      name: this.name,
      anonymous: this.anonymous,
      packed: this.packed, // Extension.
      inputs
    };
  }

  toCode() {
    let str = pretty(`event ${this.name}`, this.params);

    if (this.anonymous || this.packed)
      str += '\n ';

    if (this.anonymous)
      str += ' anonymous';

    if (this.packed)
      str += ' packed';

    return eol(this.comment) + str;
  }

  toSolidity() {
    const params = this.params.map(x => x.toSolidity());

    let str = pretty(`event ${this.name}`, params);

    if (this.anonymous || this.packed)
      str += '\n ';

    if (this.anonymous)
      str += ' anonymous';

    if (this.packed) {
      str += ' packed';
      str = str.replace(/^/gm, '// ');
    }

    str += ';';

    return eol(this.comment) + str;
  }
}

/*
 * Event Parameter
 */

class EventParam {
  constructor(name, type, indexed) {
    this.name = name;
    this.type = type.value;
    this.base = type.base;
    this.width = (type.width + 7) & ~7; // For `bool`.
    this.bytes = this.width / 8;
    this.array = type.array;
    this.indexed = indexed;
  }

  unit() {
    assert(this.array);

    if (this.width === 0)
      return 1;

    return 32;
  }

  encode(expr) {
    if (!this.array && this.width < 256) {
      if (this.base === 'bytes' || this.base === 'function')
        return tryFold(Shl(256 - this.width, expr));
    }
    return expr;
  }

  toString() {
    let str = this.type;

    if (this.indexed)
      str += ' indexed';

    if (this.name)
      str += ' ' + this.name;

    return str;
  }

  toSolidity() {
    let str = this.type;

    if (this.indexed)
      str += ' indexed';

    if (this.name)
      str += ` _${this.name}`;

    return str;
  }
}

/*
 * VM Error
 */

class VMError {
  constructor(node, depth) {
    this.type = 'error';
    this.name = node.name.value;
    this.ident = `__throw_${this.name}_${depth}`;
    this.params = [];
    this.comment = node.comment;
    this.depth = depth;
    this.signature = null;
    this.array = false;
    this.init(node);
  }

  init(node) {
    let offset = 4;

    for (const [type, ident] of node.params.items) {
      const name = ident ? ident.value : null;
      const param = new MethodParam(name, type, offset);

      this.params.push(param);

      if (type.array)
        this.array = true;

      offset += 32;
    }

    const types = [];

    for (const [type] of node.params.items)
      types.push(type.value);

    this.signature = methodHash(this.name, types);
  }

  generate(name) {
    const sig = Literal(BigInt(this.signature) << 224n);
    const body = [MemStoreN(0, sig)];
    const args = [];

    let size = 4;
    let last = null;

    for (let i = 0; i < this.params.length; i++) {
      const param = this.params[i];
      const arg = Identifier(dollar(param.name) || `__arg${i}`);

      body.push(MemStoreN(size, param.encode(arg)));

      if (param.array)
        last = [arg, param.unit()];

      args.push([arg, null]);

      size += 32;
    }

    if (last)
      size = ArrayLast(last);
    else
      size = Literal(size);

    body.push(Revert(Literal(0), size));

    return NoInline({
      type: 'FunctionDefinition',
      name: Identifier(name),
      params: TypedIdentifierList(args),
      modifier: null,
      returns: TypedIdentifierList(),
      block: Block(body),
      builtin: false
    });
  }

  toString() {
    return `error ${this.name}(${this.params.join(', ')})`;
  }

  toObject() {
    return {
      type: 'error',
      name: this.name,
      inputs: this.params.map(x => x.toObject())
    };
  }

  toCode() {
    const str = pretty(`error ${this.name}`, this.params);
    return eol(this.comment) + str;
  }

  toSolidity() {
    const params = this.params.map(x => x.toSolidity());
    const str = pretty(`error ${this.name}`, params);
    return eol(this.comment) + str + ';';
  }
}

/*
 * AST Helpers
 */

function Root(nodes = []) {
  return {
    type: 'Root',
    nodes
  };
}

function Null() {
  return Root();
}

function Block(body = []) {
  return {
    type: 'Block',
    body
  };
}

function Identifier(name, replaceable = false) {
  return {
    type: 'Identifier',
    value: name,
    replaceable
  };
}

function SubLiteral(value) {
  /* eslint valid-typeof: "off" */
  if (typeof value === 'bigint') {
    const num = value & U256_MAX;

    if (num < 1024n) {
      return {
        type: 'DecimalNumber',
        value: num.toString(10)
      };
    }

    let str = num.toString(16);

    if (str.length & 1)
      str = '0' + str;

    return {
      type: 'HexNumber',
      value: '0x' + str
    };
  }

  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value));

    return {
      type: 'DecimalNumber',
      value: value.toString(10)
    };
  }

  if (typeof value === 'string') {
    return {
      type: 'StringLiteral',
      value: JSON.stringify(value)
    };
  }

  if (typeof value === 'boolean') {
    return {
      type: 'BoolLiteral',
      value: value.toString()
    };
  }

  if (Buffer.isBuffer(value)) {
    assert(value.length <= 32);

    return {
      type: 'HexNumber',
      value: '0x' + value.toString('hex')
    };
  }

  throw new Error('Invalid literal value.');
}

function Literal(value, kind = null) {
  const node = SubLiteral(value);
  return {
    type: 'Literal',
    subtype: node.type,
    kind,
    value: node.value
  };
}

function HexNumber(value, kind = null) {
  return {
    type: 'Literal',
    subtype: 'HexNumber',
    kind,
    value
  };
}

function HexLiteral(value, kind = null) {
  return {
    type: 'Literal',
    subtype: 'HexLiteral',
    kind,
    value: `hex"${value}"`
  };
}

function DataValue(name, value) {
  return {
    type: 'DataValue',
    name,
    value
  };
}

function FunctionCall(name, args = []) {
  return {
    type: 'FunctionCall',
    name,
    args,
    filename: null,
    line: -1
  };
}

function VariableDeclaration(vars, expr = null) {
  return {
    type: 'VariableDeclaration',
    vars,
    expr
  };
}

function TypedIdentifierList(items = []) {
  return {
    type: 'TypedIdentifierList',
    items
  };
}

function IdentifierList(items = []) {
  return {
    type: 'IdentifierList',
    items
  };
}

function Assignment(lhs, rhs) {
  return {
    type: 'Assignment',
    lhs,
    rhs
  };
}

function If(expr, block) {
  return {
    type: 'If',
    expr,
    block,
    branches: [],
    otherwise: null
  };
}

function MethodParams(items = []) {
  return {
    type: 'MethodParams',
    items
  };
}

function ConstructorDefinition(body = []) {
  return {
    type: 'ConstructorDefinition',
    params: MethodParams(),
    mutability: null,
    modifier: null,
    block: Block(body),
    comment: null
  };
}

/*
 * High-Level AST Helpers
 */

function Let(ident, expr) {
  return VariableDeclaration(TypedIdentifierList([[ident, null]]), expr);
}

function Assign(ident, expr) {
  return Assignment(IdentifierList([ident]), expr);
}

function Call(name, args) {
  return FunctionCall(Identifier(name), args);
}

function MemLoad(ptr) {
  return Call('mload', [ptr]);
}

function MemLoadN(ptr) {
  return MemLoad(Literal(ptr));
}

function MemLoadAdd(pos, off) {
  if (off) {
    if (isLiteral(pos))
      pos = Literal(toBigInt(pos.value) + BigInt(off));
    else
      pos = Add(pos, Literal(off));
  }

  return MemLoad(pos);
}

function MemStore(ptr, expr) {
  return Call('mstore', [ptr, expr]);
}

function MemStoreN(ptr, expr) {
  return MemStore(Literal(ptr), expr);
}

function MemStoreAdd(pos, off, expr) {
  if (off) {
    if (isLiteral(pos))
      pos = Literal(toBigInt(pos.value) + BigInt(off));
    else
      pos = Add(pos, Literal(off));
  }

  return MemStore(pos, tryFold(expr));
}

function MemStore8(ptr, expr) {
  return Call('mstore8', [ptr, expr]);
}

// eslint-disable-next-line
function MemStore8N(ptr, expr) {
  return MemStore8(Literal(ptr), expr);
}

function MemStoreAdd8(pos, off, expr) {
  if (off) {
    if (isLiteral(pos))
      pos = Literal(toBigInt(pos.value) + BigInt(off));
    else
      pos = Add(pos, Literal(off));
  }

  return MemStore8(pos, tryFold(expr));
}

function Add(x, y) {
  return Call('add', [x, y]);
}

function Sub(x, y) {
  return Call('sub', [x, y]);
}

function Mul(x, y) {
  return Call('mul', [x, y]);
}

function And(x, y) {
  return Call('and', [x, y]);
}

function Or(x, y) {
  return Call('or', [x, y]);
}

function Xor(x, y) {
  return Call('xor', [x, y]);
}

function Shl(shift, num) {
  return Call('shl', [Literal(shift), num]);
}

function Shr(shift, num) {
  return Call('shr', [Literal(shift), num]);
}

function Byte(pos, num) {
  return Call('byte', [Literal(pos), num]);
}

function Caller() {
  return Call('caller');
}

function Origin() {
  return Call('origin');
}

function CallValue() {
  return Call('callvalue');
}

function CallDataLoad(pos) {
  return Call('calldataload', [Literal(pos)]);
}

function CallDataSize() {
  return Call('calldatasize');
}

function IsZero(expr) {
  return Call('iszero', [expr]);
}

function Eq(x, y) {
  return Call('eq', [x, y]);
}

function Lt(x, y) {
  return Call('lt', [x, y]);
}

function Gt(x, y) {
  return Call('gt', [x, y]);
}

function Slt(x, y) {
  return Call('slt', [x, y]);
}

function Sgt(x, y) {
  return Call('sgt', [x, y]);
}

function Stop() {
  return Call('stop');
}

function Revert(ptr = Literal(0), len = Literal(0)) {
  return Call('revert', [ptr, len]);
}

function Return(ptr, len) {
  return Call('return', [ptr, len]);
}

function ReturnDataSize() {
  return Call('returndatasize');
}

function ReturnDataCopy(dst, src, len) {
  return Call('returndatacopy', [dst, src, len]);
}

function RevertReturnData() {
  return Root([
    ReturnDataCopy(Literal(0), Literal(0), ReturnDataSize()),
    Revert(Literal(0), ReturnDataSize())
  ]);
}

function Leave() {
  return {
    type: 'Leave'
  };
}

function Timestamp() {
  return Call('timestamp');
}

function SetImmutable(ptr, name, value) {
  return Call('setimmutable', [ptr, name, value]);
}

function LoadImmutable(name) {
  return Call('loadimmutable', [name]);
}

function DataOffset(name) {
  return Call('dataoffset', [name]);
}

function DataSize(name) {
  return Call('datasize', [name]);
}

function DataCopy(dst, src, len) {
  return Call('datacopy', [dst, src, len]);
}

function CodeSize() {
  return Call('codesize');
}

// eslint-disable-next-line
function CodeCopy(dst, src, len) {
  return Call('codecopy', [dst, src, len]);
}

function ExtCodeSize(addr) {
  return Call('extcodesize', [addr]);
}

function PopAsm(expr) {
  return Call('verbatim_1i_0o', [
    HexLiteral('50'), // POP
    expr
  ]);
}

function CodeSizeAsm() {
  return Call('verbatim_0i_1o', [
    HexLiteral('38') // CODESIZE
  ]);
}

function Require(expr) {
  return If(IsZero(expr), Block([Revert()]));
}

function RequireZero(expr) {
  return If(expr, Block([Revert()]));
}

function RequireEq(x, y) {
  return RequireZero(Xor(x, y));
}

// eslint-disable-next-line
function RequireLte(x, y) {
  return RequireZero(Gt(x, y));
}

function RequireGte(x, y) {
  return RequireZero(Lt(x, y));
}

// eslint-disable-next-line
function RequireWidth(expr, width) {
  return RequireZero(Shr(width, expr));
}

function Gas() {
  return Call('gas');
}

function EthSend(addr, amt, gas) {
  const _0 = Literal(0);
  return Call('call', [gas, addr, amt, _0, _0, _0, _0]);
}

function ArrayLast([xp, unit]) {
  let size = MemLoad(xp);

  if (unit === 1)
    size = Shr(5, Add(size, Literal(31)));

  const xn = Add(Literal(32), Shl(5, size));

  return Add(xp, xn);
}

// [1] https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/FullInliner.cpp#L74
// [2] https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/ExpressionInliner.cpp#L41
// [3] https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/InlinableExpressionFunctionFinder.cpp#L45
// [4] https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/ControlFlowSimplifier.cpp#L88
function NoInline(func, memguard = false) {
  let needs;

  // https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/FullInliner.cpp#L227
  if (func.params.items.length === 0)
    needs = memguard ? 8 : 6;
  else
    needs = memguard ? 16 : 12;

  // CODESIZE POP (2 bytes, 4 gas, 4 size)
  const pad = PopAsm(CodeSizeAsm());
  const body = [];

  let size = codeSize(func.block);

  if (isInlinableExpression(func)) {
    body.push(pad);
    size += 4;
  }

  while (size < needs) {
    body.push(pad);
    size += 4;
  }

  if (body.length === 0)
    return func;

  for (const node of func.block.body)
    body.push(node);

  return {
    type: 'FunctionDefinition',
    name: func.name,
    params: func.params,
    modifier: null,
    returns: func.returns,
    block: Block(body),
    builtin: func.builtin
  };
}

function FunctionConstant(name, expr, memguard = false) {
  const ret = Identifier('__ret');
  const needs = memguard ? 8 : 6;
  const pad = PopAsm(CodeSizeAsm());
  const body = [pad];

  let size = 4 + codeSize(expr);

  while (size < needs) {
    body.push(pad);
    size += 4;
  }

  body.push(Assign(ret, expr));

  return {
    type: 'FunctionDefinition',
    name: Identifier(name),
    params: TypedIdentifierList(),
    modifier: null,
    returns: TypedIdentifierList([[ret, null]]),
    block: Block(body),
    builtin: false
  };
}

function isInlinableExpression(func) {
  if (func.returns.items.length !== 1)
    return false;

  if (func.block.body.length !== 1)
    return false;

  const ret = func.returns.items[0][0];
  const stmt = func.block.body[0];

  if (stmt.type !== 'Assignment')
    return false;

  assert(stmt.lhs.type === 'IdentifierList');

  if (stmt.lhs.items.length !== 1)
    return false;

  assert(stmt.lhs.items[0].type === 'Identifier');

  return stmt.lhs.items[0].value === ret.value;
}

function codeSize(root) {
  const ignore = new Set();

  let size = 0;

  // https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/Metrics.h#L52
  // https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/Metrics.cpp#L38
  for (const node of traverse(root)) {
    switch (node.type) {
      case 'Assignment':
        size += 0;
        break;
      case 'VariableDeclaration':
        size += 0;
        break;
      case 'FunctionDefinition':
        size += 1;
        break;
      case 'If':
        size += 2;
        break;
      case 'Switch':
        size += 1 + 2 * node.cases.length;
        if (node.def)
          size += 2;
        break;
      case 'ForLoop':
        size += 3;
        break;
      case 'BreakContinue':
        size += 2;
        break;
      case 'Leave':
        size += 2;
        break;
      case 'Block':
        size += 0;
        break;
      case 'FunctionCall':
        size += 1;
        break;
      case 'Identifier':
        size += 0;
        break;
      case 'Literal':
        if (isLiteral(node)) {
          const value = toBigInt(node.value);
          if (value !== 0n && !ignore.has(value)) {
            ignore.add(value);
            size += 1;
          }
        } else {
          size += 1;
        }
        break;
    }
  }

  return size;
}

function isNull(node) {
  return node.type === 'Root' && node.nodes.length === 0;
}

function filter(nodes) {
  const out = [];

  for (const node of nodes) {
    if (node.type === 'Root') {
      for (const child of node.nodes)
        out.push(child);
    } else {
      out.push(node);
    }
  }

  return out;
}

function isIdentifier(node) {
  return node.type === 'MemberIdentifier'
      || node.type === 'CallDataIdentifier'
      || node.type === 'Identifier';
}

function isExpression(node) {
  return node.type === 'StructInitializer'
      || node.type === 'MethodSignature'
      || node.type === 'EventSignature'
      || node.type === 'ErrorSignature'
      || node.type === 'InterfaceCall'
      || node.type === 'FunctionCall'
      || node.type === 'Literal'
      || isIdentifier(node);
}

function hasSideEffects(node) {
  return node.type !== 'Literal' && node.type !== 'Identifier';
}

function isLiteral(node) {
  if (node.type !== 'Literal')
    return false;

  return node.subtype === 'HexNumber'
      || node.subtype === 'DecimalNumber'
      || node.subtype === 'BoolLiteral';
}

function isStringLiteral(node) {
  return node.type === 'Literal' && node.subtype === 'StringLiteral';
}

function isHexLiteral(node) {
  return node.type === 'Literal' && node.subtype === 'HexLiteral';
}

function isLiterals(args) {
  for (const arg of args) {
    if (!isLiteral(arg))
      return false;
  }

  return true;
}

function isZero(node) {
  if (node.type !== 'Literal')
    return false;

  if (node.subtype === 'HexNumber')
    return /^0x0+$/.test(node.value);

  if (node.subtype === 'DecimalNumber')
    return /^0+$/.test(node.value);

  if (node.subtype === 'BoolLiteral')
    return node.value === 'false';

  return false;
}

function isOne(node) {
  if (node.type !== 'Literal')
    return false;

  if (node.subtype === 'HexNumber')
    return /^0x0*1$/.test(node.value);

  if (node.subtype === 'DecimalNumber')
    return /^0*1$/.test(node.value);

  if (node.subtype === 'BoolLiteral')
    return node.value === 'true';

  return false;
}

function isDefaultIdentifier(node) {
  return node.type === 'Identifier' && node.value === '@';
}

function isCall(node, name, length) {
  if (node.type !== 'FunctionCall')
    return false;

  if (node.name.value !== name)
    return false;

  return node.args.length === length;
}

function isZeroCall(node) {
  return isCall(node, 'iszero', 1);
}

function isEqCall(node) {
  return isCall(node, 'eq', 2);
}

function isLtCall(node) {
  return isCall(node, 'lt', 2);
}

function isGtCall(node) {
  return isCall(node, 'gt', 2);
}

function isNeqCall(node) {
  return isZeroCall(node) && isEqCall(node.args[0]);
}

function isZeroCast(node) {
  return isZeroCall(node) && isZeroCall(node.args[0]);
}

function isGtCast(node) {
  return isGtCall(node) && isZero(node.args[1]);
}

function isEqLiteral(node) {
  return isEqCall(node) && isLiteral(node.args[1]);
}

function ocj(node) {
  // OCJ = Optimize Conditional Jump
  if (isZeroCast(node)) // iszero(iszero(x)) -> x
    return node.args[0].args[0];

  if (isGtCast(node)) // gt(x, 0) -> x
    return node.args[0];

  if (isNeqCall(node)) { // iszero(eq(x, y)) -> xor(x, y)
    const eq = node.args[0];
    const [x, y] = eq.args;
    return Xor(x, y);
  }

  return node;
}

function returnsBool(node) {
  if (node.type === 'Literal')
    return isZero(node) || isOne(node);

  if (node.type !== 'FunctionCall')
    return false;

  switch (node.name.value) {
    case 'lt':
    case 'gt':
    case 'slt':
    case 'sgt':
    case 'eq':
    case 'iszero':
    case 'call':
    case 'callcode':
    case 'delegatecall':
    case 'staticcall': {
      return true;
    }
    case 'and': {
      if (node.args.length !== 2)
        return false;

      const [x, y] = node.args;

      return returnsBool(x) || returnsBool(y);
    }
    case 'or':
    case 'xor': {
      if (node.args.length !== 2)
        return false;

      const [x, y] = node.args;

      return returnsBool(x) && returnsBool(y);
    }
  }

  return false;
}

/*
 * Helpers
 */

// Strip comments while keeping line numbers the same.
function stripComments(input) {
  // States
  const NONE = 0;
  const SLASH = 1;
  const LINE = 2;
  const MULTI = 3;
  const STAR = 4;
  const QUOTE = 5;
  const BACK = 6;
  const comms = [];

  let output = '';
  let state = NONE;
  let line = 0;
  let comm = null;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (ch === '\r')
      continue;

    switch (state) {
      case NONE: {
        switch (ch) {
          case '/': {
            state = SLASH;
            break;
          }
          case '"': {
            state = QUOTE;
            // fallthrough
          }
          default: {
            output += ch;
            break;
          }
        }
        break;
      }

      case SLASH: {
        switch (ch) {
          case '/': {
            state = LINE;
            comm = {
              type: 'line',
              text: '//',
              start: line,
              end: line + 1
            };
            break;
          }
          case '*': {
            state = MULTI;
            comm = {
              type: 'multi',
              text: '/*',
              start: line,
              end: 0
            };
            break;
          }
          default: {
            state = NONE;
            output += '/';
            output += ch;
            break;
          }
        }
        break;
      }

      case LINE: {
        switch (ch) {
          case '\n': {
            state = NONE;
            output += '\n';
            if (comm.text[2] === '/')
              comms.push(comm);
            break;
          }
          default: {
            comm.text += ch;
            break;
          }
        }
        break;
      }

      case MULTI: {
        comm.text += ch;
        switch (ch) {
          case '*': {
            state = STAR;
            break;
          }
          case '\n': {
            output += '\n';
            break;
          }
        }
        break;
      }

      case STAR: {
        comm.text += ch;
        switch (ch) {
          case '/': {
            state = NONE;
            comm.end = line + 1;
            if (comm.text[2] === '*')
              comms.push(comm);
            break;
          }
          case '\n': {
            output += '\n';
            // fallthrough
          }
          default: {
            state = MULTI;
            break;
          }
        }
        break;
      }

      case QUOTE: {
        switch (ch) {
          case '"': {
            state = NONE;
            output += ch;
            break;
          }
          case '\n': {
            throw new Error(`No closing quote for string at line ${line}.`);
          }
          case '\\': {
            state = BACK;
            // fallthrough
          }
          default: {
            output += ch;
            break;
          }
        }
        break;
      }

      case BACK: {
        state = QUOTE;
        output += ch;
        break;
      }
    }

    if (ch === '\n')
      line += 1;
  }

  const map = new Map();

  for (let i = 0; i < comms.length; i++) {
    const node = comms[i];

    if (node.type === 'line') {
      for (let j = i + 1; j < comms.length; j++) {
        const child = comms[j];

        if (child.type !== 'line' || child.start !== node.end)
          break;

        node.text += '\n' + child.text;
        node.end = child.end;

        i = j;
      }
    }

    if (node.type === 'multi')
      node.text = node.text.replace(/^[ \t]*\*/gm, ' *');

    map.set(node.end, node.text);
  }

  return [output, map];
}

function indent(str, len) {
  return str.replace(/^/gm, ' '.repeat(len));
}

function canonicalize(type) {
  switch (type) {
    case 'uint':
      return 'uint256';
    case 'int':
      return 'int256';
    case 'uint[]':
      return 'uint256[]';
    case 'int[]':
      return 'int256[]';
    default:
      return type;
  }
}

function abiHash(name, types) {
  const preimage = `${name}(${types.map(canonicalize).join(',')})`;
  const raw = Buffer.from(preimage, 'binary');
  return keccak256.digest(raw);
}

function methodHash(name, types) {
  const hash = abiHash(name, types);
  return '0x' + hash.toString('hex', 0, 4);
}

function eventHash(name, types) {
  const hash = abiHash(name, types);
  return '0x' + hash.toString('hex');
}

function keccak160() {}

keccak160.digest = function digest(data) {
  return keccak256.digest(data).slice(12);
};

function toBigInt(value) {
  if (value === 'false')
    return 0n;

  if (value === 'true')
    return 1n;

  return BigInt(value);
}

function bswap16(x) {
  x = ((x & 0x00ffn) << 8n)
    | ((x & 0xff00n) >> 8n);
  return x;
}

function bswap32(x) {
  x = ((x & 0x0000ffffn) << 16n)
    | ((x & 0xffff0000n) >> 16n);
  x = ((x & 0x00ff00ffn) << 8n)
    | ((x & 0xff00ff00n) >> 8n);
  return x;
}

function bswap64(x) {
  x = ((x & 0x00000000ffffffffn) << 32n)
    | ((x & 0xffffffff00000000n) >> 32n);
  x = ((x & 0x0000ffff0000ffffn) << 16n)
    | ((x & 0xffff0000ffff0000n) >> 16n);
  x = ((x & 0x00ff00ff00ff00ffn) << 8n)
    | ((x & 0xff00ff00ff00ff00n) >> 8n);
  return x;
}

function dollar(name) {
  return name ? name + '$' : null;
}

function eol(str) {
  return str ? str + '\n' : '';
}

function pretty(prefix, params) {
  const items = [];

  let size = prefix.length + 2;

  for (const param of params) {
    const str = String(param);

    size += str.length + 2;

    items.push(str);
  }

  // 80 - 3 == 77 (2 spaces, 1 semicolon).
  if (size <= 77 || items.length === 0)
    return `${prefix}(${items.join(', ')})`;

  const pad = ' '.repeat(prefix.length + 1);

  return `${prefix}(${items.join(',\n' + pad)})`;
}

/*
 * Semver (simplified)
 */

const SEMVER_PREFIX = /^(?:\^|~|[<>]=?|=)/;
const VERSION_REGEX = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/;

function parsePattern(str) {
  if (typeof str !== 'string')
    throw new TypeError('Version pattern must be a string.');

  const match = SEMVER_PREFIX.exec(str);
  const prefix = match ? match[0] : '';

  let version;

  try {
    version = parseVersion(str.substring(prefix.length));
  } catch (e) {
    throw new SyntaxError(`Invalid version pattern: ${str}`);
  }

  return [prefix || '=', version];
}

function parseVersion(str) {
  if (typeof str !== 'string')
    throw new TypeError('Version must be a string.');

  const match = VERSION_REGEX.exec(str);

  if (!match)
    throw new SyntaxError(`Invalid version format: ${str}`);

  let version = 0;

  for (let i = 1; i < match.length; i++) {
    const num = Number(match[i]);

    if (num >= 0x100)
      throw new SyntaxError(`Invalid version format: ${str}`);

    version = (version << 8) | num;
  }

  return version;
}

function semver() {}

semver.match = function match(version, pattern) {
  const [pre, exp] = parsePattern(pattern);
  const ver = parseVersion(version);

  switch (pre) {
    case '^':
      // '^1.2.3' -> ['>=1.2.3-0', '<2.0.0-0']
      if ((ver >> 16) !== (exp >> 16))
        return false;
      return ver >= exp;
    case '~':
      // '~1.2.3' -> ['>=1.2.3-0', '<1.3.0-0']
      if ((ver >> 8) !== (exp >> 8))
        return false;
      return ver >= exp;
    case '<':
      return ver < exp;
    case '<=':
      return ver <= exp;
    case '>':
      return ver > exp;
    case '>=':
      return ver >= exp;
    case '=':
      return ver === exp;
    default:
      throw new Error('unreachable');
  }
};

semver.test = function test(str) {
  try {
    parsePattern(str);
    return true;
  } catch (e) {
    return false;
  }
};

/*
 * Expose
 */

exports.Parser = Parser;
exports.Transformer = Transformer;
exports.Serializer = Serializer;
exports.Rewriter = Rewriter;
exports.Builtins = Builtins;

exports.parse = parse;
exports.transform = transform;
exports.serialize = serialize;
exports.rewrite = rewrite;
exports.traverse = traverse;
exports.prettify = prettify;
exports.transpile = transpile;
exports.hash = abiHash;
exports.version = parseVersion;
