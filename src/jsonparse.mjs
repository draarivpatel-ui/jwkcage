/* Strict JSON object parser: rejects duplicate keys, pollution keys, deep input. */
import { JWKCAGE_ERROR_CODES as CODE } from './constants.mjs';
import { fail } from './errors.mjs';

const POLLUTION = new Set(['__proto__', 'constructor', 'prototype']);

class Parser {
  constructor(text, maxDepth) {
    this.text = text;
    this.pos = 0;
    this.maxDepth = maxDepth;
  }

  error(detail) {
    fail(CODE.MALFORMED_JSON, detail + ' at byte ' + this.pos);
  }

  peek() {
    return this.text[this.pos];
  }

  skipWhitespace() {
    while (this.pos < this.text.length) {
      const ch = this.text[this.pos];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') this.pos += 1;
      else break;
    }
  }

  parseValue(depth) {
    if (depth > this.maxDepth) fail(CODE.MALFORMED_JSON, 'JSON nesting exceeds depth budget');
    this.skipWhitespace();
    const ch = this.peek();
    if (ch === '{') return this.parseObject(depth);
    if (ch === '[') return this.parseArray(depth);
    if (ch === '"') return this.parseString();
    if (ch === 't') return this.parseLiteral('true', true);
    if (ch === 'f') return this.parseLiteral('false', false);
    if (ch === 'n') return this.parseLiteral('null', null);
    if (ch === '-' || (ch >= '0' && ch <= '9')) return this.parseNumber();
    this.error('unexpected token');
  }

  parseLiteral(word, value) {
    if (this.text.slice(this.pos, this.pos + word.length) !== word) this.error('invalid literal');
    this.pos += word.length;
    return value;
  }

  parseNumber() {
    const start = this.pos;
    if (this.peek() === '-') this.pos += 1;
    if (this.peek() === '0') this.pos += 1;
    else if (this.peek() >= '1' && this.peek() <= '9') {
      while (this.peek() >= '0' && this.peek() <= '9') this.pos += 1;
    } else this.error('invalid number');
    if (this.peek() === '.') {
      this.pos += 1;
      if (!(this.peek() >= '0' && this.peek() <= '9')) this.error('invalid fraction');
      while (this.peek() >= '0' && this.peek() <= '9') this.pos += 1;
    }
    if (this.peek() === 'e' || this.peek() === 'E') {
      this.pos += 1;
      if (this.peek() === '+' || this.peek() === '-') this.pos += 1;
      if (!(this.peek() >= '0' && this.peek() <= '9')) this.error('invalid exponent');
      while (this.peek() >= '0' && this.peek() <= '9') this.pos += 1;
    }
    return Number(this.text.slice(start, this.pos));
  }

  parseString() {
    this.pos += 1;
    let out = '';
    while (this.pos < this.text.length) {
      const ch = this.text[this.pos];
      if (ch === '"') {
        this.pos += 1;
        return out;
      }
      if (ch === '\\') {
        this.pos += 1;
        const esc = this.text[this.pos];
        if (esc === '"' || esc === '\\' || esc === '/') out += esc;
        else if (esc === 'b') out += '\b';
        else if (esc === 'f') out += '\f';
        else if (esc === 'n') out += '\n';
        else if (esc === 'r') out += '\r';
        else if (esc === 't') out += '\t';
        else if (esc === 'u') {
          const hex = this.text.slice(this.pos + 1, this.pos + 5);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) this.error('invalid unicode escape');
          const first = parseInt(hex, 16);
          this.pos += 4;
          if (first >= 0xd800 && first <= 0xdbff) {
            if (this.text[this.pos + 1] === '\\' && this.text[this.pos + 2] === 'u') {
              const hex2 = this.text.slice(this.pos + 3, this.pos + 7);
              if (/^[0-9A-Fa-f]{4}$/.test(hex2)) {
                const second = parseInt(hex2, 16);
                if (second >= 0xdc00 && second <= 0xdfff) {
                  out += String.fromCodePoint(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00));
                  this.pos += 6;
                  this.pos += 1;
                  continue;
                }
              }
            }
            this.error('unpaired surrogate');
          } else if (first >= 0xdc00 && first <= 0xdfff) {
            this.error('unpaired surrogate');
          } else {
            out += String.fromCharCode(first);
          }
        } else this.error('invalid escape');
        this.pos += 1;
        continue;
      }
      if (ch < ' ') this.error('control character in string');
      out += ch;
      this.pos += 1;
    }
    this.error('unterminated string');
  }

  parseObject(depth) {
    this.pos += 1;
    const out = {};
    const seen = new Set();
    this.skipWhitespace();
    if (this.peek() === '}') {
      this.pos += 1;
      return out;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.peek() !== '"') this.error('object key must be a string');
      const key = this.parseString();
      if (seen.has(key)) fail(CODE.DUPLICATE_JSON_KEY, 'duplicate JSON object key', { key });
      seen.add(key);
      if (POLLUTION.has(key)) fail(CODE.PROTOTYPE_POLLUTION, 'prototype pollution key in JSON input', { key });
      this.skipWhitespace();
      if (this.peek() !== ':') this.error('missing colon');
      this.pos += 1;
      const value = this.parseValue(depth + 1);
      out[key] = value;
      this.skipWhitespace();
      const ch = this.peek();
      if (ch === ',') {
        this.pos += 1;
        continue;
      }
      if (ch === '}') {
        this.pos += 1;
        return out;
      }
      this.error('missing comma or closing brace');
    }
  }

  parseArray(depth) {
    this.pos += 1;
    const out = [];
    this.skipWhitespace();
    if (this.peek() === ']') {
      this.pos += 1;
      return out;
    }
    for (;;) {
      out.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      const ch = this.peek();
      if (ch === ',') {
        this.pos += 1;
        continue;
      }
      if (ch === ']') {
        this.pos += 1;
        return out;
      }
      this.error('missing comma or closing bracket');
    }
  }

  finish() {
    this.skipWhitespace();
    if (this.pos !== this.text.length) this.error('trailing data');
  }
}

export function parseJsonStrict(text, maxDepth) {
  const parser = new Parser(text, maxDepth);
  const value = parser.parseValue(0);
  parser.finish();
  return value;
}

export function scanObjectForPollution(value, depth, maxDepth) {
  if (depth > maxDepth) fail(CODE.MALFORMED_JSON, 'object nesting exceeds depth budget');
  if (value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) scanObjectForPollution(item, depth + 1, maxDepth);
    return;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    fail(CODE.PROTOTYPE_POLLUTION, 'input object has a nonstandard prototype');
  }
  for (const key of Object.keys(value)) {
    if (POLLUTION.has(key)) fail(CODE.PROTOTYPE_POLLUTION, 'prototype pollution key in input object', { key });
    scanObjectForPollution(value[key], depth + 1, maxDepth);
  }
}
