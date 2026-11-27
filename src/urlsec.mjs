/* Offline SSRF perimeter analysis for jku and x5u URLs. Never performs network access. */
import { internalHostname, ipv4Scope, ipv6Analysis, parseIpv4Like, parseIpv6Literal } from './network.mjs';

const CONTROL_RE = /[\u0000-\u001f\u007f]/u;

export function auditEndpointUrl(value, field) {
  const findings = [];
  const add = (code, severity, message) => findings.push(Object.freeze({ code, severity, field, message }));
  if (typeof value !== 'string' || value.length === 0) {
    add('ENDPOINT_URL_TYPE', 'critical', field + ' must be a non-empty string');
    return findings;
  }
  if (value.length > 2048) add('ENDPOINT_URL_TOO_LONG', 'high', field + ' exceeds the URL length budget');
  if (CONTROL_RE.test(value)) add('ENDPOINT_URL_CONTROL', 'critical', field + ' contains control characters');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    add('ENDPOINT_URL_MALFORMED', 'critical', field + ' is not a syntactically valid URL');
    return findings;
  }
  if (parsed.protocol !== 'https:') add('ENDPOINT_URL_NOT_HTTPS', 'critical', field + ' must use the https scheme');
  if (parsed.username !== '' || parsed.password !== '') add('ENDPOINT_URL_CREDENTIALS', 'critical', field + ' embeds userinfo credentials');
  if (parsed.hash !== '') add('ENDPOINT_URL_FRAGMENT', 'medium', field + ' carries a fragment that splits key identity');
  if (parsed.hostname === '') {
    add('ENDPOINT_URL_EMPTY_HOST', 'critical', field + ' has an empty host');
    return findings;
  }
  let rawAuthority = '';
  try {
    const schemeEnd = value.indexOf('//');
    const authorityStart = schemeEnd === -1 ? 0 : schemeEnd + 2;
    let authorityEnd = value.length;
    for (const delimiter of ['/', '?', '#']) {
      const at = value.indexOf(delimiter, authorityStart);
      if (at !== -1 && at < authorityEnd) authorityEnd = at;
    }
    rawAuthority = value.slice(authorityStart, authorityEnd);
  } catch {
    rawAuthority = '';
  }
  const atSign = rawAuthority.lastIndexOf('@');
  const hostPort = atSign === -1 ? rawAuthority : rawAuthority.slice(atSign + 1);
  let rawHost;
  let rawBracketed = false;
  if (hostPort.startsWith('[')) {
    const close = hostPort.indexOf(']');
    rawHost = close === -1 ? hostPort.slice(1) : hostPort.slice(1, close);
    rawBracketed = true;
  } else {
    const colon = hostPort.indexOf(':');
    rawHost = (colon === -1 ? hostPort : hostPort.slice(0, colon)).toLowerCase();
  }
  if (rawHost.includes('%')) add('ENDPOINT_URL_HOST_ENCODED', 'critical', field + ' host contains percent encoding');
  const host = parsed.hostname;
  const bracketed = rawBracketed || (host.startsWith('[') && host.endsWith(']'));
  const bareHost = bracketed ? rawHost : rawHost.replace(/\.$/u, '');
  if (bracketed) {
    const v6 = parseIpv6Literal(bareHost);
    if (!v6 || !v6.valid) {
      add('ENDPOINT_URL_IPV6_INVALID', 'critical', field + ' uses a malformed IPv6 literal');
    } else {
      if (v6.embeddedIpv4Syntax) add('ENDPOINT_URL_IPV6_TRANSITION', 'high', field + ' uses an IPv4-embedded IPv6 transition form');
      const analysis = ipv6Analysis(v6.groups);
      const scope = analysis.scope === 'tunnel' && analysis.embeddedScope ? analysis.embeddedScope : analysis.scope;
      if (scope !== 'public') add('ENDPOINT_URL_IP_NOT_PUBLIC', 'critical', field + ' targets a non-public IPv6 scope: ' + scope);
      if (analysis.tunnel) add('ENDPOINT_URL_IPV6_TUNNEL', 'high', field + ' uses a ' + analysis.tunnel + ' transition tunnel');
    }
  } else {
    const ipv4 = parseIpv4Like(bareHost);
    if (ipv4 && ipv4.numericLike) {
      if (!ipv4.valid) {
        add('ENDPOINT_URL_IPV4_INVALID', 'critical', field + ' uses an invalid numeric IPv4 representation');
      } else {
        if (ipv4.obfuscated) add('ENDPOINT_URL_IPV4_OBFUSCATED', 'critical', field + ' uses an obfuscated decimal, octal, hex, or shorthand IPv4 form');
        const scope = ipv4Scope(ipv4.bytes);
        if (scope !== 'public') add('ENDPOINT_URL_IP_NOT_PUBLIC', 'critical', field + ' targets a non-public IPv4 scope: ' + scope);
      }
    } else {
      if (internalHostname(bareHost)) add('ENDPOINT_URL_INTERNAL_HOST', 'critical', field + ' targets localhost or an internal single-label, .local, or .internal name');
      if (!/^[a-z0-9.-]+$/u.test(bareHost)) add('ENDPOINT_URL_HOST_CHARSET', 'high', field + ' host contains characters outside the ASCII DNS set');
      if (bareHost.length > 253) add('ENDPOINT_URL_HOST_TOO_LONG', 'high', field + ' host exceeds the DNS length budget');
      const labels = bareHost.split('.');
      if (labels.some((label) => label.length === 0)) add('ENDPOINT_URL_HOST_EMPTY_LABEL', 'high', field + ' host contains an empty DNS label');
      if (labels.some((label) => label.length > 63)) add('ENDPOINT_URL_HOST_LONG_LABEL', 'high', field + ' host contains an overlong DNS label');
      if (labels.some((label) => label.startsWith('-') || label.endsWith('-'))) add('ENDPOINT_URL_HOST_HYPHEN_EDGE', 'medium', field + ' host label begins or ends with a hyphen');
    }
  }
  if (parsed.port !== '') {
    const portNumber = Number(parsed.port);
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) add('ENDPOINT_URL_BAD_PORT', 'high', field + ' uses an invalid port');
    if (parsed.protocol === 'https:' && parsed.port === '443') add('ENDPOINT_URL_DEFAULT_PORT', 'low', field + ' repeats the default https port');
  }
  return findings;
}
