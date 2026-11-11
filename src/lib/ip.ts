import { isIPv4, isIPv6 } from 'node:net';

/**
 * Minimal IPv4/IPv6 + CIDR utilities used by the blocklist.
 *
 * Every address is converted to a BigInt (32 bits for IPv4, 128 bits for IPv6).
 * An address belongs to a CIDR block when the first `prefix` bits are equal:
 *   (address & mask) === network
 */

export type IpVersion = 4 | 6;

export interface ParsedIp {
  version: IpVersion;
  value: bigint;
}

export interface Cidr {
  version: IpVersion;
  /** Network address (host bits zeroed). */
  network: bigint;
  prefix: number;
}

const BITS: Record<IpVersion, number> = { 4: 32, 6: 128 };

function ipv4ToBigInt(address: string): bigint {
  return address.split('.').reduce((acc, octet) => (acc << 8n) | BigInt(Number(octet)), 0n);
}

function ipv6ToBigInt(address: string): bigint {
  let normalized = address;

  // Embedded IPv4 tail, e.g. ::ffff:192.0.2.1 -> convert the dotted part into two hextets.
  const lastColon = normalized.lastIndexOf(':');
  const tail = normalized.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToBigInt(tail);
    const high = ((v4 >> 16n) & 0xffffn).toString(16);
    const low = (v4 & 0xffffn).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${high}:${low}`;
  }

  // Expand "::" into the right number of zero groups.
  const [head = '', rest] = normalized.split('::');
  const headGroups = head === '' ? [] : head.split(':');
  const tailGroups = rest === undefined || rest === '' ? [] : rest.split(':');
  const missing = 8 - headGroups.length - tailGroups.length;
  const groups =
    rest === undefined
      ? headGroups
      : [...headGroups, ...Array<string>(missing).fill('0'), ...tailGroups];

  return groups.reduce((acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)), 0n);
}

const IPV4_MAPPED_PREFIX = 0xffffn << 32n; // ::ffff:0:0/96

/**
 * Parses an IP address. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d), which Node reports
 * for IPv4 clients on dual-stack sockets, are normalized to plain IPv4 so that a rule
 * like 203.0.113.0/24 still matches them.
 */
export function parseIp(input: string): ParsedIp | null {
  const address = input.trim().split('%')[0] ?? ''; // drop IPv6 zone id (fe80::1%eth0)

  if (isIPv4(address)) return { version: 4, value: ipv4ToBigInt(address) };
  if (!isIPv6(address)) return null;

  const value = ipv6ToBigInt(address);
  if (value >> 32n === IPV4_MAPPED_PREFIX >> 32n) {
    return { version: 4, value: value & 0xffffffffn };
  }
  return { version: 6, value };
}

function maskFor(version: IpVersion, prefix: number): bigint {
  const bits = BITS[version];
  if (prefix === 0) return 0n;
  return ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
}

/**
 * Parses "10.0.0.0/8", "2001:db8::/32" or a bare address (treated as /32 or /128).
 * Host bits are zeroed, so "10.1.2.3/8" is normalized to 10.0.0.0/8.
 */
export function parseCidr(input: string): Cidr | null {
  const [addressPart, prefixPart, extra] = input.trim().split('/');
  if (addressPart === undefined || extra !== undefined) return null;

  const ip = parseIp(addressPart);
  if (!ip) return null;

  const bits = BITS[ip.version];
  let prefix = bits;
  if (prefixPart !== undefined) {
    if (!/^\d{1,3}$/.test(prefixPart)) return null;
    prefix = Number(prefixPart);
    if (prefix > bits) return null;
  }

  return { version: ip.version, network: ip.value & maskFor(ip.version, prefix), prefix };
}

export function cidrContains(cidr: Cidr, ip: ParsedIp): boolean {
  if (cidr.version !== ip.version) return false;
  return (ip.value & maskFor(cidr.version, cidr.prefix)) === cidr.network;
}

function formatIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => ((value >> shift) & 0xffn).toString()).join('.');
}

/** RFC 5952 style: lowercase, no leading zeros, longest run (>= 2) of zero groups as "::". */
function formatIpv6(value: bigint): string {
  const groups = Array.from({ length: 8 }, (_, i) =>
    Number((value >> BigInt(112 - i * 16)) & 0xffffn),
  );

  let bestStart = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }

  const hex = groups.map((g) => g.toString(16));
  if (bestLength < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLength).join(':');
  return `${head}::${tail}`;
}

export function formatCidr(cidr: Cidr): string {
  const address = cidr.version === 4 ? formatIpv4(cidr.network) : formatIpv6(cidr.network);
  return `${address}/${cidr.prefix}`;
}

export function isValidIp(input: string): boolean {
  return parseIp(input) !== null;
}
