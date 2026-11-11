import { describe, expect, it } from 'vitest';
import { cidrContains, formatCidr, parseCidr, parseIp, type Cidr } from '../../src/lib/ip.js';

function contains(cidr: string, ip: string): boolean {
  const block = parseCidr(cidr);
  const address = parseIp(ip);
  if (!block || !address) throw new Error(`invalid test input ${cidr} / ${ip}`);
  return cidrContains(block, address);
}

describe('parseIp', () => {
  it('parses IPv4', () => {
    expect(parseIp('192.168.1.10')).toEqual({ version: 4, value: 0xc0a8010an });
  });

  it('parses compressed IPv6', () => {
    expect(parseIp('2001:db8::1')).toEqual({
      version: 6,
      value: 0x20010db8000000000000000000000001n,
    });
    expect(parseIp('::')).toEqual({ version: 6, value: 0n });
  });

  it('normalizes IPv4-mapped IPv6 to IPv4', () => {
    expect(parseIp('::ffff:203.0.113.9')).toEqual(parseIp('203.0.113.9'));
    expect(parseIp('::ffff:cb00:7109')).toEqual(parseIp('203.0.113.9'));
  });

  it('ignores IPv6 zone ids', () => {
    expect(parseIp('fe80::1%eth0')).toEqual(parseIp('fe80::1'));
  });

  it.each(['', 'abc', '256.1.1.1', '1.2.3', '1.2.3.4.5', '2001:db8:::1', '10.0.0.1/24'])(
    'rejects invalid input %j',
    (input) => {
      expect(parseIp(input)).toBeNull();
    },
  );
});

describe('parseCidr', () => {
  it('treats a bare address as a host route', () => {
    expect(parseCidr('10.0.0.1')).toMatchObject({ version: 4, prefix: 32 });
    expect(parseCidr('2001:db8::1')).toMatchObject({ version: 6, prefix: 128 });
  });

  it('zeroes host bits', () => {
    const cidr = parseCidr('10.1.2.3/8') as Cidr;
    expect(formatCidr(cidr)).toBe('10.0.0.0/8');
  });

  it.each(['10.0.0.0/33', '2001:db8::/129', '10.0.0.0/-1', '10.0.0.0/abc', '10.0.0.0/8/8', 'x/8'])(
    'rejects invalid CIDR %j',
    (input) => {
      expect(parseCidr(input)).toBeNull();
    },
  );
});

describe('cidrContains', () => {
  it('matches addresses inside an IPv4 block', () => {
    expect(contains('203.0.113.0/24', '203.0.113.0')).toBe(true);
    expect(contains('203.0.113.0/24', '203.0.113.255')).toBe(true);
    expect(contains('203.0.113.0/24', '203.0.114.0')).toBe(false);
    expect(contains('203.0.113.0/24', '203.0.112.255')).toBe(false);
  });

  it('handles non-octet-aligned prefixes', () => {
    // 10.0.0.0/12 covers 10.0.0.0 - 10.15.255.255
    expect(contains('10.0.0.0/12', '10.15.255.255')).toBe(true);
    expect(contains('10.0.0.0/12', '10.16.0.0')).toBe(false);
  });

  it('handles /0 and /32', () => {
    expect(contains('0.0.0.0/0', '8.8.8.8')).toBe(true);
    expect(contains('8.8.8.8/32', '8.8.8.8')).toBe(true);
    expect(contains('8.8.8.8/32', '8.8.8.9')).toBe(false);
  });

  it('matches IPv6 blocks', () => {
    expect(contains('2001:db8::/32', '2001:db8:ffff::1')).toBe(true);
    expect(contains('2001:db8::/32', '2001:db9::1')).toBe(false);
  });

  it('never matches across IP versions', () => {
    expect(contains('0.0.0.0/0', '::1')).toBe(false);
    expect(contains('::/0', '127.0.0.1')).toBe(false);
  });

  it('matches IPv4-mapped clients against IPv4 rules', () => {
    expect(contains('203.0.113.0/24', '::ffff:203.0.113.50')).toBe(true);
  });
});

describe('formatCidr', () => {
  it.each([
    ['2001:0db8:0000:0000:0000:0000:0000:0001/128', '2001:db8::1/128'],
    ['2001:db8:0:1:0:0:0:0/64', '2001:db8:0:1::/64'],
    ['::/0', '::/0'],
    ['::1', '::1/128'],
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2:3:4:5:6/128'],
    ['192.168.1.77/16', '192.168.0.0/16'],
  ])('formats %s as %s', (input, expected) => {
    expect(formatCidr(parseCidr(input) as Cidr)).toBe(expected);
  });
});
