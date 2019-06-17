// SPDX-License-Identifier: GPL-2.0
/*
 * Multipath TCP cryptographic functions
 * Copyright (c) 2017 - 2019, Intel Corporation.
 *
 * Note: This code is based on mptcp_ctrl.c, mptcp_ipv4.c, and
 *       mptcp_ipv6 from multipath-tcp.org, authored by:
 *
 *       Sébastien Barré <sebastien.barre@uclouvain.be>
 *       Christoph Paasch <christoph.paasch@uclouvain.be>
 *       Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *       Gregory Detal <gregory.detal@uclouvain.be>
 *       Fabien Duchêne <fabien.duchene@uclouvain.be>
 *       Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *       Lavkesh Lahngir <lavkesh51@gmail.com>
 *       Andreas Ripke <ripke@neclab.eu>
 *       Vlad Dogaru <vlad.dogaru@intel.com>
 *       Octavian Purdila <octavian.purdila@intel.com>
 *       John Ronan <jronan@tssg.org>
 *       Catalin Nicutar <catalin.nicutar@gmail.com>
 *       Brandon Heller <brandonh@stanford.edu>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cryptohash.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include <asm/unaligned.h>

static siphash_key_t crypto_key_secret __read_mostly;
static hsiphash_key_t crypto_nonce_secret __read_mostly;
static u32 crypto_seed;

u32 crypto_v4_get_nonce(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	return hsiphash_4u32((__force u32)saddr, (__force u32)daddr,
			    (__force u32)sport << 16 | (__force u32)dport,
			    crypto_seed++, &crypto_nonce_secret);
}

u64 crypto_v4_get_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	pr_debug("src=%x:%d, dst=%x:%d", saddr, sport, daddr, dport);
	return siphash_4u32((__force u32)saddr, (__force u32)daddr,
			    (__force u32)sport << 16 | (__force u32)dport,
			    crypto_seed++, &crypto_key_secret);
}

u32 crypto_v6_get_nonce(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__be16 sport, __be16 dport)
{
	const struct {
		struct in6_addr saddr;
		struct in6_addr daddr;
		u32 seed;
		__be16 sport;
		__be16 dport;
	} __aligned(SIPHASH_ALIGNMENT) combined = {
		.saddr = *saddr,
		.daddr = *daddr,
		.seed = crypto_seed++,
		.sport = sport,
		.dport = dport,
	};

	return hsiphash(&combined, offsetofend(typeof(combined), dport),
			&crypto_nonce_secret);
}

u64 crypto_v6_get_key(const struct in6_addr *saddr,
		      const struct in6_addr *daddr,
		      __be16 sport, __be16 dport)
{
	const struct {
		struct in6_addr saddr;
		struct in6_addr daddr;
		u32 seed;
		__be16 sport;
		__be16 dport;
	} __aligned(SIPHASH_ALIGNMENT) combined = {
		.saddr = *saddr,
		.daddr = *daddr,
		.seed = crypto_seed++,
		.sport = sport,
		.dport = dport,
	};

	return siphash(&combined, offsetofend(typeof(combined), dport),
		       &crypto_key_secret);
}

void crypto_key_sha1(u64 key, u32 *token, u64 *idsn)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u32 mptcp_hashed_key[SHA_DIGEST_WORDS];
	u8 input[64];

	memset(workspace, 0, sizeof(workspace));

	/* Initialize input with appropriate padding */
	memset(&input[9], 0, sizeof(input) - 10); /* -10, because the last byte
						   * is explicitly set too
						   */
	put_unaligned_be64(key, input);
	input[8] = 0x80; /* Padding: First bit after message = 1 */
	input[63] = 0x40; /* Padding: Length of the message = 64 bits */

	sha_init(mptcp_hashed_key);
	sha_transform(mptcp_hashed_key, input, workspace);

	if (token)
		*token = mptcp_hashed_key[0];
	if (idsn)
		*idsn = ((u64)mptcp_hashed_key[3] << 32) + mptcp_hashed_key[4];
}

void crypto_hmac_sha1(u64 key1, u64 key2, u32 *hash_out,
		      int arg_num, ...)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u8 input[128]; /* 2 512-bit blocks */
	int i;
	int index;
	int length;
	u8 *msg;
	va_list list;
	u8 key_1[8];
	u8 key_2[8];

	memset(workspace, 0, sizeof(workspace));

	put_unaligned_be64(key1, key_1);
	put_unaligned_be64(key2, key_2);

	/* Generate key xored with ipad */
	memset(input, 0x36, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	va_start(list, arg_num);
	index = 64;
	for (i = 0; i < arg_num; i++) {
		length = va_arg(list, int);
		msg = va_arg(list, u8 *);
		WARN_ON(index + length > 125); /* Message is too long */
		memcpy(&input[index], msg, length);
		index += length;
	}
	va_end(list);

	input[index] = 0x80; /* Padding: First bit after message = 1 */
	memset(&input[index + 1], 0, (126 - index));

	/* Padding: Length of the message = 512 + message length (bits) */
	input[126] = 0x02;
	input[127] = ((index - 64) * 8); /* Message length (bits) */

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);
	memset(workspace, 0, sizeof(workspace));

	for (i = 0; i < 5; i++)
		hash_out[i] = (__force u32)cpu_to_be32(hash_out[i]);

	/* Prepare second part of hmac */
	memset(input, 0x5C, 64);
	for (i = 0; i < 8; i++)
		input[i] ^= key_1[i];
	for (i = 0; i < 8; i++)
		input[i + 8] ^= key_2[i];

	memcpy(&input[64], hash_out, 20);
	input[84] = 0x80;
	memset(&input[85], 0, 41);

	/* Padding: Length of the message = 512 + 160 bits */
	input[126] = 0x02;
	input[127] = 0xA0;

	sha_init(hash_out);
	sha_transform(hash_out, input, workspace);
	memset(workspace, 0, sizeof(workspace));

	sha_transform(hash_out, &input[64], workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = (__force u32)cpu_to_be32(hash_out[i]);
}

void crypto_init(void)
{
	get_random_bytes((void *)&crypto_key_secret,
			 sizeof(crypto_key_secret));
	get_random_bytes((void *)&crypto_nonce_secret,
			 sizeof(crypto_nonce_secret));
	crypto_seed = 0;
}
