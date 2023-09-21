/*
 * Copyright (c) Brendan Shanks.  All rights reserved.
 *
 * This file is part of ntlmclient, distributed under the MIT license.
 * For full terms and copyright information, and for third-party
 * copyright information, see the included LICENSE.txt file.
 */

#include <stdint.h>
#include <string.h>

#include <windows.h>
#include <bcrypt.h>

#include "ntlm.h"
#include "crypt.h"

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

bool ntlm_crypt_init(ntlm_client *ntlm)
{
	memset(&ntlm->crypt_ctx, 0, sizeof(ntlm_crypt_ctx));
	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&ntlm->crypt_ctx.md4_alg, BCRYPT_MD4_ALGORITHM, NULL, 0)) ||
	    !NT_SUCCESS(BCryptOpenAlgorithmProvider(&ntlm->crypt_ctx.md5_alg, BCRYPT_MD5_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) ||
	    !NT_SUCCESS(BCryptOpenAlgorithmProvider(&ntlm->crypt_ctx.des_alg, BCRYPT_DES_ALGORITHM, NULL, 0)))
	{
		ntlm_client_set_errmsg(ntlm, "BCryptOpenAlgorithmProvider error");
		return false;
	}
	return true;
}

bool ntlm_random_bytes(
	unsigned char *out,
	ntlm_client *ntlm,
	size_t len)
{
	NTSTATUS status;

	status = BCryptGenRandom(NULL, out, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (!NT_SUCCESS(status))
	{
		ntlm_client_set_errmsg(ntlm, "BCryptGenRandom error");
		return false;
	}

	return true;
}

bool ntlm_des_encrypt(
	ntlm_des_block *out,
	ntlm_client *ntlm,
	ntlm_des_block *plaintext,
	ntlm_des_block *key)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hkey;
	ULONG written;

	status = BCryptGenerateSymmetricKey(ntlm->crypt_ctx.des_alg,
			&hkey,
			NULL, 0,
			(PUCHAR)key, sizeof(ntlm_des_block),
			0);
	if (!NT_SUCCESS(status))
		return false;

	status = BCryptEncrypt(hkey,
			(PUCHAR)plaintext, sizeof(ntlm_des_block),
			NULL,
			NULL, 0,
			(PUCHAR)out, sizeof(ntlm_des_block),
			&written, 0);
	if (!NT_SUCCESS(status))
		return false;

	BCryptDestroyKey(hkey);

	return true;
}

bool ntlm_md4_digest(
	unsigned char out[CRYPT_MD4_DIGESTSIZE],
	ntlm_client *ntlm,
	const unsigned char *in,
	size_t in_len)
{
	NTSTATUS status;
	BCRYPT_HASH_HANDLE hash;

	status = BCryptCreateHash(ntlm->crypt_ctx.md4_alg,
			&hash,
			NULL, 0,
			NULL, 0,
			0);
	if (!NT_SUCCESS(status))
		return false;

	status = BCryptHashData(hash, (PUCHAR)in, in_len, 0);
	if (!NT_SUCCESS(status))
		return false;

	status = BCryptFinishHash(hash, out, CRYPT_MD4_DIGESTSIZE, 0);
	if (!NT_SUCCESS(status))
		return false;

	BCryptDestroyHash(hash);

	return true;
}

bool ntlm_hmac_md5_init(
	ntlm_client *ntlm,
	const unsigned char *key,
	size_t key_len)
{
	NTSTATUS status;

	status = BCryptCreateHash(ntlm->crypt_ctx.md5_alg,
			&ntlm->crypt_ctx.md5_hash,
			NULL, 0,
			(PUCHAR)key, key_len,
			0);
	if (!NT_SUCCESS(status))
		return false;

	return true;
}

bool ntlm_hmac_md5_update(
	ntlm_client *ntlm,
	const unsigned char *data,
	size_t data_len)
{
	NTSTATUS status;

	status = BCryptHashData(ntlm->crypt_ctx.md5_hash, (PUCHAR)data, data_len, 0);
	if (!NT_SUCCESS(status))
		return false;

	return true;
}

bool ntlm_hmac_md5_final(
	unsigned char *out,
	size_t *out_len,
	ntlm_client *ntlm)
{
	NTSTATUS status;

	if (*out_len < CRYPT_MD5_DIGESTSIZE)
		return false;

	status = BCryptFinishHash(ntlm->crypt_ctx.md5_hash, out, *out_len, 0);
	if (!NT_SUCCESS(status))
		return false;

	BCryptDestroyHash(ntlm->crypt_ctx.md5_hash);

	*out_len = CRYPT_MD5_DIGESTSIZE;
	return true;
}

void ntlm_crypt_shutdown(ntlm_client *ntlm)
{
	BCryptCloseAlgorithmProvider(ntlm->crypt_ctx.md4_alg, 0);
	BCryptCloseAlgorithmProvider(ntlm->crypt_ctx.md5_alg, 0);
	BCryptCloseAlgorithmProvider(ntlm->crypt_ctx.des_alg, 0);
}
