/*
 * Copyright (c) Brendan Shanks.  All rights reserved.
 *
 * This file is part of ntlmclient, distributed under the MIT license.
 * For full terms and copyright information, and for third-party
 * copyright information, see the included LICENSE.txt file.
 */

#ifndef PRIVATE_CRYPT_BCRYPT_H__
#define PRIVATE_CRYPT_BCRYPT_H__

#include <windows.h>
#include <bcrypt.h>

struct ntlm_crypt_ctx {
	BCRYPT_ALG_HANDLE md4_alg;
	BCRYPT_ALG_HANDLE md5_alg;
	BCRYPT_HASH_HANDLE md5_hash;
	BCRYPT_ALG_HANDLE des_alg;
};

#endif /* PRIVATE_CRYPT_BCRYPT_H__ */
