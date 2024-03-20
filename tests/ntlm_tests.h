#ifndef PRIVATE_TESTS_NTLM_H__
#define PRIVATE_TESTS_NTLM_H__

#include "clar.h"
#include "ntlm.h"
#include "util.h"

#define cl_must_fail_with_(val, expr, desc) clar__assert((expr) == (val), __FILE__, __func__, __LINE__, "Expected function call to fail with " #val ": " #expr, desc, 0)

#define cl_must_fail_with(val, expr) cl_must_fail_with_(val, expr, NULL)

#define cl_ntlm_pass(ntlm, expr) cl_ntlm_expect((ntlm), (expr), 0, __FILE__, __func__, __LINE__)

#define cl_ntlm_expect(ntlm, expr, expected, file, func, line) do { \
	int _ntlm_error; \
	if ((_ntlm_error = (expr)) != expected) \
		cl_ntlm_report_failure(ntlm, file, func, line, "Function call failed: " #expr); \
} while (0)

#ifdef __GNUC__
__attribute__((unused))
#endif
static void cl_ntlm_report_failure(
	ntlm_client *ntlm,
	const char *file,
	const char *func,
	int line,
	const char *message)
{
	clar__fail(file, func, line, message, ntlm_client_errmsg(ntlm), 1);
}

#endif /* PRIVATE_TESTS_NTLM_H__ */
