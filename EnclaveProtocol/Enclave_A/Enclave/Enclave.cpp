#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_trts.h"
#include "sgx_tcrypto.h"


int eprintf(const char* fmt, ...) {
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_eputs(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
};

class EnclaveState {
enum {
	READY,
	ERROR,
} stage = ERROR;

    sgx_ecc_state_handle_t handle;
    sgx_ec256_private_t sk;
    sgx_ec256_public_t pk;

    public:
    sgx_status_t reset() {
	    sgx_status_t status;

	    status = sgx_ecc256_open_context(&handle);
	    if (status) {
		    eprintf("sgx_ecc256_open_context: %d", status);
		    stage = ERROR;
		    return status;
	    }

	    status = sgx_ecc256_create_key_pair(&sk, &pk, handle);
	    if (status) {
		    eprintf("sgx_ecc256_create_key_pair: %d", status);
		    stage = ERROR;
		    return status;
	    }
	    stage = READY;
	    return status;
    }
};

static EnclaveState state;


sgx_status_t enclave_reset()
{
  return state.reset();
}

void ipc_recv(const char* buf, size_t buflen) {
}
