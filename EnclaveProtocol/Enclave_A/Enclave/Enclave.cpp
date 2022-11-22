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

struct IpcPacket {
	void *to_void() {
		return this;
	}
	virtual ~IpcPacket() {}
};

struct IpcHandshakePacket : public IpcPacket {
	sgx_ec256_public_t sender_pk;
};
struct Record {
			char iv[16];
			size_t len;
			char ciphertext[];
};

class EnclaveState {
enum {
	NO_KEY,
	READY,
	ERROR,
} stage = ERROR;

    sgx_ecc_state_handle_t handle;
    sgx_ec256_private_t sk;
    sgx_ec256_public_t pk;
    sgx_ec256_dh_shared_t ssk;

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
	    IpcHandshakePacket handshake;
	    handshake.sender_pk = pk;
	    ipc_send((char*)handshake.to_void(), sizeof handshake);
	    stage = NO_KEY;
	    return status;
    }

    sgx_status_t recv(const IpcHandshakePacket *pkt) {
	    sgx_status_t status = sgx_ecc256_compute_shared_dhkey(&sk, &pkt->sender_pk, &ssk, handle);
	    if (status) {
		    eprintf("sgx_ecc256_compute_shared_dhkey: %d", status);
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

sgx_status_t ipc_recv(const char* buf, size_t buflen) {
	auto pkt = (const IpcPacket*)buf;
	assert(buflen >= sizeof *pkt);
	if (auto pkt1 = dynamic_cast<const IpcHandshakePacket*>(pkt)) {
		assert(buflen >= sizeof *pkt1);
		return state.recv(pkt1);
	} else {
		eprintf("unable to upcast!");
		return SGX_ERROR_INVALID_PARAMETER;
	}
}
