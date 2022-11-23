#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <memory>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

const size_t IV_LEN = 16; // must be equal to block size (128 bits)

int eprintf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_eputs(buf);
  return (int)strnlen(buf, BUFSIZ - 1) + 1;
};

struct IpcPacket {
  const enum Type { HANDSHAKE, RECORD } type;
  IpcPacket(Type type) : type(type) {}
  void *to_void() {
    return this;
  }
};

struct IpcHandshakePacket : public IpcPacket {
  sgx_ec256_public_t sender_pk;
  IpcHandshakePacket(const sgx_ec256_public_t &sender_pk)
      : IpcPacket(HANDSHAKE), sender_pk(sender_pk) {}
};
struct IpcRecordPacket : public IpcPacket {
  uint8_t iv[IV_LEN];
  const uint32_t len;
  uint8_t ciphertext[];

protected:
  IpcRecordPacket(uint32_t len) : IpcPacket(RECORD), len(len) {}

public:
  static std::unique_ptr<IpcRecordPacket> make(uint32_t len) {
    IpcRecordPacket *pkt = (IpcRecordPacket *)malloc(sizeof *pkt + len);
    new (pkt) IpcRecordPacket(len);
    return std::unique_ptr<IpcRecordPacket>{pkt};
  }
  size_t size() const {
    return sizeof *this + len;
  }
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
  sgx_aes_ctr_128bit_key_t ssk;

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
    IpcHandshakePacket handshake(pk);
    ipc_send((char *)handshake.to_void(), sizeof handshake);
    stage = NO_KEY;
    return status;
  }

  sgx_status_t recv(const IpcHandshakePacket *pkt) {
    assert(stage == NO_KEY);
    sgx_ec256_dh_shared_t dh_ssk;
    sgx_status_t status =
        sgx_ecc256_compute_shared_dhkey(&sk, &pkt->sender_pk, &dh_ssk, handle);
    if (status) {
      eprintf("sgx_ecc256_compute_shared_dhkey: %d", status);
      return status;
    }
    memcpy(ssk, &dh_ssk.s, sizeof ssk);
    stage = READY;
    return status;
  }

  sgx_status_t recv(const IpcRecordPacket *pkt) {
    assert(stage == READY);
    uint8_t iv[IV_LEN];
    std::vector<uint8_t> buf(pkt->len);
    memcpy(iv, pkt->iv, sizeof iv);
    sgx_aes_ctr_decrypt(&ssk, pkt->ciphertext, pkt->len, iv, 8, buf.data());
    eprintf("%s", buf.data());
    return SGX_SUCCESS;
  }

  sgx_status_t say_hello() {
    uint8_t msg[] = "hello world!";
    uint8_t iv[IV_LEN] = {}; // TODO: randomize
    auto pkt = IpcRecordPacket::make(sizeof msg);
    memcpy(pkt->iv, iv, sizeof pkt->iv);
    sgx_aes_ctr_encrypt(&ssk, msg, sizeof msg, iv, 8, pkt->ciphertext);
    ipc_send((char *)pkt->to_void(), pkt->size());
    std::vector<uint8_t> buf(pkt->len);
    memcpy(iv, pkt->iv, sizeof iv);
    sgx_aes_ctr_decrypt(&ssk, pkt->ciphertext, pkt->len, iv, 8, buf.data());
    return SGX_SUCCESS;
  }
};

static EnclaveState state;

sgx_status_t enclave_reset() {
  return state.reset();
}

sgx_status_t ipc_recv(const char *buf, size_t buflen) {
  auto pkt = (const IpcPacket *)buf;
  assert(buflen >= sizeof *pkt);
  switch (pkt->type) {
  case IpcPacket::HANDSHAKE: {
    auto pkt1 = static_cast<const IpcHandshakePacket *>(pkt);
    assert(buflen >= sizeof *pkt1);
    return state.recv(pkt1);
  } break;
  case IpcPacket::RECORD: {
    auto pkt1 = static_cast<const IpcRecordPacket *>(pkt);
    assert(buflen >= sizeof *pkt1);
    assert(buflen >= pkt1->size());
    return state.recv(pkt1);
  } break;
  default:
    eprintf("unable to upcast!");
    return SGX_ERROR_INVALID_PARAMETER;
  }
}

void say_hello() {
  state.say_hello();
}
