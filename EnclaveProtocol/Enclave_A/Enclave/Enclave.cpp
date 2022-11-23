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

int logf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_elog(buf);
  return (int)strnlen(buf, BUFSIZ - 1) + 1;
};

struct IpcPacket {
  const enum Type { HANDSHAKE, RECORD } type;
  void *to_void() {
    return this;
  }

protected:
  IpcPacket(Type type) : type(type) {}
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

struct Message {
  enum Type { CHALLENGE, RESPONSE } type;
  const uint8_t *data() const {
    return reinterpret_cast<const uint8_t *>(this);
  }
  static const Message *safe_cast(const uint8_t *data, size_t len);

protected:
  Message(Type type) : type(type) {}
  size_t data_size() const; // override me!
};

struct ChallengeMessage : public Message {
  const uint64_t challenge_id;
  const uint64_t a, b;
  ChallengeMessage(uint64_t challenge_id, uint64_t a, uint64_t b)
      : Message(CHALLENGE), challenge_id(challenge_id), a(a), b(b) {}
  const size_t data_size() const {
    return sizeof *this;
  }
};

struct ResponseMessage : public Message {
  const uint64_t challenge_id;
  const uint64_t c;
  ResponseMessage(uint64_t challenge_id, uint64_t c)
      : Message(RESPONSE), challenge_id(challenge_id), c(c) {}
  const size_t data_size() const {
    return sizeof *this;
  }
};

inline const Message *Message::safe_cast(const uint8_t *data, size_t len) {
  if (len < sizeof(Message))
    return nullptr;
  auto msg = reinterpret_cast<const Message *>(data);
  switch (msg->type) {
  case CHALLENGE:
    if (len < sizeof(ChallengeMessage))
      return nullptr;
    break;
  case RESPONSE:
    if (len < sizeof(ResponseMessage))
      return nullptr;
    break;
  default:
    return nullptr;
  }
  return msg;
}

class Actor {
  EnclaveState stage = ERROR;

  sgx_ecc_state_handle_t handle;
  sgx_ec256_private_t sk;
  sgx_ec256_public_t pk;
  sgx_aes_ctr_128bit_key_t ssk;

  uint64_t challenge_id;
  uint64_t a, b;

public:
  sgx_status_t reset() {
    sgx_status_t status;

    status = sgx_ecc256_open_context(&handle);
    if (status) {
      logf("sgx_ecc256_open_context: %d", status);
      stage = ERROR;
      return status;
    }

    status = sgx_ecc256_create_key_pair(&sk, &pk, handle);
    if (status) {
      logf("sgx_ecc256_create_key_pair: %d", status);
      stage = ERROR;
      return status;
    }
    IpcHandshakePacket handshake(pk);
    ipc_send((char *)handshake.to_void(), sizeof handshake);
    stage = NO_KEY;
    return status;
  }

  EnclaveState get_state() const {
    return stage;
  }

  sgx_status_t recv(const IpcHandshakePacket *pkt) {
    assert(stage == NO_KEY);
    sgx_ec256_dh_shared_t dh_ssk;
    sgx_status_t status =
        sgx_ecc256_compute_shared_dhkey(&sk, &pkt->sender_pk, &dh_ssk, handle);
    if (status) {
      logf("sgx_ecc256_compute_shared_dhkey: %d", status);
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
    recv(Message::safe_cast(buf.data(), buf.size()));
    return SGX_SUCCESS;
  }

  sgx_status_t recv(const Message *msg) {
    switch (msg->type) {
    case Message::CHALLENGE:
      return recv((ChallengeMessage *)msg);
    case Message::RESPONSE:
      return recv((ResponseMessage *)msg);
    default:
      return SGX_ERROR_INVALID_PARAMETER;
    }
  }

  sgx_status_t recv(const ChallengeMessage *msg) {
    auto id = msg->challenge_id;
    auto c = msg->a + msg->b;
    ResponseMessage rep(id, c);
    return send(&rep);
  }

  sgx_status_t recv(const ResponseMessage *msg) {
    assert(stage == AWAIT_RESPONSE);
    assert(challenge_id == msg->challenge_id);
    assert(msg->c - a == b);
    logf("Challenge passed!");
    stage = READY;
    return SGX_SUCCESS;
  }

  template <typename M> sgx_status_t send(const M *msg) {
    const uint8_t *buf = msg->data();
    size_t buflen = msg->data_size();
    assert(buflen <= UINT32_MAX);
    uint8_t iv[IV_LEN];
    sgx_read_rand(iv, sizeof iv);
    auto pkt = IpcRecordPacket::make(buflen);
    memcpy(pkt->iv, iv, sizeof pkt->iv);
    sgx_aes_ctr_encrypt(&ssk, buf, buflen, iv, 8, pkt->ciphertext);
    return ipc_send((char *)pkt->to_void(), pkt->size());
  }

  sgx_status_t issue_challenge() {
    assert(stage == READY);
    sgx_read_rand((uint8_t *)&challenge_id, sizeof challenge_id);
    sgx_read_rand((uint8_t *)&a, sizeof a);
    sgx_read_rand((uint8_t *)&b, sizeof b);
    ChallengeMessage msg(challenge_id, a, b);
    stage = AWAIT_RESPONSE;
    return send(&msg);
  }
};

static Actor state;

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
    logf("unable to upcast!");
    return SGX_ERROR_INVALID_PARAMETER;
  }
}

sgx_status_t enclave_issue_challenge() {
  return state.issue_challenge();
}
EnclaveState enclave_state() {
  return state.get_state();
}
