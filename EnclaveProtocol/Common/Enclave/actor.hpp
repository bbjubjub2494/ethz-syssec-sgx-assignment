#include "Enclave.h"
#include "Enclave_t.h" /* ocalls */

#include "messages.hpp"
#include "packets.hpp"
#include "utils.hpp"

#include <cstring>
#include <vector>

#include "sgx_trts.h"

class Actor {
  EnclaveState state = ERROR;

  sgx_ecc_state_handle_t handle;
  sgx_ec256_private_t sk;
  sgx_ec256_public_t pk;
  sgx_aes_ctr_128bit_key_t ssk;

  uint64_t challenge_id;
  uint64_t a, b;
  uint64_t round_count = 20;

public:
  sgx_status_t reset() {
    sgx_status_t status;

    status = sgx_ecc256_open_context(&handle);
    if (status) {
      logf("sgx_ecc256_open_context: %d", status);
      state = ERROR;
      return status;
    }

    status = sgx_ecc256_create_key_pair(&sk, &pk, handle);
    if (status) {
      logf("sgx_ecc256_create_key_pair: %d", status);
      state = ERROR;
      return status;
    }
    IpcHandshakePacket handshake(pk);
    ocall_ipc_send((char *)handshake.to_void(), sizeof handshake);
    state = NO_KEY;
    return status;
  }

  EnclaveState get_state() const {
    return state;
  }

  sgx_status_t recv(const IpcHandshakePacket *pkt) {
    if (state != NO_KEY) {
      logf("unexpected handshake");
      return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_ec256_dh_shared_t dh_ssk;
    sgx_status_t status =
        sgx_ecc256_compute_shared_dhkey(&sk, &pkt->sender_pk, &dh_ssk, handle);
    if (status) {
      logf("sgx_ecc256_compute_shared_dhkey: %d", status);
      return status;
    }
    std::memcpy(ssk, &dh_ssk.s, sizeof ssk);
    state = READY;
    return status;
  }

  sgx_status_t recv(const IpcRecordPacket *pkt) {
    if (state == NO_KEY || state == ERROR) {
      logf("unable to process messages");
      return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t iv[IV_LEN];
    std::vector<uint8_t> buf(pkt->len);
    std::memcpy(iv, pkt->iv, sizeof iv);
    sgx_aes_ctr_decrypt(&ssk, pkt->ciphertext, pkt->len, iv, 8, buf.data());
    recv(Message::safe_cast(buf.data(), buf.size()));
    return SGX_SUCCESS;
  }

  sgx_status_t recv(const Message *msg) {
    switch (msg->type) {
    case Message::CHALLENGE:
      logf("received challenge");
      return recv((ChallengeMessage *)msg);
    case Message::RESPONSE:
      logf("received response");
      return recv((ResponseMessage *)msg);
    default:
      return SGX_ERROR_INVALID_PARAMETER;
    }
  }

  sgx_status_t recv(const ChallengeMessage *msg) {
    auto id = msg->challenge_id;
    auto c = msg->a + msg->b;
    ResponseMessage rep(id, c);
    if (--round_count <= 0)
      state = DONE;
    return send(&rep);
  }

  sgx_status_t recv(const ResponseMessage *msg) {
    if (state != AWAIT_RESPONSE) {
      logf("unexpected response");
      return SGX_ERROR_INVALID_PARAMETER;
    }
    if (challenge_id != msg->challenge_id) {
      logf("invalid response challenge id");
      return SGX_ERROR_INVALID_PARAMETER;
    }
    if (msg->c - a != b) {
      logf("invalid response proof");
      return SGX_ERROR_INVALID_PARAMETER;
    }
    logf("Challenge passed!");
    state = READY;
    if (--round_count <= 0)
      state = DONE;
    return SGX_SUCCESS;
  }

  template <typename M> sgx_status_t send(const M *msg) {
    const uint8_t *buf = msg->data();
    size_t buflen = msg->data_size();
    assert(buflen <= UINT32_MAX);
    uint8_t iv[IV_LEN];
    sgx_read_rand(iv, sizeof iv);
    auto pkt = IpcRecordPacket::make(buflen);
    std::memcpy(pkt->iv, iv, sizeof pkt->iv);
    sgx_aes_ctr_encrypt(&ssk, buf, buflen, iv, 8, pkt->ciphertext);
    return ocall_ipc_send((char *)pkt->to_void(), pkt->size());
  }

  sgx_status_t issue_challenge() {
    assert(state == READY);
    logf("issuing challenge...");
    sgx_read_rand((uint8_t *)&challenge_id, sizeof challenge_id);
    sgx_read_rand((uint8_t *)&a, sizeof a);
    sgx_read_rand((uint8_t *)&b, sizeof b);
    ChallengeMessage msg(challenge_id, a, b);
    state = AWAIT_RESPONSE;
    return send(&msg);
  }
};
