#include "actor.hpp"

static Actor actor;

sgx_status_t enclave_reset() {
  return actor.reset();
}

sgx_status_t enclave_ipc_recv(const char *buf, size_t buflen) {
  auto pkt = (const IpcPacket *)buf;
  assert(buflen >= sizeof *pkt);
  switch (pkt->type) {
  case IpcPacket::HANDSHAKE: {
    auto pkt1 = static_cast<const IpcHandshakePacket *>(pkt);
    assert(buflen >= sizeof *pkt1);
    return actor.recv(pkt1);
  } break;
  case IpcPacket::RECORD: {
    auto pkt1 = static_cast<const IpcRecordPacket *>(pkt);
    assert(buflen >= sizeof *pkt1);
    assert(buflen >= pkt1->size());
    return actor.recv(pkt1);
  } break;
  default:
    logf("unable to upcast!");
    return SGX_ERROR_INVALID_PARAMETER;
  }
}

sgx_status_t enclave_issue_challenge() {
  return actor.issue_challenge();
}

EnclaveState enclave_state() {
  return actor.get_state();
}
