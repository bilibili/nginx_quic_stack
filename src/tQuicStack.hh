// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack class.

#ifndef _NGINX_T_QUIC_STACK_H_
#define _NGINX_T_QUIC_STACK_H_

#include <memory>
#include <unordered_map>
#include "quic/core/crypto/proof_source.h"
#include "quic/platform/api/quic_socket_address.h"
#include "quic/core/crypto/quic_crypto_server_config.h"
#include "quic/core/crypto/quic_random.h"
#include "quic/core/proto/crypto_server_config_proto.h"
#include "src/tQuicDispatcher.hh"
#include "src/tQuicServerStream.hh"
#include "src/tQuicAlarmFactory.hh"
#include "src/quic_stack_api.h"
#include "src/tQuicClock.hh"

namespace nginx {

class tQuicStack {
 public:
  tQuicStack(tQuicStackContext stack_ctx,
             tQuicRequestCallback cb,
             tQuicClockTimeGenerator clock_gen,
             uint32_t max_streams_per_connection,
             uint64_t initial_idle_timeout_in_sec,
             uint64_t default_idle_timeout_in_sec,
             uint64_t max_idle_timeout_in_sec,
             uint64_t max_time_before_crypto_handshake_in_sec,
             uint8_t expected_connection_id_length);

  ~tQuicStack();

  void AddCertificate(const tQuicServerIdentify& qsi);

  void InitializeWithWriter(int fd, tQuicOnCanWriteCallback cb);

  void ProcessBufferedChlos(size_t max_connections_to_create);

  void ProcessPacket(const quic::QuicSocketAddress& self_addr,
                     const quic::QuicSocketAddress& peer_addr,
                     char* buffer, size_t length);

  void OnCanWrite();

  bool HasChlosBuffered();

  bool HasPendingWrites();

  int ReadRequestBody(
    const tQuicRequestID& id,
    char* data,
    size_t len);

  bool WriteResponseHeader(
    const tQuicRequestID& id,
    const char* data,
    size_t len,
    const char* trailers,
    size_t trailers_len,
    int fin);

  int WriteResponseBody(
    const tQuicRequestID& id,
    const char* data,
    size_t len,
    const char* trailers,
    size_t trailers_len,
    size_t limit,
    bool fin);

  void CloseStream(const tQuicRequestID& id);

  void AddOnCanWriteCallback(
    const tQuicRequestID& id,
    tQuicOnCanWriteCallback cb);

  int64_t NextAlarmTime();
  void OnAlarmTimeout(int64_t deadline_ms);

  tQuicServerIdentify* GetServerIdentifyByName(const std::string& name);
  bool AddServerIdentify(const tQuicServerIdentify& qsi);

 private:
  // Initialize the internal state of the stack.
  void Initialize();
  void InitializeConfigOptions(); 
  // Generates a QuicServerConfigProtobuf protobuf suitable for
  // QuicServAddConfig and SetConfigs in QuicCryptoServerConfig.
  quic::QuicServerConfigProtobuf GenerateConfigProtobuf(
    quic::QuicRandom* rand,
    const quic::QuicClock* clock,
    const quic::QuicCryptoServerConfig::ConfigOptions& options);

  tQuicServerSession* GetSession(const tQuicRequestID& id);
  tQuicServerStream*  GetStream(const tQuicRequestID& id);


 private:
  std::unique_ptr<tQuicDispatcher> dispatcher_;
  tQuicStackContext                stack_ctx_;
  tQuicRequestCallback             callback_;
  tQuicClock                       clock_;

  tQuicServerIdentifyManager       qsi_mgr_;

  // config_ contains non-crypto parameters that are negotiated in the crypto
  // handshake.
  quic::QuicConfig config_;
  // crypto_config_ contains crypto parameters for the handshake.
  quic::QuicCryptoServerConfig crypto_config_;
  // crypto_config_options_ contains crypto parameters for the handshake.
  quic::QuicCryptoServerConfig::ConfigOptions crypto_config_options_;

  // Used to generate current supported versions.
  quic::QuicVersionManager version_manager_;

  // The timeout before the handshake succeeds.
  uint32_t max_streams_per_connection_;

  // Maximum idle time before the crypto handshake is completed.
  uint64_t initial_idle_timeout_in_sec_;
  // The default idle timeout.
  uint64_t default_idle_timeout_in_sec_;
  // The maximum idle timeout than can be negotiated.
  uint64_t max_idle_timeout_in_sec_;
  // Maximum time the session can be alive before crypto handshake is finished (should not be less than initial_idle_timeout_in_sec_).
  uint64_t max_time_before_crypto_handshake_in_sec_;

  // Connection ID length expected to be read on incoming IETF short headers.
  uint8_t expected_connection_id_length_;

  // Stack alarm events
  tQuicAlarmEventQueue*  quic_alarm_evq_;

};

}  // namespace nginx

#endif  /* _NGINX_T_QUIC_STACK_H_ */
