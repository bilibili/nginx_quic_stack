#include "base/files/file_path.h"
#include "quic/core/quic_default_packet_writer.h"
#include "quic/core/crypto/curve25519_key_exchange.h"
#include "quic/core/crypto/p256_key_exchange.h"
#include "src/tQuicProofSource.hh"
#include "src/tQuicConnectionHelper.hh"
#include "src/tQuicCryptoServerStream.hh"
#include "src/tQuicServerSession.hh"
#include "quic/core/batch_writer/quic_batch_writer_buffer.h"
#include "quic/core/batch_writer/quic_sendmmsg_batch_writer.h"
#include "src/tQuicStack.hh"
#include "openssl/sha.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"

using namespace quic;

namespace nginx {

namespace {
  const char kSourceAddressTokenSecret[] = "bilibili";
  const uint64_t scfgExpiryTime  = 4733481600*1000000; //unix timestamp in Microseconds 
}


tQuicStack::tQuicStack(
  tQuicStackContext stack_ctx,
  tQuicRequestCallback cb,
  tQuicClockTimeGenerator clock_gen,
  uint32_t max_streams_per_connection,
  uint64_t initial_idle_timeout_in_sec,
  uint64_t default_idle_timeout_in_sec,
  uint64_t max_idle_timeout_in_sec,
  uint64_t max_time_before_crypto_handshake_in_sec,
  uint8_t expected_connection_id_length)
  : stack_ctx_(stack_ctx),
    callback_(cb),
    clock_(clock_gen),
    config_(QuicConfig()),
    crypto_config_(kSourceAddressTokenSecret,
                   QuicRandom::GetInstance(),
                   std::make_unique<nginx::tQuicProofSource>(&clock_),
                   KeyExchangeSource::Default()),
    crypto_config_options_(QuicCryptoServerConfig::ConfigOptions()),
    version_manager_(AllSupportedVersions()),
    max_streams_per_connection_(max_streams_per_connection),
    initial_idle_timeout_in_sec_(initial_idle_timeout_in_sec),
    default_idle_timeout_in_sec_(default_idle_timeout_in_sec),
    max_idle_timeout_in_sec_(max_idle_timeout_in_sec),
    max_time_before_crypto_handshake_in_sec_(max_time_before_crypto_handshake_in_sec),
    expected_connection_id_length_(expected_connection_id_length)
{
  Initialize();
}

tQuicStack::~tQuicStack() {}

void tQuicStack::AddCertificate(const tQuicServerIdentify& qsi) {
  nginx::tQuicProofSource* proof_source =
    static_cast<nginx::tQuicProofSource*>(crypto_config_.proof_source());

  if (proof_source == nullptr) {
    return;
  }

  proof_source->AddCertificateChainFromPath(
    base::FilePath(qsi.cert_path), base::FilePath(qsi.key_path));

  if (!qsi_mgr_.AddServerIdentify(qsi)) {
    std::cout << "[WARNING] AddServerIdentify failed." << std::endl;
    return;
  }
}

void tQuicStack::InitializeWithWriter(int fd, tQuicOnCanWriteCallback write_blocked_cb)
{
  if (dispatcher_ == nullptr) {
    return;
  }
  dispatcher_->InitializeWithWriter(
    new quic::QuicSendmmsgBatchWriter(
            std::unique_ptr<quic::QuicBatchWriterBuffer>(new quic::QuicBatchWriterBuffer()),
            fd));
  dispatcher_->SetWriteBlockedCallback(write_blocked_cb);
}

void tQuicStack::ProcessBufferedChlos(size_t max_connections_to_create)
{
  if (dispatcher_ == nullptr) {
    return;
  }
  dispatcher_->ProcessBufferedChlos(max_connections_to_create);
}

void tQuicStack::ProcessPacket(
    const QuicSocketAddress& self_addr,
    const QuicSocketAddress& peer_addr,
    char* buffer, size_t length)
{
  if (dispatcher_ == nullptr || buffer == nullptr || length <= 0) {
    return;
  }

  QuicWallTime walltimestamp = clock_.WallNow();
  QuicTime timestamp = clock_.ConvertWallTimeToQuicTime(walltimestamp);
  QuicReceivedPacket packet(buffer, length, timestamp, false);
  dispatcher_->ProcessPacket(self_addr, peer_addr, packet);
}

void tQuicStack::OnCanWrite()
{
  if (dispatcher_ == nullptr) {
    return;
  }
  dispatcher_->OnCanWrite();
}

bool tQuicStack::HasChlosBuffered()
{
  if (dispatcher_ == nullptr) {
    return false;
  }
  return dispatcher_->HasChlosBuffered();
}

bool tQuicStack::HasPendingWrites()
{
  if (dispatcher_ == nullptr) {
    return false;
  }
  return dispatcher_->HasPendingWrites();
}

tQuicServerSession* tQuicStack::GetSession(const tQuicRequestID& id)
{
  QuicConnectionId cid(id.connection_data, id.connection_len);
  if (cid.IsEmpty() || dispatcher_ == nullptr) {
    return nullptr;
  }

  const auto& session_map = dispatcher_->GetSessionsSnapshot();
  auto it = session_map.begin();
  for (; it != session_map.end(); it++) {
    if((*it)->connection_id() == cid) {
      break;
    }
  }
  if (it == session_map.end()) {
    return nullptr;
  }

  return static_cast<tQuicServerSession*>((*it).get());
}

tQuicServerStream* tQuicStack::GetStream(const tQuicRequestID& id)
{
  tQuicServerSession* session = GetSession(id);
  if (session == nullptr) {
    return nullptr;
  }

  return session->GetStream(id.stream_id);
}

int tQuicStack::ReadRequestBody(
  const tQuicRequestID& id,
  char* data,
  size_t len)
{
  tQuicServerStream* stream = GetStream(id);
  if (stream == nullptr) {
    return QUIC_STACK_SERVER;
  }

  return stream->ReadRequestBody(data, len);
}

bool tQuicStack::WriteResponseHeader(
  const tQuicRequestID& id,
  const char* data,
  size_t len,
  const char* trailers,
  size_t trailers_len,
  int last)
{
  tQuicServerStream* stream = GetStream(id);
  if (stream == nullptr) {
    return false;
  }

  return stream->WriteResponseHeader(data, len, trailers, trailers_len, last);
}

int tQuicStack::WriteResponseBody(
  const tQuicRequestID& id,
  const char* data,
  size_t len,
  const char* trailers,
  size_t trailers_len,
  size_t limit,
  bool fin)
{
  tQuicServerStream* stream = GetStream(id);
  if (stream == nullptr) {
    return QUIC_STACK_SERVER;
  }

  return stream->WriteResponseBody(data, len, trailers, trailers_len, limit, fin);
}

void tQuicStack::CloseStream(const tQuicRequestID& id)
{
  tQuicServerSession* session = GetSession(id);
  if (session == nullptr) {
    return;
  }

  session->OnStreamClosed(id.stream_id);
}

void tQuicStack::AddOnCanWriteCallback(
    const tQuicRequestID& id,
    tQuicOnCanWriteCallback cb)
{
    tQuicServerStream* stream = GetStream(id);
    if (stream == nullptr) {
      return;
    }

    stream->AddOnCanWriteCallback(cb);
}

int64_t tQuicStack::NextAlarmTime()
{
  if (quic_alarm_evq_ == nullptr) {
    return 0;
  }

  return static_cast<int64_t>(quic_alarm_evq_->NextAlarmTimeInUs() / 1000);
}

void tQuicStack::OnAlarmTimeout(int64_t deadline_ms)
{
  if (quic_alarm_evq_ == nullptr) {
    return;
  }

  quic_alarm_evq_->CallTimeoutAlarms(deadline_ms * 1000);
}

void tQuicStack::Initialize()
{
  const uint32_t kInitialSessionFlowControlWindow = 16 * 1024 * 1024;  // 16 MB
  const uint32_t kInitialStreamFlowControlWindow = 1024 * 1024;         // 1024 KB

  if (config_.GetInitialStreamFlowControlWindowToSend() ==
      kDefaultFlowControlSendWindow) {
    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindow);
  }
  if (config_.GetInitialSessionFlowControlWindowToSend() ==
      kDefaultFlowControlSendWindow) {
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindow);
  }

  if (config_.GetMaxBidirectionalStreamsToSend() ==
      kDefaultMaxStreamsPerConnection) {
    config_.SetMaxBidirectionalStreamsToSend(
        max_streams_per_connection_);
  }
  if (config_.GetMaxUnidirectionalStreamsToSend() ==
      kDefaultMaxStreamsPerConnection) {
    config_.SetMaxUnidirectionalStreamsToSend(
        max_streams_per_connection_);
  }

  if (config_.max_idle_time_before_crypto_handshake() ==
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs)) {
    config_.set_max_idle_time_before_crypto_handshake(
        QuicTime::Delta::FromSeconds(initial_idle_timeout_in_sec_));
  }

  config_.SetIdleNetworkTimeout(QuicTime::Delta::FromSeconds(max_idle_timeout_in_sec_));

  if (config_.max_time_before_crypto_handshake() ==
      QuicTime::Delta::FromSeconds(kMaxTimeForCryptoHandshakeSecs)) {
    config_.set_max_time_before_crypto_handshake(
        QuicTime::Delta::FromSeconds(max_time_before_crypto_handshake_in_sec_));
  }

  { // init CryptoHandshakeMessage firstly
    InitializeConfigOptions();
    QuicServerConfigProtobuf config_pb = GenerateConfigProtobuf(QuicRandom::GetInstance(),
		    &clock_, crypto_config_options_);
    std::unique_ptr<CryptoHandshakeMessage> scfg(
		    crypto_config_.AddConfig(config_pb, clock_.WallNow()));
  }

  std::unique_ptr<tQuicAlarmFactory> alarm_factory(new tQuicAlarmFactory);
  quic_alarm_evq_ = alarm_factory->quic_alarm_event_queue();
  QUIC_DLOG(INFO) << "tQuicDispatcher Initialize ";
  dispatcher_.reset(
    new tQuicDispatcher(
      &config_, &crypto_config_, &version_manager_,
      std::unique_ptr<tQuicConnectionHelper>(
        new tQuicConnectionHelper(&clock_, QuicAllocator::BUFFER_POOL)),
      std::unique_ptr<QuicCryptoServerStream::Helper>(
        new tQuicCryptoServerStream),
      std::move(alarm_factory),
      expected_connection_id_length_,
      stack_ctx_,
      callback_,
      &qsi_mgr_));

}

void tQuicStack::InitializeConfigOptions() {
    char host_name[64];
    if(gethostname(host_name, sizeof(host_name))) {
        std::cout << "[WARNING] get host_name failed." << std::endl;
        return;
    }
    std::string host_name_str = host_name;
    std::string host_name_prefix = host_name_str.substr(0, host_name_str.find_last_of('-') + 1);
    if (host_name_prefix.empty()) {
        std::cout << "[WARNING] get host_name_prefix failed." << std::endl;
        return;
    }
    uint8_t scid_bytes[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(host_name_prefix.data()),
           host_name_prefix.size(), scid_bytes);

    crypto_config_options_.id = std::string(reinterpret_cast<const char*>(scid_bytes), 16);
    crypto_config_options_.orbit = std::string(reinterpret_cast<const char*>(scid_bytes), 8);
    crypto_config_options_.expiry_time = QuicWallTime::FromUNIXMicroseconds(scfgExpiryTime);
} 

QuicServerConfigProtobuf tQuicStack::GenerateConfigProtobuf(
    QuicRandom* rand,
    const QuicClock* clock,
    const QuicCryptoServerConfig::ConfigOptions& options) {
  CryptoHandshakeMessage msg;
  std::string curve25519_private_key; 
  if (options.id.empty()) {
      curve25519_private_key =
          Curve25519KeyExchange::NewPrivateKey(rand);
  } else {
      uint8_t private_key_bytes[32];
      SHA256(reinterpret_cast<const uint8_t*>(options.id.data()),
           options.id.size(), private_key_bytes);
      curve25519_private_key = 
          std::string(reinterpret_cast<const char*>(private_key_bytes),
                      sizeof(private_key_bytes));
  }

  std::unique_ptr<Curve25519KeyExchange> curve25519 =
      Curve25519KeyExchange::New(curve25519_private_key);
  quiche::QuicheStringPiece curve25519_public_value =
      curve25519->public_value();

  std::string encoded_public_values;
  // First three bytes encode the length of the public value.
  QUICHE_DCHECK_LT(curve25519_public_value.size(), (1U << 24));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size()));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size() >> 8));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size() >> 16));
  encoded_public_values.append(curve25519_public_value.data(),
                               curve25519_public_value.size());

  std::string p256_private_key;
  if (options.p256) {
    p256_private_key = P256KeyExchange::NewPrivateKey();
    std::unique_ptr<P256KeyExchange> p256(
        P256KeyExchange::New(p256_private_key));
    quiche::QuicheStringPiece p256_public_value = p256->public_value();

    QUICHE_DCHECK_LT(p256_public_value.size(), (1U << 24));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size()));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size() >> 8));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size() >> 16));
    encoded_public_values.append(p256_public_value.data(),
                                 p256_public_value.size());
  }

  msg.set_tag(kSCFG);
  if (options.p256) {
    msg.SetVector(kKEXS, QuicTagVector{kC255, kP256});
  } else {
    msg.SetVector(kKEXS, QuicTagVector{kC255});
  }
  msg.SetVector(kAEAD, QuicTagVector{kAESG, kCC20});
  msg.SetStringPiece(kPUBS, encoded_public_values);

  if (options.expiry_time.IsZero()) {
    const QuicWallTime now = clock->WallNow();
    const QuicWallTime expiry = now.Add(QuicTime::Delta::FromSeconds(
        60 * 60 * 24 * 180 /* 180 days, ~six months */));
    const uint64_t expiry_seconds = expiry.ToUNIXSeconds();
    msg.SetValue(kEXPY, expiry_seconds);
  } else {
    msg.SetValue(kEXPY, options.expiry_time.ToUNIXSeconds());
  }

  char orbit_bytes[kOrbitSize];
  if (options.orbit.size() == sizeof(orbit_bytes)) {
    memcpy(orbit_bytes, options.orbit.data(), sizeof(orbit_bytes));
  } else {
    QUICHE_DCHECK(options.orbit.empty());
    rand->RandBytes(orbit_bytes, sizeof(orbit_bytes));
  }
  msg.SetStringPiece(
      kORBT, quiche::QuicheStringPiece(orbit_bytes, sizeof(orbit_bytes)));

  if (options.channel_id_enabled) {
    msg.SetVector(kPDMD, QuicTagVector{kCHID});
  }

  if (options.id.empty()) {
    // We need to ensure that the SCID changes whenever the server config does
    // thus we make it a hash of the rest of the server config.
    std::unique_ptr<QuicData> serialized =
        CryptoFramer::ConstructHandshakeMessage(msg);

    uint8_t scid_bytes[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(serialized->data()),
           serialized->length(), scid_bytes);
    // The SCID is a truncated SHA-256 digest.
    static_assert(16 <= SHA256_DIGEST_LENGTH, "SCID length too high.");
    msg.SetStringPiece(kSCID,
                       quiche::QuicheStringPiece(
                           reinterpret_cast<const char*>(scid_bytes), 16));
  } else {
    msg.SetStringPiece(kSCID, options.id);
  }
  // Don't put new tags below this point. The SCID generation should hash over
  // everything but itself and so extra tags should be added prior to the
  // preceding if block.

  std::unique_ptr<QuicData> serialized =
      CryptoFramer::ConstructHandshakeMessage(msg);

  QuicServerConfigProtobuf config;
  config.set_config(std::string(serialized->AsStringPiece()));
  QuicServerConfigProtobuf::PrivateKey* curve25519_key = config.add_key();
  curve25519_key->set_tag(kC255);
  curve25519_key->set_private_key(curve25519_private_key);

  if (options.p256) {
    QuicServerConfigProtobuf::PrivateKey* p256_key = config.add_key();
    p256_key->set_tag(kP256);
    p256_key->set_private_key(p256_private_key);
  }

  return config;
} 
}  // namespace nginx


////// Stack APIs
tQuicStackHandler quic_stack_create(const tQuicStackConfig* opt_ptr)
{
#if 0
  auto logger = spdlog::basic_logger_mt("nginx-quic-module", "/data/ngxquicmodule.log");
  quiche::GetLogger().swap(*logger);
  quiche::SetVerbosityLogThreshold(4);
#endif
  SetQuicReloadableFlag(quic_default_to_bbr, true);
  if (opt_ptr == nullptr) {
    return nullptr;
  }

  if (opt_ptr->clock_gen.ApproximateTimeNowInUsec == nullptr ||
      opt_ptr->clock_gen.TimeNowInUsec == nullptr) {
    return nullptr;
  }
  
  QUIC_DLOG(INFO) << "quic_stack_create";
  auto stack = std::make_unique<nginx::tQuicStack>(
    opt_ptr->stack_ctx,
    opt_ptr->req_cb,
    opt_ptr->clock_gen,
    opt_ptr->max_streams_per_connection,
    opt_ptr->initial_idle_timeout_in_sec,
    opt_ptr->default_idle_timeout_in_sec,
    opt_ptr->max_idle_timeout_in_sec,
    opt_ptr->max_time_before_crypto_handshake_in_sec,
    kQuicDefaultConnectionIdLength);
  if (stack == nullptr) {
    return nullptr;
  }

  return stack.release();
}

#define GET_THIS(ptr)   static_cast<nginx::tQuicStack*>(ptr)


void quic_stack_add_certificate(tQuicStackHandler handler, const tQuicStackCertificate* cert_ptr)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr || cert_ptr == nullptr) {
    return;
  }

  if (cert_ptr->certificate == nullptr || cert_ptr->certificate_len <= 0 ||
      cert_ptr->certificate_key == nullptr || cert_ptr->certificate_key_len <= 0 ||
      cert_ptr->hostname == nullptr || cert_ptr->hostname_len <= 0) {
    return;
  }

  nginx::tQuicServerIdentify qsi;
  qsi.name      = std::string(cert_ptr->hostname, cert_ptr->hostname_len);
  qsi.cert_path = std::string(cert_ptr->certificate, cert_ptr->certificate_len);
  qsi.key_path  = std::string(cert_ptr->certificate_key, cert_ptr->certificate_key_len);
  qsi.ctx = *cert_ptr->server_ctx;

  stack->AddCertificate(qsi);
}

void quic_stack_init_writer(tQuicStackHandler handler, int sockfd,
  tQuicOnCanWriteCallback write_blocked_cb)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return;
  }

  stack->InitializeWithWriter(sockfd, write_blocked_cb);
}

void quic_stack_process_chlos(
  tQuicStackHandler handler,
  size_t max_connection_to_create)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return;
  }

  stack->ProcessBufferedChlos(max_connection_to_create);
}

void quic_stack_process_packet(
  tQuicStackHandler handler,
  const sockaddr* self_saddr, socklen_t self_len,
  const sockaddr* peer_saddr, socklen_t peer_len,
  char *buffer, size_t len)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return;
  }
  QuicSocketAddress self_addr(self_saddr, self_len);
  QuicSocketAddress peer_addr(peer_saddr, peer_len);
  stack->ProcessPacket(self_addr, peer_addr, buffer, len);
}

void quic_stack_on_can_write(tQuicStackHandler handler)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return;
  }
  stack->OnCanWrite();
}

int quic_stack_has_chlos_buffered(tQuicStackHandler handler)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return 0;
  }
  return stack->HasChlosBuffered() ? 1 : 0;
}

int quic_stack_has_pending_writes(tQuicStackHandler handler)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return 0;
  }
  return stack->HasPendingWrites() ? 1 : 0;
}

int quic_stack_read_request_body(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    char* data,
    size_t len)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr || id == nullptr || data == nullptr || len <= 0) {
    return QUIC_STACK_PARAMETER;
  }

  return stack->ReadRequestBody(*id, data, len);
}

int quic_stack_write_response_header(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    const char* data,
    size_t len,
    const char* trailers,
    size_t trailers_len,
    int last)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr || id == nullptr || data == nullptr || len <= 0) {
    return QUIC_STACK_PARAMETER;
  }

  if (!stack->WriteResponseHeader(*id, data, len, trailers, trailers_len, last)) {
    return QUIC_STACK_SERVER;
  }
  return QUIC_STACK_OK;
}

int quic_stack_write_response_body(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    const char* data,
    size_t len,
    const char* trailers,
    size_t trailers_len,
    size_t limit,
    int last)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr || id == nullptr || data == nullptr || len < 0) {
    return QUIC_STACK_PARAMETER;
  }

  return stack->WriteResponseBody(*id, data, len, trailers, trailers_len, limit, last);

}

void quic_stack_close_stream(
    tQuicStackHandler handler,
    const tQuicRequestID* id)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr || id == nullptr) {
    return;
  }

  return stack->CloseStream(*id);
}

int64_t quic_stack_next_alarm_time(tQuicStackHandler handler)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return QUIC_STACK_PARAMETER;
  }

  return stack->NextAlarmTime();
}

void quic_stack_on_alarm_timeout(
  tQuicStackHandler handler,
  int64_t deadline_ms)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return;
  }

  stack->OnAlarmTimeout(deadline_ms);
}

int quic_stack_supported_versions(
    tQuicStackHandler handler,
    char* buf,
    size_t len)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr) {
    return QUIC_STACK_PARAMETER;
  }

  std::string qvl_str;
  quic::ParsedQuicVersionVector qvv = CurrentSupportedVersions();
  for (const auto& i : qvv) {
    if (i.handshake_protocol != quic::HandshakeProtocol::PROTOCOL_QUIC_CRYPTO) {
      continue;
    }
    if (!qvl_str.empty()) {
      qvl_str.append(",");
    }
    qvl_str.append(std::to_string(i.transport_version));
  }

  if (qvl_str.size() > len) {
    return QUIC_STACK_SERVER;
  }

  memcpy(buf, qvl_str.c_str(), qvl_str.size());
  return qvl_str.size();
}

void quic_stack_add_on_can_write_callback_once(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    tQuicOnCanWriteCallback cb)
{
  nginx::tQuicStack *stack = GET_THIS(handler);
  if (stack == nullptr || id == nullptr) {
    return;
  }

  return stack->AddOnCanWriteCallback(*id, cb);
}
