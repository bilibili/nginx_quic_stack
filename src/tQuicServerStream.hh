// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack server stream class.

#ifndef _NGINX_T_QUIC_SERVER_STREAM_H_
#define _NGINX_T_QUIC_SERVER_STREAM_H_

#include <set>
#include <string>
#include <memory>
#include "quic/core/quic_circular_deque.h"
#include "base/macros.h"
#include "quic/platform/api/quic_reference_counted.h"

#include "net/base/io_buffer.h"
#include "quic/core/http/quic_spdy_server_stream_base.h"
#include "quic/core/quic_packets.h"
#include "platform/quiche_platform_impl/quiche_text_utils_impl.h"
#include "spdy/core/spdy_framer.h"
#include "quic_stack_api.h"


namespace nginx {

  struct tQuicServerIdentify {
    std::string      name;
    std::string      cert_path;
    std::string      key_path;
    tQuicServerCtx   ctx;
    tQuicServerIdentify();
    tQuicServerIdentify(const tQuicServerIdentify& qsi);
  };

  class tQuicServerIdentifyManager {
   public:
    tQuicServerIdentifyManager();
    virtual ~tQuicServerIdentifyManager();

    tQuicServerIdentify* GetServerIdentifyByName(const std::string& name);
    bool AddServerIdentify(const tQuicServerIdentify& qsi);

   private:
    std::vector<tQuicServerIdentify> servers_;
   };

  // IOBuffer of pending data to write which has a queue of pending data. Each
  // pending data is stored in std::string.  data() is the data of first
  // std::string stored.
  class QueuedWriteIOBuffer : public net::IOBuffer {
   public:
    static const int kDefaultMaxBufferSize = 32 * 1024 * 1024;  // 32 Mbytes.

    QueuedWriteIOBuffer();

    // Whether or not pending data exists.
    bool IsEmpty() const;

    // Appends new pending data and returns true if total size doesn't exceed
    // the limit, |total_size_limit_|.  It would change data() if new data is
    // the first pending data.
    bool Append(const std::string& data);

    // Consumes data and changes data() accordingly.  It cannot be more than
    // GetSizeToWrite().
    void DidConsume(int size);

    // Gets size of data to write this time. It is NOT total data size.
    int GetSizeToWrite() const;

    // Total size of all pending data.
    int total_size() const { return total_size_; }

    // Limit of how much data can be pending.
    int max_buffer_size() const { return max_buffer_size_; }
    void set_max_buffer_size(int max_buffer_size) {
      max_buffer_size_ = max_buffer_size;
    }

   private:
    ~QueuedWriteIOBuffer() override;

    // This needs to indirect since we need pointer stability for the payload
    // chunks, as they may be handed out via net::IOBuffer::data().
    quic::QuicCircularDeque<std::unique_ptr<std::string>> pending_data_;
    int total_size_;
    int max_buffer_size_;

    DISALLOW_COPY_AND_ASSIGN(QueuedWriteIOBuffer);
};

// All this does right now is aggregate data, and on fin, send an HTTP
// response.
class tQuicServerStream : public quic::QuicSpdyServerStreamBase {
 public:
  tQuicServerStream(quic::QuicStreamId id,
                    quic::QuicSpdySession* session,
                    quic::StreamType type,
                    tQuicStackContext stack_ctx,
                    tQuicRequestCallback cb,
                    tQuicServerIdentifyManager* qsi_ptr);
  tQuicServerStream(quic::PendingStream* pending,
                    quic::QuicSpdySession* session,
                    tQuicStackContext stack_ctx,
                    tQuicRequestCallback cb,
                    tQuicServerIdentifyManager* qsi_ptr);
  tQuicServerStream(const tQuicServerStream&) = delete;
  tQuicServerStream& operator=(const tQuicServerStream&) = delete;
  ~tQuicServerStream() override;

  // QuicSpdyStream
  void OnInitialHeadersComplete(bool fin,
                                size_t frame_len,
                                const quic::QuicHeaderList& header_list) override;
  void OnTrailingHeadersComplete(bool fin,
                                 size_t frame_len,
                                 const quic::QuicHeaderList& header_list) override;

  // QuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnBodyAvailable() override;

  void OnClose() override;

  // The response body of error responses.
  static const char* const kErrorResponseBody;
  static const char* const k403ResponseBody;

  int ReadRequestBody(char* data, size_t len);

  void FlushResponse();

  bool WriteResponseHeader(const char* data, size_t len, const char* trailers, size_t trailers_len, int fin);

  int WriteResponseBody(const char* data, size_t len, const char* trailers, size_t trailers_len, size_t limit, bool fin);

  void OnCanWriteNewData() override; // override from quic_stream
  void AddOnCanWriteCallback(tQuicOnCanWriteCallback cb);

  std::vector<std::string> SplitString(const std::string& str, const std::string& delim);

 protected:

  static const std::set<std::string> kHopHeaders;
  static const std::set<std::string> kTrailersHeaders;

  void SetRequestID();

  void CopySocketAddress(sockaddr** sa, socklen_t& len, sockaddr_storage& ss);

  void SendErrorResponse(int resp_code);
  void SendErrorResponseInternal(int resp_code, const char* resp_body);

  void OnRequestHeader();
  void OnRequestBody();

  void SetTrailers(const std::string& str, spdy::SpdyHeaderBlock& header);

  void SendHeadersAndBody(spdy::SpdyHeaderBlock response_headers,
                          quiche::QuicheStringPiece body);
  void SendHeadersAndBodyAndTrailers(spdy::SpdyHeaderBlock response_headers,
                                     quiche::QuicheStringPiece body,
                                     spdy::SpdyHeaderBlock response_trailers);

  spdy::SpdyHeaderBlock* request_headers() { return &request_headers_; }

  bool CopyAndValidateHeaders(const quic::QuicHeaderList& header_list,
                              int64_t&     content_length,
                              std::string& header_str);

  // The parsed headers received from the client.
  spdy::SpdyHeaderBlock request_headers_;
  int64_t               content_length_;
  bool                  header_sent_;

  std::string             request_host_;
  std::string             raw_header_str_;
  tQuicRequestID          request_id_;
  void                   *callback_ctx_; // not owned
  tQuicRequestCallback    callback_;

  tQuicServerIdentifyManager* qsi_mgr_;
  tQuicServerIdentify*    qsi_;
  bool                    is_new_ok_;
  tQuicOnCanWriteCallback can_write_cb_;

  spdy::SpdyHeaderBlock response_headers_;
  std::string           response_body_;
  spdy::SpdyHeaderBlock response_trailers_;

  sockaddr_storage self_generic_address_;
  sockaddr_storage peer_generic_address_;
 private:
  const quic::QuicReferenceCountedPointer<QueuedWriteIOBuffer>  body_;
};

}  // namespace nginx

#endif  // _NGINX_T_QUIC_SERVER_STREAM_H_
