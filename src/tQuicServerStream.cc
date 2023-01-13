#include <list>
#include <utility>

#include "quic/core/http/quic_spdy_stream.h"
#include "quic/core/http/spdy_utils.h"
#include "quic/core/quic_utils.h"
#include "quic/platform/api/quic_bug_tracker.h"
#include "quic/platform/api/quic_flags.h"
#include "quic/platform/api/quic_logging.h"
#include "quic/platform/api/quic_map_util.h"
#include "quic/core/http/quic_spdy_session.h"
#include "googleurl/base/strings/pattern.h"
#include "googleurl/base/strings/string_split.h"
#include "googleurl/base/strings/string_util.h"
#include "http_parser/http_request_headers.hh"
#include "http_parser/http_response_headers.hh"
#include "src/tQuicServerStream.hh"

using namespace bvc;
using namespace quic;
using spdy::SpdyHeaderBlock;

namespace nginx {

tQuicServerIdentify::tQuicServerIdentify() {}
tQuicServerIdentify::tQuicServerIdentify(const tQuicServerIdentify& qsi) {
   name = qsi.name;
   cert_path = qsi.cert_path;
   key_path = qsi.key_path;
   ctx = qsi.ctx;
}
tQuicServerIdentifyManager::tQuicServerIdentifyManager() {}
tQuicServerIdentifyManager::~tQuicServerIdentifyManager() {}

tQuicServerIdentify* tQuicServerIdentifyManager::GetServerIdentifyByName(
   const std::string& name)
{
  for (auto& i : servers_) {
    if (gurl_base::MatchPattern(name, i.name)) {
      return &i;
    }
  }

  return nullptr;
}

bool tQuicServerIdentifyManager::AddServerIdentify(const tQuicServerIdentify& qsi)
{
  tQuicServerIdentify* p = GetServerIdentifyByName(qsi.name);
  if (p) {
    return false;
  }
  servers_.push_back(qsi);
  return true;
}


const std::set<std::string> tQuicServerStream::kHopHeaders = {
    "alt-svc",
    "connection",
    "proxy-connection",  // non-standard but still sent by libcurl and rejected
                         // by e.g. google
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te",       // canonicalized version of "TE"
    "trailer",  // not Trailers per URL above;
                // http://www.rfc-editor.org/errata_search.php?eid=4522
    "transfer-encoding", "upgrade",
    "vary",
};


QueuedWriteIOBuffer::QueuedWriteIOBuffer()
    : total_size_(0),
      max_buffer_size_(kDefaultMaxBufferSize) {
}

QueuedWriteIOBuffer::~QueuedWriteIOBuffer() {
  data_ = nullptr;  // pending_data_ owns data_.
}

bool QueuedWriteIOBuffer::IsEmpty() const {
  return pending_data_.empty();
}

bool QueuedWriteIOBuffer::Append(const std::string& data) {
  if (data.empty())
    return true;

  if (total_size_ + static_cast<int>(data.size()) > max_buffer_size_) {
    //LOG(ERROR) << "Too large write data is pending: size="
    //           << total_size_ + data.size()
    //           << ", max_buffer_size=" << max_buffer_size_;
    return false;
  }

  pending_data_.push_back(std::make_unique<std::string>(data));
  total_size_ += data.size();

  // If new data is the first pending data, updates data_.
  if (pending_data_.size() == 1)
    data_ = const_cast<char*>(pending_data_.front()->data());
  return true;
}

void QueuedWriteIOBuffer::DidConsume(int size) {
  QUICHE_DCHECK_GE(total_size_, size);
  QUICHE_DCHECK_GE(GetSizeToWrite(), size);
  if (size == 0)
    return;

  if (size < GetSizeToWrite()) {
    data_ += size;
  } else {  // size == GetSizeToWrite(). Updates data_ to next pending data.
    pending_data_.pop_front();
    data_ =
        IsEmpty() ? nullptr : const_cast<char*>(pending_data_.front()->data());
  }
  total_size_ -= size;
}

int QueuedWriteIOBuffer::GetSizeToWrite() const {
  if (IsEmpty()) {
    QUICHE_DCHECK_EQ(0, total_size_);
    return 0;
  }

  QUICHE_DCHECK_GE(data_, pending_data_.front()->data());
  int consumed = static_cast<int>(data_ - pending_data_.front()->data());
  QUICHE_DCHECK_GT(static_cast<int>(pending_data_.front()->size()), consumed);
  return pending_data_.front()->size() - consumed;
}

tQuicServerStream::tQuicServerStream(
    QuicStreamId id,
    QuicSpdySession* session,
    StreamType type,
    tQuicStackContext stack_ctx,
    tQuicRequestCallback cb,
    tQuicServerIdentifyManager* qsi_ptr)
    : QuicSpdyServerStreamBase(id, session, type),
      content_length_(-1),
      header_sent_(false),
      callback_ctx_(stack_ctx), // first time, callback ctx is stack context
      callback_(cb),
      qsi_mgr_(qsi_ptr),
      is_new_ok_(true),
      body_(new QueuedWriteIOBuffer()){
  can_write_cb_.OnCanWriteCallback = nullptr;
  can_write_cb_.OnCanWriteContext  = nullptr;
  SetRequestID();
}

tQuicServerStream::tQuicServerStream(
    PendingStream* pending,
    QuicSpdySession* session,
    tQuicStackContext stack_ctx,
    tQuicRequestCallback cb,
    tQuicServerIdentifyManager* qsi_ptr)
    : QuicSpdyServerStreamBase(pending, session),
      content_length_(-1),
      header_sent_(false),
      callback_ctx_(stack_ctx),
      callback_(cb),
      qsi_mgr_(qsi_ptr),
      is_new_ok_(true),
      body_(new QueuedWriteIOBuffer()){
  can_write_cb_.OnCanWriteCallback = nullptr;
  can_write_cb_.OnCanWriteContext  = nullptr;
  SetRequestID();
}

tQuicServerStream::~tQuicServerStream() {
}

void tQuicServerStream::OnRequestHeader()
{
  if (callback_.OnRequestHeader && !request_host_.empty()) {

    qsi_ = qsi_mgr_->GetServerIdentifyByName(request_host_);
    if (qsi_ == nullptr) {
      SendErrorResponseInternal(403, k403ResponseBody);
      is_new_ok_ = false;
      return;
    }
    int rc = callback_.OnRequestHeader(
                &request_id_,
                raw_header_str_.c_str(),
                raw_header_str_.length(),
                &callback_ctx_,
                &qsi_->ctx);
    if (rc != QUIC_STACK_OK) {
      SendErrorResponse(0);
      is_new_ok_ = false;
      return;
    }
  }

}

void tQuicServerStream::OnRequestBody()
{
  if (is_new_ok_ && qsi_ && callback_.OnRequestBody) {
    int rc = callback_.OnRequestBody(
                 &request_id_,
                 callback_ctx_,
                 &qsi_->ctx);
    if (rc < 0) {
      SendErrorResponse(0);
      is_new_ok_ = false;
    }
  }
}

void tQuicServerStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
  if (!CopyAndValidateHeaders(header_list, content_length_, raw_header_str_)) {
    SendErrorResponse(0);
  }

  if (fin) {
    OnRequestHeader();
    raw_header_str_.clear();
    header_sent_ = true;
  }

  ConsumeHeaderList();
}

void tQuicServerStream::OnTrailingHeadersComplete(
    bool /*fin*/,
    size_t /*frame_len*/,
    const QuicHeaderList& /*header_list*/) {
  QUIC_BUG(-1) << "Server does not support receiving Trailers.";
  SendErrorResponse(0);
}

void tQuicServerStream::OnBodyAvailable() {

  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }

    bool rc = body_->Append(std::string(static_cast<char*>(iov.iov_base), iov.iov_len));
    if (!rc) {
      SendErrorResponse(0);
      return;
    }

    if (content_length_ >= 0 &&
        static_cast<int64_t>(body_->total_size()) > content_length_) {
       SendErrorResponse(0);
       return;
     }

     MarkConsumed(iov.iov_len);
   }

   if (!sequencer()->IsClosed()) {
     sequencer()->SetUnblocked();
     return;
   }

   // If the sequencer is closed, then all the body, including the fin, has been
   // consumed.
   OnFinRead();
   if (write_side_closed() || fin_buffered()) {
     return;
   }

  if (content_length_ < 0) {
    content_length_ = body_->total_size();
    HttpRequestHeaders kContentLength;
    kContentLength.SetHeader("content-length", std::to_string(content_length_));
    raw_header_str_ = raw_header_str_.substr(0, raw_header_str_.length()-2);
    raw_header_str_ += kContentLength.ToString();
  }

  if (!header_sent_) {
    OnRequestHeader();
    header_sent_ = true;
  }
  OnRequestBody();
}

void tQuicServerStream::OnClose()
{
  if (is_new_ok_  && qsi_ && callback_.OnRequestClose) {
    callback_.OnRequestClose(&request_id_, callback_ctx_, &qsi_->ctx);
  }
  is_new_ok_ = false;
}

void tQuicServerStream::OnCanWriteNewData()
{
  tQuicOnCanWriteCallback once_cb = can_write_cb_;
  can_write_cb_.OnCanWriteCallback = nullptr;
  can_write_cb_.OnCanWriteContext  = nullptr;
  if (once_cb.OnCanWriteCallback) {
    once_cb.OnCanWriteCallback(once_cb.OnCanWriteContext);
  }
}

void tQuicServerStream::AddOnCanWriteCallback(tQuicOnCanWriteCallback cb)
{
  can_write_cb_ = cb;
}

int tQuicServerStream::ReadRequestBody(char* data, size_t len)
{
  size_t n;
  int read_bytes = 0;

  while(!body_->IsEmpty() && len > 0) {
    struct iovec iov;
    iov.iov_base = body_->data();
    iov.iov_len  = body_->GetSizeToWrite();
    n = (len <= iov.iov_len ? len : iov.iov_len);

    memcpy(data+read_bytes, iov.iov_base, n);

    body_->DidConsume(n);
    len -= n;
    read_bytes += n;
  }

  if (read_bytes > 0) {
    return read_bytes;
  }

  if (body_->IsEmpty()) {
    return QUIC_STACK_STREAM_CLOSED;
  }

  // TODO find a better way to notify nginx finialzie request.
  return QUIC_STACK_SERVER;
}

void tQuicServerStream::SetTrailers(
  const std::string& str,
  spdy::SpdyHeaderBlock& headers)
{
  if (str.empty()) {
    return;
  }

  std::vector<std::string> trailers_v = SplitString(str, "\n");

  for (const auto& trailers_e : trailers_v) {
    std::size_t pos = trailers_e.find(":");
    if (pos != std::string::npos) {
      std::string hk = gurl_base::ToLowerASCII(trailers_e.substr(0, pos));

      std::string hv;
      gurl_base::TrimString(trailers_e.substr(pos + 1), " ", &hv);
      if (!hk.empty() && !hv.empty()) {
        headers[hk] = hv;
      }
    }
  }
}

void tQuicServerStream::FlushResponse()
{
  response_headers_["content-length"] = std::to_string(response_body_.size());
  SendHeadersAndBodyAndTrailers(
    std::move(response_headers_),
    response_body_,
    SpdyHeaderBlock());
}

bool tQuicServerStream::WriteResponseHeader(
  const char* data, size_t len, const char* trailers, size_t trailers_len, int fin)
{
  gurl_base::StringPiece header_str(data, len);
  if (header_str.empty()) {
    return false;
  }

  std::shared_ptr<HttpResponseHeaders> resp_header = HttpResponseHeaders::TryToCreate(header_str);
  if (resp_header == nullptr || !resp_header->response_code()) {
    return false;
  }

  response_headers_[":status"] = std::to_string(resp_header->response_code());
  size_t itr = 0;
  std::string name, value;
  while(resp_header->EnumerateHeaderLines(&itr, &name, &value)) {
    const auto name_lower = gurl_base::ToLowerASCII(name);
    if (QuicContainsKey(kHopHeaders, name_lower)) {
      continue;
    }
    response_headers_.AppendValueOrAddHeader(name_lower, value);
  }

  SetTrailers(std::string(trailers, trailers_len), response_trailers_);

  if (fin) {
    FlushResponse();
  }

  return true;
}

int tQuicServerStream::WriteResponseBody(
  const char* data, size_t len, const char* trailers, size_t trailers_len, size_t limit, bool fin)
{
  size_t to_write_size = len;
  if (limit > 0) {
    size_t buffered_size = BufferedDataBytes();
    to_write_size = buffered_size >= limit ? 0 : limit - buffered_size;
    if (to_write_size > len) {
      to_write_size = len;
    }
  }

  gurl_base::StringPiece body_str(data, to_write_size);
  if (!body_str.empty()) {
    response_body_.append(body_str.data(), body_str.size());
  }

  SetTrailers(std::string(trailers, trailers_len), response_trailers_);

  if (fin) {
    FlushResponse();
  }

  return body_str.size();
}

void tQuicServerStream::SendErrorResponse(int resp_code) {
  SendErrorResponseInternal(resp_code, kErrorResponseBody);
}

void tQuicServerStream::SendErrorResponseInternal(int resp_code, const char* resp_body) {
  SpdyHeaderBlock headers;
  if (resp_code <= 0) {
    headers[":status"] = "500";
  } else {
    headers[":status"] = quiche::QuicheTextUtilsImpl::Uint64ToString(resp_code);
  }
  headers["content-length"] =
     quiche::QuicheTextUtilsImpl::Uint64ToString(strlen(resp_body));
  SendHeadersAndBody(std::move(headers), resp_body);
}

void tQuicServerStream::SendHeadersAndBody(
    SpdyHeaderBlock response_headers,
    quiche::QuicheStringPiece body) {
  SendHeadersAndBodyAndTrailers(std::move(response_headers), body,
                                SpdyHeaderBlock());
}

void tQuicServerStream::SendHeadersAndBodyAndTrailers(
    SpdyHeaderBlock response_headers,
    quiche::QuicheStringPiece body,
    SpdyHeaderBlock response_trailers) {
  // Send the headers, with a FIN if there's nothing else to send.
  bool send_fin = (body.empty() && response_trailers.empty());
  WriteHeaders(std::move(response_headers), send_fin, nullptr);
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the body, with a FIN if there's no trailers to send.
  send_fin = response_trailers.empty();
  if (!body.empty() || send_fin) {
    WriteOrBufferBody(body, send_fin);
  }

  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the trailers. A FIN is always sent with trailers.
  WriteTrailers(std::move(response_trailers), nullptr);
}

void tQuicServerStream::CopySocketAddress(
  sockaddr** sa, socklen_t& len, sockaddr_storage& ss)
{
  switch (ss.ss_family) {
    case AF_INET6:
      len = sizeof(sockaddr_in6);
      *sa = reinterpret_cast<sockaddr*>(&ss);
      break;
    case AF_INET:
      len = sizeof(sockaddr_in);
      *sa = reinterpret_cast<sockaddr*>(&ss);
      break;
    default:
      len = sizeof(sockaddr_in);
      (*sa)->sa_family = AF_UNSPEC;
      break;
  }
}

void tQuicServerStream::SetRequestID()
{
  QuicConnectionId cid = spdy_session()->connection_id();
  memcpy(request_id_.connection_data, cid.data(), cid.length());
  request_id_.connection_len = cid.length();
  request_id_.stream_id     = id();

  self_generic_address_ = spdy_session()->self_address().generic_address();
  peer_generic_address_ = spdy_session()->peer_address().Normalized().generic_address();

  // self address
  CopySocketAddress(
    &request_id_.self_sockaddr,
    request_id_.self_socklen,
    self_generic_address_);

  // peer address
  CopySocketAddress(
    &request_id_.peer_sockaddr,
    request_id_.peer_socklen,
    peer_generic_address_);
}

bool tQuicServerStream::CopyAndValidateHeaders(
  const QuicHeaderList& header_list,
  int64_t& content_length,
  std::string& header_str)
{
  header_str.clear();

  // first of all, fetch request line
  std::string method;
  std::string path;
  std::string cookies;
  HttpRequestHeaders headers;
  for (const auto& p : header_list) {
    std::string name = p.first;
    if (name.empty()) {
      //QUIC_DLOG(ERROR) << "Header name must not be empty.";
      return false;
    }

    if (std::find_if(name.begin(), name.end(), ::isupper) != name.end()) {
      //QUIC_DLOG(ERROR) << "Malformed header: Header name " << name
      //                 << " contains upper-case characters.";
      name = gurl_base::ToLowerASCII(name);
    }

    if (name == "content-length") {
      uint64_t val;
      if (!quiche::QuicheTextUtilsImpl::StringToUint64(p.second, &val)) {
        return false;
      }
      if (content_length < 0) {
        content_length = val;
      }
      continue;
    }

    if (name == "cookie" && !p.second.empty()) {
      cookies += p.second;
      cookies += ";";
      continue;
    }

    if (name[0] == ':') {
      if (name[1] == 'm') { // method
        method = p.second;
      } else if (name[1] == 'p') { // path
        path = p.second;
      } else if (name[1] == 'a') { // authority
        headers.SetHeader("Host", p.second);
        request_host_ = p.second;
      }
      continue;
    }

    headers.SetHeader(name, p.second);
  }

  if (!cookies.empty()) {
    headers.SetHeader("cookie", cookies);
  }

  if (content_length >= 0) {
    headers.SetHeader("content-length", std::to_string(content_length));
  }
  headers.SetHeader("transport-protocol", std::string("quic"));
  header_str = method + std::string(" ") +
               path   + std::string(" HTTP/1.1\r\n") +
               headers.ToString();

  return true;
}

const char* const tQuicServerStream::kErrorResponseBody = "bad";

const char* const tQuicServerStream::k403ResponseBody =
"<html>\r\n"
"<head><title>403 Forbidden</title></head>\r\n"
"<body>\r\n"
"<center><h1>403 Forbidden</h1></center>\r\n";

std::vector<std::string>
tQuicServerStream::SplitString(const std::string& str, const std::string& delim) {
  std::vector<std::string> output;
  std::string::size_type pos1, pos2;
  pos1 = 0;
  pos2 = str.find(delim);

  while(std::string::npos != pos2) {
    output.push_back(str.substr(pos1, pos2 - pos1));
    pos1 = pos2 + delim.size();
    pos2 = str.find(delim, pos1);
  }

  if (pos1 != str.length()) {
    output.push_back(str.substr(pos1));
  }

  return output;  
}

}  // namespace nginx
