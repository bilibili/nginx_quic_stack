// Copyright (c) 2019 Bilibili Video Cloud Team. All rights reserved.
// Description: QUIC Stack APIs header file.

#ifndef _QUIC_STACK_API_H_
#define _QUIC_STACK_API_H_

#if defined(WIN32)
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__((visibility("default")))
#endif

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define   QUIC_STACK_OK              0
#define   QUIC_STACK_MEM            -1
#define   QUIC_STACK_SERVER         -2
#define   QUIC_STACK_PARAMETER      -3
#define   QUIC_STACK_STREAM_CLOSED  -4

#ifdef __cplusplus
extern "C" {
#endif

typedef void* tQuicStackHandler;
typedef void* tQuicSessionHandler;
typedef void* tQuicStreamHandler;
typedef void* tQuicStackContext;

typedef struct {
    char               connection_data[18];
    uint8_t            connection_len;
    uint32_t           stream_id;
    struct sockaddr    *self_sockaddr;
    socklen_t          self_socklen;
    struct sockaddr    *peer_sockaddr;
    socklen_t          peer_socklen;
} tQuicRequestID;

struct tQuicServerCtx {
    uint32_t    module_idx;
    int    (*on_request_header_impl)(
                const tQuicRequestID *id,
                const char *data,
                size_t len,
                void **ctx,
                tQuicServerCtx *server_ctx);
   int     (*on_request_body_impl)(
                const tQuicRequestID *id,
                void *ctx,
                tQuicServerCtx *server_ctx);
   int    (*on_request_close_impl)(
                const tQuicRequestID *id,
                void *ctx,
                tQuicServerCtx *server_ctx);
   void    *server_conf;
};

typedef struct {
    /* OnRequestHeader
       Called when quic stack received request headers and parsed them.
       id: unique id for quic request
       data: header raw string data
       len: data length
       ctx: callback context
    */
    int                       (*OnRequestHeader)(
                                const tQuicRequestID *id,
                                const char *data,
                                size_t len,
                                void **ctx,
                                tQuicServerCtx *server_ctx);

    /* OnRequestBody
       Called when quic stack received request body.
       id: unique id for quic request
       ctx: callback context
    */
    int                       (*OnRequestBody)(
                                const tQuicRequestID *id,
                                void *ctx,
                                tQuicServerCtx *server_ctx);

    /* OnRequestClose
       Called when quic stack close request.
       id: unique id for quic request
       ctx: callback context
    */
    int                       (*OnRequestClose)(
                                const tQuicRequestID *id,
                                void *ctx,
                                tQuicServerCtx *server_ctx);

} tQuicRequestCallback;

typedef struct {
    int64_t                   (*ApproximateTimeNowInUsec)();
    int64_t                   (*TimeNowInUsec)();
} tQuicClockTimeGenerator;

typedef struct tQuicOnCanWriteCallback {
    void                     (*OnCanWriteCallback)(void* ctx);
    void                     *OnCanWriteContext;
} tQuicOnCanWriteCallback;

typedef struct tQuicStackCertificate {
    char                       *certificate;
    int                         certificate_len;
    char                       *certificate_key;
    int                         certificate_key_len;
    char                       *hostname;
    int                         hostname_len;
    tQuicServerCtx             *server_ctx; // used for SNI
} tQuicStackCertificate;

typedef struct tQuicStackConfig {
    int                         max_streams_per_connection; // 100 by default

    int64_t                     initial_idle_timeout_in_sec; // 10 by default
    int64_t                     default_idle_timeout_in_sec; // 60 by default
    int64_t                     max_idle_timeout_in_sec; // 60*10 by default
    int64_t                     max_time_before_crypto_handshake_in_sec; // 15 by default

    tQuicStackContext           stack_ctx;

    tQuicRequestCallback        req_cb;

    tQuicClockTimeGenerator     clock_gen;

    int                        *active_connection_nums;
    size_t                     *established_connection_nums;
    size_t                     *zero_rtt_connection_nums;
} tQuicStackConfig;


EXPORT_API
tQuicStackHandler quic_stack_create(const tQuicStackConfig* opt_ptr);

EXPORT_API
void quic_stack_add_certificate(tQuicStackHandler handler, const tQuicStackCertificate* cert_ptr);

EXPORT_API
void quic_stack_init_writer(tQuicStackHandler handler, int sockfd, tQuicOnCanWriteCallback write_blocked_cb);

EXPORT_API
void quic_stack_process_chlos(tQuicStackHandler handler, size_t max_connection_to_create);

EXPORT_API
void quic_stack_process_packet(
    tQuicStackHandler handler,
    const struct sockaddr* self_saddr, socklen_t self_len,
    const struct sockaddr* peer_saddr, socklen_t peer_len,
    char *buffer, size_t len);

EXPORT_API
void quic_stack_on_can_write(tQuicStackHandler handler);

EXPORT_API
int quic_stack_has_chlos_buffered(tQuicStackHandler handler);

EXPORT_API
int quic_stack_has_pending_writes(tQuicStackHandler handler);

EXPORT_API
int quic_stack_read_request_body(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    char* data,
    size_t len);

EXPORT_API
int quic_stack_write_response_header(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    const char* data,
    size_t len,
    const char* trailers,
    size_t trailers_len,
    int last);

EXPORT_API
int quic_stack_write_response_body(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    const char* data,
    size_t len,
    const char* trailers,
    size_t trailers_len,
    size_t limit,
    int last);

EXPORT_API
void quic_stack_close_stream(
    tQuicStackHandler handler,
    const tQuicRequestID* id);

EXPORT_API
int64_t quic_stack_next_alarm_time(tQuicStackHandler handler);

EXPORT_API
void quic_stack_on_alarm_timeout(
    tQuicStackHandler handler,
    int64_t deadline_ms);

EXPORT_API
int quic_stack_supported_versions(
    tQuicStackHandler handler,
    char* buf,
    size_t len,
    uint64_t port,
    uint64_t max_age);

EXPORT_API
void quic_stack_add_on_can_write_callback_once(
    tQuicStackHandler handler,
    const tQuicRequestID* id,
    tQuicOnCanWriteCallback cb);


#ifdef __cplusplus
}
#endif


#endif /* _QUIC_STACK_API_H_ */
