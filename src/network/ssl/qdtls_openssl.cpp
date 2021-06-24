/****************************************************************************
**
** Copyright (C) 2018 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX
#include "private/qnativesocketengine_p.h"

#include "qsslpresharedkeyauthenticator_p.h"
#include "qsslsocket_openssl_symbols_p.h"
#include "qsslsocket_openssl_p.h"
#include "qsslcertificate_p.h"
#include "qdtls_openssl_p.h"
#include "qudpsocket.h"
#include "qssl_p.h"

#include "qmessageauthenticationcode.h"
#include "qcryptographichash.h"

#include "qdebug.h"

#include <cstring>
#include <cstddef>

QT_BEGIN_NAMESPACE

#define QT_DTLS_VERBOSE 0

#if QT_DTLS_VERBOSE

#define qDtlsWarning(arg) qWarning(arg)
#define qDtlsDebug(arg) qDebug(arg)

#else

#define qDtlsWarning(arg)
#define qDtlsDebug(arg)

#endif // QT_DTLS_VERBOSE

namespace dtlsutil
{

QByteArray cookie_for_peer(SSL *ssl)
{
    Q_ASSERT(ssl);

    // SSL_get_rbio does not increment the reference count
    BIO *readBIO = q_SSL_get_rbio(ssl);
    if (!readBIO) {
        qCWarning(lcSsl, "No BIO (dgram) found in SSL object");
        return {};
    }

    auto listener = static_cast<dtlsopenssl::DtlsState *>(q_BIO_get_app_data(readBIO));
    if (!listener) {
        qCWarning(lcSsl, "BIO_get_app_data returned invalid (nullptr) value");
        return {};
    }

    const QHostAddress peerAddress(listener->remoteAddress);
    const quint16 peerPort(listener->remotePort);
    QByteArray peerData;
    if (peerAddress.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR sin6_addr(peerAddress.toIPv6Address());
        peerData.resize(int(sizeof sin6_addr + sizeof peerPort));
        char *dst = peerData.data();
        std::memcpy(dst, &peerPort, sizeof peerPort);
        dst += sizeof peerPort;
        std::memcpy(dst, &sin6_addr, sizeof sin6_addr);
    } else if (peerAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 sin_addr(peerAddress.toIPv4Address());
        peerData.resize(int(sizeof sin_addr + sizeof peerPort));
        char *dst = peerData.data();
        std::memcpy(dst, &peerPort, sizeof peerPort);
        dst += sizeof peerPort;
        std::memcpy(dst, &sin_addr, sizeof sin_addr);
    } else {
        Q_UNREACHABLE();
    }

    return peerData;
}

struct FallbackCookieSecret
{
    FallbackCookieSecret()
    {
        key.resize(32);
        const int status = q_RAND_bytes(reinterpret_cast<unsigned char *>(key.data()),
                                        key.size());
        if (status <= 0)
            key.clear();
    }

    QByteArray key;

    Q_DISABLE_COPY(FallbackCookieSecret)
};

QByteArray fallbackSecret()
{
    static const FallbackCookieSecret generator;
    return generator.key;
}

int next_timeoutMs(SSL *tlsConnection)
{
    Q_ASSERT(tlsConnection);
    timeval timeLeft = {};
    q_DTLSv1_get_timeout(tlsConnection, &timeLeft);
    return timeLeft.tv_sec * 1000;
}


void delete_connection(SSL *ssl)
{
    // The 'deleter' for QSharedPointer<SSL>.
    if (ssl)
        q_SSL_free(ssl);
}

#if QT_CONFIG(opensslv11)

void delete_BIO_ADDR(BIO_ADDR *bio)
{
    // A deleter for QSharedPointer<BIO_ADDR>
    if (bio)
        q_BIO_ADDR_free(bio);
}

void delete_bio_method(BIO_METHOD *method)
{
    // The 'deleter' for QSharedPointer<BIO_METHOD>.
    if (method)
        q_BIO_meth_free(method);
}

#endif // openssl 1.1

// The 'deleter' for QScopedPointer<BIO>.
struct bio_deleter
{
    static void cleanup(BIO *bio)
    {
        if (bio)
            q_BIO_free(bio);
    }
};

// The path MTU discovery is non-trivial: it's a mix of getsockopt/setsockopt
// (IP_MTU/IP6_MTU/IP_MTU_DISCOVER) and fallback MTU values. It's not
// supported on all platforms, worse so - imposes specific requirements on
// underlying UDP socket etc. So for now, we either try a user-proposed MTU
// hint  or rely on our own fallback value. As a fallback mtu OpenSSL uses 576
// for IPv4 and 1280 for IPv6 (RFC 791, RFC 2460). To KIS we use 576. This
// rather small MTU value does not affect the size that can be read/written
// by QDtls, only a handshake (which is allowed to fragment).
enum class MtuGuess : long
{
    defaultMtu = 576
};

} // namespace dtlsutil

namespace dtlscallbacks
{

extern "C" int q_generate_cookie_callback(SSL *ssl, unsigned char *dst,
                                          unsigned *cookieLength)
{
    if (!ssl || !dst || !cookieLength) {
        qCWarning(lcSsl,
                  "Failed to generate cookie - invalid (nullptr) parameter(s)");
        return 0;
    }

    void *generic = q_SSL_get_ex_data(ssl, QSslSocketBackendPrivate::s_indexForSSLExtraData);
    if (!generic) {
        qCWarning(lcSsl, "SSL_get_ex_data returned nullptr, cannot generate cookie");
        return 0;
    }

    *cookieLength = 0;

    auto dtls = static_cast<dtlsopenssl::DtlsState *>(generic);
    if (!dtls->secret.size())
        return 0;

    const QByteArray peerData(dtlsutil::cookie_for_peer(ssl));
    if (!peerData.size())
        return 0;

    QMessageAuthenticationCode hmac(dtls->hashAlgorithm, dtls->secret);
    hmac.addData(peerData);
    const QByteArray cookie = hmac.result();
    Q_ASSERT(cookie.size() >= 0);
    // DTLS1_COOKIE_LENGTH is erroneously 256 bytes long, must be 255 - RFC 6347, 4.2.1.
    *cookieLength = qMin(DTLS1_COOKIE_LENGTH - 1, cookie.size());
    std::memcpy(dst, cookie.constData(), *cookieLength);

    return 1;
}

extern "C" int q_verify_cookie_callback(SSL *ssl, const unsigned char *cookie,
                                        unsigned cookieLength)
{
    if (!ssl || !cookie || !cookieLength) {
        qCWarning(lcSsl, "Could not verify cookie, invalid (nullptr or zero) parameters");
        return 0;
    }

    unsigned char newCookie[DTLS1_COOKIE_LENGTH] = {};
    unsigned newCookieLength = 0;
    if (q_generate_cookie_callback(ssl, newCookie, &newCookieLength) != 1)
        return 0;

    return newCookieLength == cookieLength
           && !std::memcmp(cookie, newCookie, cookieLength);
}

extern "C" int q_X509DtlsCallback(int ok, X509_STORE_CTX *ctx)
{
    if (!ok) {
        // Store the error and at which depth the error was detected.
        SSL *ssl = static_cast<SSL *>(q_X509_STORE_CTX_get_ex_data(ctx, q_SSL_get_ex_data_X509_STORE_CTX_idx()));
        if (!ssl) {
            qCWarning(lcSsl, "X509_STORE_CTX_get_ex_data returned nullptr, handshake failure");
            return 0;
        }

        void *generic = q_SSL_get_ex_data(ssl, QSslSocketBackendPrivate::s_indexForSSLExtraData);
        if (!generic) {
            qCWarning(lcSsl, "SSL_get_ex_data returned nullptr, handshake failure");
            return 0;
        }

        auto dtls = static_cast<dtlsopenssl::DtlsState *>(generic);
        dtls->x509Errors.append(QSslErrorEntry::fromStoreContext(ctx));
    }

    // Always return 1 (OK) to allow verification to continue. We handle the
    // errors gracefully after collecting all errors, after verification has
    // completed.
    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
extern "C" unsigned q_PSK_client_callback(SSL *ssl, const char *hint, char *identity,
                                          unsigned max_identity_len, unsigned char *psk,
                                          unsigned max_psk_len)
{
    auto *dtls = static_cast<dtlsopenssl::DtlsState *>(q_SSL_get_ex_data(ssl,
                            QSslSocketBackendPrivate::s_indexForSSLExtraData));
    if (!dtls)
        return 0;

    Q_ASSERT(dtls->dtlsPrivate);
    return dtls->dtlsPrivate->pskClientCallback(hint, identity, max_identity_len, psk, max_psk_len);
}

extern "C" unsigned q_PSK_server_callback(SSL *ssl, const char *identity, unsigned char *psk,
                                          unsigned max_psk_len)
{
    auto *dtls = static_cast<dtlsopenssl::DtlsState *>(q_SSL_get_ex_data(ssl,
                            QSslSocketBackendPrivate::s_indexForSSLExtraData));
    if (!dtls)
        return 0;

    Q_ASSERT(dtls->dtlsPrivate);
    return dtls->dtlsPrivate->pskServerCallback(identity, psk, max_psk_len);
}
#endif

} // namespace dtlscallbacks

namespace dtlsbio
{

extern "C" int q_dgram_read(BIO *bio, char *dst, int bytesToRead)
{
    if (!bio || !dst || bytesToRead <= 0) {
        qCWarning(lcSsl, "invalid input parameter(s)");
        return 0;
    }

    q_BIO_clear_retry_flags(bio);

    auto dtls = static_cast<dtlsopenssl::DtlsState *>(q_BIO_get_app_data(bio));
    // It's us who set data, if OpenSSL does too, the logic here is wrong
    // then and we have to use BIO_set_app_data then!
    Q_ASSERT(dtls);
    int bytesRead = 0;
    if (dtls->dgram.size()) {
        bytesRead = qMin(dtls->dgram.size(), bytesToRead);
        std::memcpy(dst, dtls->dgram.constData(), bytesRead);

        if (!dtls->peeking)
            dtls->dgram = dtls->dgram.mid(bytesRead);
    } else {
        bytesRead = -1;
    }

    if (bytesRead <= 0)
        q_BIO_set_retry_read(bio);

    return bytesRead;
}

extern "C" int q_dgram_write(BIO *bio, const char *src, int bytesToWrite)
{
    if (!bio || !src || bytesToWrite <= 0) {
        qCWarning(lcSsl, "invalid input parameter(s)");
        return 0;
    }

    q_BIO_clear_retry_flags(bio);

    auto dtls = static_cast<dtlsopenssl::DtlsState *>(q_BIO_get_app_data(bio));
    Q_ASSERT(dtls);
    if (dtls->writeSuppressed) {
        // See the comment in QDtls::startHandshake.
        return bytesToWrite;
    }

    QUdpSocket *udpSocket = dtls->udpSocket;
    Q_ASSERT(udpSocket);

    const QByteArray dgram(QByteArray::fromRawData(src, bytesToWrite));
    qint64 bytesWritten = -1;
    if (udpSocket->state() == QAbstractSocket::ConnectedState) {
        bytesWritten = udpSocket->write(dgram);
    } else {
        bytesWritten = udpSocket->writeDatagram(dgram, dtls->remoteAddress,
                                                dtls->remotePort);
    }

    if (bytesWritten <= 0)
        q_BIO_set_retry_write(bio);

    Q_ASSERT(bytesWritten <= std::numeric_limits<int>::max());
    return int(bytesWritten);
}

extern "C" int q_dgram_puts(BIO *bio, const char *src)
{
    if (!bio || !src) {
        qCWarning(lcSsl, "invalid input parameter(s)");
        return 0;
    }

    return q_dgram_write(bio, src, int(std::strlen(src)));
}

extern "C" long q_dgram_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    // This is our custom BIO_ctrl. bio.h defines a lot of BIO_CTRL_*
    // and BIO_* constants and BIO_somename macros that expands to BIO_ctrl
    // call with one of those constants as argument. What exactly BIO_ctrl
    // does - depends on the 'cmd' and the type of BIO (so BIO_ctrl does
    // not even have a single well-defined value meaning success or failure).
    // We handle only the most generic commands - the ones documented for
    // BIO_ctrl - and also DGRAM specific ones. And even for them - in most
    // cases we do nothing but report a success or some non-error value.
    // Documents also state: "Source/sink BIOs return an 0 if they do not
    // recognize the BIO_ctrl() operation." - these are covered by 'default'
    // label in the switch-statement below. Debug messages in the switch mean:
    // 1) we got a command that is unexpected for dgram BIO, or:
    // 2) we do not call any function that would lead to OpenSSL using this
    //    command.

    if (!bio) {
        qDebug(lcSsl, "invalid 'bio' parameter (nullptr)");
        return -1;
    }

    auto dtls = static_cast<dtlsopenssl::DtlsState *>(q_BIO_get_app_data(bio));
    Q_ASSERT(dtls);

#if !QT_CONFIG(opensslv11)
    Q_UNUSED(num)
#endif

    switch (cmd) {
    // Let's start from the most generic ones, in the order in which they are
    // documented (as BIO_ctrl):
    case BIO_CTRL_RESET:
        // BIO_reset macro.
        // From documentation:
        // "BIO_reset() normally returns 1 for success and 0 or -1 for failure.
        // File BIOs are an exception, they return 0 for success and -1 for
        // failure."
        // We have nothing to reset and we are not file BIO.
        return 1;
    case BIO_C_FILE_SEEK:
    case BIO_C_FILE_TELL:
        qDtlsWarning("Unexpected cmd (BIO_C_FILE_SEEK/BIO_C_FILE_TELL)");
        // These are for BIO_seek, BIO_tell. We are not a file BIO.
        // Non-negative return value means success.
        return 0;
    case BIO_CTRL_FLUSH:
        // BIO_flush, nothing to do, we do not buffer any data.
        // 0 or -1 means error, 1 - success.
        return 1;
    case BIO_CTRL_EOF:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_EOF)");
        // BIO_eof, 1 means EOF read. Makes no sense for us.
        return 0;
    case BIO_CTRL_SET_CLOSE:
        // BIO_set_close with BIO_CLOSE/BIO_NOCLOSE flags. Documented as
        // always returning 1.
        // From the documentation:
        // "Typically BIO_CLOSE is used in a source/sink BIO to indicate that
        // the underlying I/O stream should be closed when the BIO is freed."
        //
        // QUdpSocket we work with is not BIO's business, ignoring.
        return 1;
    case BIO_CTRL_GET_CLOSE:
        // BIO_get_close. No, never, see the comment above.
        return 0;
    case BIO_CTRL_PENDING:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_PENDING)");
        // BIO_pending. Not used by DTLS/OpenSSL (we are not buffering).
        return 0;
    case BIO_CTRL_WPENDING:
        // No, we have nothing buffered.
        return 0;
    // The constants below are not documented as a part BIO_ctrl documentation,
    // but they are also not type-specific.
    case BIO_CTRL_DUP:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DUP)");
        // BIO_dup_state, not used by DTLS (and socket-related BIOs in general).
        // For some very specific BIO type this 'cmd' would copy some state
        // from 'bio' to (BIO*)'ptr'. 1 means success.
        return 0;
    case BIO_CTRL_SET_CALLBACK:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_SET_CALLBACK)");
        // BIO_set_info_callback. We never call this, OpenSSL does not do this
        // on its own (normally it's used if client code wants to have some
        // debug information, for example, dumping handshake state via
        // BIO_printf from SSL info_callback).
        return 0;
    case BIO_CTRL_GET_CALLBACK:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_GET_CALLBACK)");
        // BIO_get_info_callback. We never call this.
        if (ptr)
            *static_cast<bio_info_cb **>(ptr) = nullptr;
        return 0;
    case BIO_CTRL_SET:
    case BIO_CTRL_GET:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_SET/BIO_CTRL_GET)");
        // Somewhat 'documented' as setting/getting IO type. Not used anywhere
        // except BIO_buffer_get_num_lines (which contradics 'get IO type').
        // Ignoring.
        return 0;
    // DGRAM-specific operation, we have to return some reasonable value
    // (so far, I've encountered only peek mode switching, connect).
    case BIO_CTRL_DGRAM_CONNECT:
        // BIO_ctrl_dgram_connect. Not needed. Our 'dtls' already knows
        // the peer's address/port. Report success though.
        return 1;
    case BIO_CTRL_DGRAM_SET_CONNECTED:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_SET_CONNECTED)");
        // BIO_ctrl_dgram_set_connected. We never call it, OpenSSL does
        // not call it on its own (so normally it's done by client code).
        // Similar to BIO_CTRL_DGRAM_CONNECT, but it also informs the BIO
        // that its UDP socket is connected. We never need it though.
        return -1;
    case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_SET_RECV_TIMEOUT)");
        // Essentially setsockopt with SO_RCVTIMEO, not needed, our sockets
        // are non-blocking.
        return -1;
    case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_GET_RECV_TIMEOUT)");
        // getsockopt with SO_RCVTIMEO, not needed, our sockets are
        // non-blocking. ptr is timeval *.
        return -1;
    case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_SET_SEND_TIMEOUT)");
        // setsockopt, SO_SNDTIMEO, cannot happen.
        return -1;
    case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_GET_SEND_TIMEOUT)");
        // getsockopt, SO_SNDTIMEO, cannot happen.
        return -1;
    case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
        // BIO_dgram_recv_timedout. No, we are non-blocking.
        return 0;
    case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
        // BIO_dgram_send_timedout. No, we are non-blocking.
        return 0;
    case BIO_CTRL_DGRAM_MTU_DISCOVER:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_MTU_DISCOVER)");
        // setsockopt, IP_MTU_DISCOVER/IP6_MTU_DISCOVER, to be done
        // in QUdpSocket instead. OpenSSL never calls it, only client
        // code.
        return 1;
    case BIO_CTRL_DGRAM_QUERY_MTU:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_QUERY_MTU)");
        // To be done in QUdpSocket instead.
        return 1;
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
        qDtlsWarning("Unexpected command *BIO_CTRL_DGRAM_GET_FALLBACK_MTU)");
        // Without SSL_OP_NO_QUERY_MTU set on SSL, OpenSSL can request for
        // fallback MTU after several re-transmissions.
        // Should never happen in our case.
        return long(dtlsutil::MtuGuess::defaultMtu);
    case BIO_CTRL_DGRAM_GET_MTU:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_GET_MTU)");
        return -1;
    case BIO_CTRL_DGRAM_SET_MTU:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_SET_MTU)");
        // Should not happen (we don't call BIO_ctrl with this parameter)
        // and set MTU on SSL instead.
        return -1; // num is mtu and it's a return value meaning success.
    case BIO_CTRL_DGRAM_MTU_EXCEEDED:
        qDtlsWarning("Unexpected cmd (BIO_CTRL_DGRAM_MTU_EXCEEDED)");
        return 0;
    case BIO_CTRL_DGRAM_GET_PEER:
        qDtlsDebug("BIO_CTRL_DGRAM_GET_PEER");
        // BIO_dgram_get_peer. We do not return a real address (DTLS is not
        // using this address), but let's pretend a success.
        switch (dtls->remoteAddress.protocol()) {
        case QAbstractSocket::IPv6Protocol:
            return sizeof(sockaddr_in6);
        case QAbstractSocket::IPv4Protocol:
            return sizeof(sockaddr_in);
        default:
            return -1;
        }
    case BIO_CTRL_DGRAM_SET_PEER:
        // Similar to BIO_CTRL_DGRAM_CONNECTED.
        return 1;
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
        // DTLSTODO: I'm not sure yet, how it's used by OpenSSL.
        return 1;
    case BIO_CTRL_DGRAM_SET_DONT_FRAG:
        qDtlsDebug("BIO_CTRL_DGRAM_SET_DONT_FRAG");
        // To be done in QUdpSocket, it's about IP_DONTFRAG etc.
        return 1;
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        // AFAIK it's 28 for IPv4 and 48 for IPv6, but let's pretend it's 0
        // so that OpenSSL does not start suddenly fragmenting the first
        // client hello (which will result in DTLSv1_listen rejecting it).
        return 0;
#if QT_CONFIG(opensslv11)
    case BIO_CTRL_DGRAM_SET_PEEK_MODE:
        dtls->peeking = num;
        return 1;
#endif
    default:;
#if QT_DTLS_VERBOSE
        qWarning() << "Unexpected cmd (" << cmd << ")";
#endif
    }

    return 0;
}

extern "C" int q_dgram_create(BIO *bio)
{
#if QT_CONFIG(opensslv11)
    q_BIO_set_init(bio, 1);
#else
    bio->init = 1;
#endif
    // With a custom BIO you'd normally allocate some implementation-specific
    // data and append it to this new BIO: bio->ptr = ... (pre 1.0.2) or
    // BIO_set_data (1.1). We don't need it and thus q_dgram_destroy below
    // is a noop.
    return 1;
}

extern "C" int q_dgram_destroy(BIO *bio)
{
    Q_UNUSED(bio)
    return 1;
}

const char * const qdtlsMethodName = "qdtlsbio";

#if !QT_CONFIG(opensslv11)

/*
typedef struct bio_method_st {
    int type;
    const char *name;
    int (*bwrite) (BIO *, const char *, int);
    int (*bread) (BIO *, char *, int);
    int (*bputs) (BIO *, const char *);
    int (*bgets) (BIO *, char *, int);
    long (*ctrl) (BIO *, int, long, void *);
    int (*create) (BIO *);
    int (*destroy) (BIO *);
    long (*callback_ctrl) (BIO *, int, bio_info_cb *);
} BIO_METHOD;
*/

bio_method_st qdtlsCustomBioMethod =
{
    BIO_TYPE_DGRAM,
    qdtlsMethodName,
    q_dgram_write,
    q_dgram_read,
    q_dgram_puts,
    nullptr,
    q_dgram_ctrl,
    q_dgram_create,
    q_dgram_destroy,
    nullptr
};

#endif // openssl < 1.1

} // namespace dtlsbio

namespace dtlsopenssl
{

bool DtlsState::init(QDtlsBasePrivate *dtlsBase, QUdpSocket *socket,
                     const QHostAddress &remote, quint16 port,
                     const QByteArray &receivedMessage)
{
    Q_ASSERT(dtlsBase);
    Q_ASSERT(socket);

    if (!tlsContext.data() && !initTls(dtlsBase))
        return false;

    udpSocket = socket;

    setLinkMtu(dtlsBase);

    dgram = receivedMessage;
    remoteAddress = remote;
    remotePort = port;

    // SSL_get_rbio does not increment a reference count.
    BIO *bio = q_SSL_get_rbio(tlsConnection.data());
    Q_ASSERT(bio);
    q_BIO_set_app_data(bio, this);

    return true;
}

void DtlsState::reset()
{
    tlsConnection.reset();
    tlsContext.reset();
}

bool DtlsState::initTls(QDtlsBasePrivate *dtlsBase)
{
    if (tlsContext.data())
        return true;

    if (!QSslSocket::supportsSsl())
        return false;

    if (!initCtxAndConnection(dtlsBase))
        return false;

    if (!initBIO(dtlsBase)) {
        tlsConnection.reset();
        tlsContext.reset();
        return false;
    }

    return true;
}

static QString msgFunctionFailed(const char *function)
{
    //: %1: Some function
    return QDtls::tr("%1 failed").arg(QLatin1String(function));
}

bool DtlsState::initCtxAndConnection(QDtlsBasePrivate *dtlsBase)
{
    Q_ASSERT(dtlsBase);
    Q_ASSERT(QSslSocket::supportsSsl());

    if (dtlsBase->mode == QSslSocket::UnencryptedMode) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               QDtls::tr("Invalid SslMode, SslServerMode or SslClientMode expected"));
        return false;
    }

    if (!QDtlsBasePrivate::isDtlsProtocol(dtlsBase->dtlsConfiguration.protocol)) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               QDtls::tr("Invalid protocol version, DTLS protocol expected"));
        return false;
    }

    // Create a deep copy of our configuration
    auto configurationCopy = new QSslConfigurationPrivate(dtlsBase->dtlsConfiguration);
    configurationCopy->ref.store(0); // the QSslConfiguration constructor refs up

    // DTLSTODO: check we do not set something DTLS-incompatible there ...
    TlsContext newContext(QSslContext::sharedFromConfiguration(dtlsBase->mode,
                                                               configurationCopy,
                                                               dtlsBase->dtlsConfiguration.allowRootCertOnDemandLoading));

    if (newContext->error() != QSslError::NoError) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError, newContext->errorString());
        return false;
    }

    TlsConnection newConnection(newContext->createSsl(), dtlsutil::delete_connection);
    if (!newConnection.data()) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               msgFunctionFailed("SSL_new"));
        return false;
    }

    const int set = q_SSL_set_ex_data(newConnection.data(),
                                      QSslSocketBackendPrivate::s_indexForSSLExtraData,
                                      this);

    if (set != 1 && configurationCopy->peerVerifyMode != QSslSocket::VerifyNone) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               msgFunctionFailed("SSL_set_ex_data"));
        return false;
    }

    if (dtlsBase->mode == QSslSocket::SslServerMode) {
        if (dtlsBase->dtlsConfiguration.dtlsCookieEnabled)
            q_SSL_set_options(newConnection.data(), SSL_OP_COOKIE_EXCHANGE);
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
        q_SSL_set_psk_server_callback(newConnection.data(), dtlscallbacks::q_PSK_server_callback);
#endif
    } else {
#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_PSK)
        q_SSL_set_psk_client_callback(newConnection.data(), dtlscallbacks::q_PSK_client_callback);
#endif
    }

    tlsContext.swap(newContext);
    tlsConnection.swap(newConnection);

    return true;
}

bool DtlsState::initBIO(QDtlsBasePrivate *dtlsBase)
{
    Q_ASSERT(dtlsBase);
    Q_ASSERT(tlsContext.data() && tlsConnection.data());

#if QT_CONFIG(opensslv11)
    BioMethod customMethod(q_BIO_meth_new(BIO_TYPE_DGRAM, dtlsbio::qdtlsMethodName),
                           dtlsutil::delete_bio_method);
    if (!customMethod.data()) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               msgFunctionFailed("BIO_meth_new"));
        return false;
    }

    BIO_METHOD *biom = customMethod.data();
    q_BIO_meth_set_create(biom, dtlsbio::q_dgram_create);
    q_BIO_meth_set_destroy(biom, dtlsbio::q_dgram_destroy);
    q_BIO_meth_set_read(biom, dtlsbio::q_dgram_read);
    q_BIO_meth_set_write(biom, dtlsbio::q_dgram_write);
    q_BIO_meth_set_puts(biom, dtlsbio::q_dgram_puts);
    q_BIO_meth_set_ctrl(biom, dtlsbio::q_dgram_ctrl);
#else
    BIO_METHOD *biom = &dtlsbio::qdtlsCustomBioMethod;
#endif // openssl 1.1

    QScopedPointer<BIO, dtlsutil::bio_deleter> newBio(q_BIO_new(biom));
    BIO *bio = newBio.data();
    if (!bio) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               msgFunctionFailed("BIO_new"));
        return false;
    }

    q_SSL_set_bio(tlsConnection.data(), bio, bio);
    newBio.take();

#if QT_CONFIG(opensslv11)
    bioMethod.swap(customMethod);
#endif // openssl 1.1

    return true;
}

void DtlsState::setLinkMtu(QDtlsBasePrivate *dtlsBase)
{
    Q_ASSERT(dtlsBase);
    Q_ASSERT(udpSocket);
    Q_ASSERT(tlsConnection.data());

    long mtu = dtlsBase->mtuHint;
    if (!mtu) {
        // If the underlying QUdpSocket was connected, getsockopt with
        // IP_MTU/IP6_MTU can give us some hint:
        bool optionFound = false;
        if (udpSocket->state() == QAbstractSocket::ConnectedState) {
            const QVariant val(udpSocket->socketOption(QAbstractSocket::PathMtuSocketOption));
            if (val.isValid() && val.canConvert<int>())
                mtu = val.toInt(&optionFound);
        }

        if (!optionFound || mtu <= 0) {
            // OK, our own initial guess.
            mtu = long(dtlsutil::MtuGuess::defaultMtu);
        }
    }

    // For now, we disable this option.
    q_SSL_set_options(tlsConnection.data(), SSL_OP_NO_QUERY_MTU);

    q_DTLS_set_link_mtu(tlsConnection.data(), mtu);
}

} // namespace dtlsopenssl

QDtlsClientVerifierOpenSSL::QDtlsClientVerifierOpenSSL()
{
    secret = dtlsutil::fallbackSecret();
}

bool QDtlsClientVerifierOpenSSL::verifyClient(QUdpSocket *socket, const QByteArray &dgram,
                                              const QHostAddress &address, quint16 port)
{
    Q_ASSERT(socket);
    Q_ASSERT(dgram.size());
    Q_ASSERT(!address.isNull());
    Q_ASSERT(port);

    clearDtlsError();
    verifiedClientHello.clear();

    if (!dtls.init(this, socket, address, port, dgram))
        return false;

    dtls.secret = secret;
    dtls.hashAlgorithm = hashAlgorithm;

    Q_ASSERT(dtls.tlsConnection.data());
#if QT_CONFIG(opensslv11)
    QSharedPointer<BIO_ADDR> peer(q_BIO_ADDR_new(), dtlsutil::delete_BIO_ADDR);
    if (!peer.data()) {
        setDtlsError(QDtlsError::TlsInitializationError,
                     QDtlsClientVerifier::tr("BIO_ADDR_new failed, ignoring client hello"));
        return false;
    }

    const int ret = q_DTLSv1_listen(dtls.tlsConnection.data(), peer.data());
    if (ret < 0) {
        // Since 1.1 - it's a fatal error (not so in 1.0.2 for non-blocking socket)
        setDtlsError(QDtlsError::TlsFatalError, QSslSocketBackendPrivate::getErrorsFromOpenSsl());
        return false;
    }
#else
    qt_sockaddr peer;
    const int ret = q_DTLSv1_listen(dtls.tlsConnection.data(), &peer);
#endif
    if (ret > 0) {
        verifiedClientHello = dgram;
        return true;
    }

    return false;
}

void QDtlsPrivateOpenSSL::TimeoutHandler::start(int hintMs)
{
    Q_ASSERT(timerId == -1);
    timerId = startTimer(hintMs > 0 ? hintMs : timeoutMs, Qt::PreciseTimer);
}

void QDtlsPrivateOpenSSL::TimeoutHandler::doubleTimeout()
{
    if (timeoutMs * 2 < 60000)
        timeoutMs *= 2;
    else
        timeoutMs = 60000;
}

void QDtlsPrivateOpenSSL::TimeoutHandler::stop()
{
    if (timerId != -1) {
        killTimer(timerId);
        timerId = -1;
    }
}

void QDtlsPrivateOpenSSL::TimeoutHandler::timerEvent(QTimerEvent *event)
{
    Q_UNUSED(event)
    Q_ASSERT(timerId != -1);

    killTimer(timerId);
    timerId = -1;

    Q_ASSERT(dtlsConnection);
    dtlsConnection->reportTimeout();
}

QDtlsPrivateOpenSSL::QDtlsPrivateOpenSSL()
{
    secret = dtlsutil::fallbackSecret();
    dtls.dtlsPrivate = this;
}

bool QDtlsPrivateOpenSSL::startHandshake(QUdpSocket *socket, const QByteArray &dgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::HandshakeNotStarted);

    clearDtlsError();
    connectionEncrypted = false;

    if (!dtls.init(this, socket, remoteAddress, remotePort, dgram))
        return false;

    if (mode == QSslSocket::SslServerMode && dtlsConfiguration.dtlsCookieEnabled) {
        dtls.secret = secret;
        dtls.hashAlgorithm = hashAlgorithm;
        // Let's prepare the state machine so that message sequence 1 does not
        // surprise DTLS/OpenSSL (such a message would be disregarded as
        // 'stale or future' in SSL_accept otherwise):
        int result = 0;
#if QT_CONFIG(opensslv11)
        QSharedPointer<BIO_ADDR> peer(q_BIO_ADDR_new(), dtlsutil::delete_BIO_ADDR);
        if (!peer.data()) {
            setDtlsError(QDtlsError::TlsInitializationError,
                         QDtls::tr("BIO_ADD_new failed, cannot start handshake"));
            return false;
        }

        // If it's an invalid/unexpected ClientHello, we don't want to send
        // VerifyClientRequest - it's a job of QDtlsClientVerifier - so we
        // suppress any attempts to write into socket:
        dtls.writeSuppressed = true;
        result = q_DTLSv1_listen(dtls.tlsConnection.data(), peer.data());
        dtls.writeSuppressed = false;
#else
        qt_sockaddr peer;
        result = q_DTLSv1_listen(dtls.tlsConnection.data(), &peer);
#endif
        if (result <= 0) {
            setDtlsError(QDtlsError::TlsFatalError,
                         QDtls::tr("Cannot start the handshake, verified client hello expected"));
            dtls.reset();
            return false;
        }
    }

    handshakeState = QDtls::HandshakeInProgress;
    opensslErrors.clear();
    tlsErrors.clear();

    return continueHandshake(socket, dgram);
}

bool QDtlsPrivateOpenSSL::continueHandshake(QUdpSocket *socket, const QByteArray &dgram)
{
    Q_ASSERT(socket);

    Q_ASSERT(handshakeState == QDtls::HandshakeInProgress);

    clearDtlsError();

    if (timeoutHandler.data())
        timeoutHandler->stop();

    if (!dtls.init(this, socket, remoteAddress, remotePort, dgram))
        return false;

    dtls.x509Errors.clear();

    int result = 0;
    if (mode == QSslSocket::SslServerMode)
        result = q_SSL_accept(dtls.tlsConnection.data());
    else
        result = q_SSL_connect(dtls.tlsConnection.data());

    // DTLSTODO: Investigate/test if it makes sense - QSslSocket can emit
    // peerVerifyError at this point (and thus potentially client code
    // will close the underlying TCP connection immediately), but we are using
    // QUdpSocket, no connection to close, our verification callback returns 1
    // (verified OK) and this probably means OpenSSL has already sent a reply
    // to the server's hello/certificate.

    opensslErrors << dtls.x509Errors;

    if (result <= 0) {
        const auto code = q_SSL_get_error(dtls.tlsConnection.data(), result);
        switch (code) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            // DTLSTODO: to be tested - in principle, if it was the first call to
            // continueHandshake and server for some reason discards the client
            // hello message (even the verified one) - our 'this' will probably
            // forever stay in this strange InProgress state? (the client
            // will dully re-transmit the same hello and we discard it again?)
            // SSL_get_state can provide more information about state
            // machine and we can switch to NotStarted (since we have not
            // replied with our hello ...)
            if (!timeoutHandler.data()) {
                timeoutHandler.reset(new TimeoutHandler);
                timeoutHandler->dtlsConnection = this;
            } else {
                // Back to 1s.
                timeoutHandler->resetTimeout();
            }

            timeoutHandler->start();

            return true; // The handshake is not yet complete.
        default:
            storePeerCertificates();
            setDtlsError(QDtlsError::TlsFatalError,
                         QSslSocketBackendPrivate::msgErrorsDuringHandshake());
            dtls.reset();
            handshakeState = QDtls::HandshakeNotStarted;
            return false;
        }
    }

    storePeerCertificates();
    fetchNegotiatedParameters();

    const bool doVerifyPeer = dtlsConfiguration.peerVerifyMode == QSslSocket::VerifyPeer
                              || (dtlsConfiguration.peerVerifyMode == QSslSocket::AutoVerifyPeer
                                  && mode == QSslSocket::SslClientMode);

    if (!doVerifyPeer || verifyPeer() || tlsErrorsWereIgnored()) {
        connectionEncrypted = true;
        handshakeState = QDtls::HandshakeComplete;
        return true;
    }

    setDtlsError(QDtlsError::PeerVerificationError, QDtls::tr("Peer verification failed"));
    handshakeState = QDtls::PeerVerificationFailed;
    return false;
}


bool QDtlsPrivateOpenSSL::handleTimeout(QUdpSocket *socket)
{
    Q_ASSERT(socket);

    Q_ASSERT(timeoutHandler.data());
    Q_ASSERT(dtls.tlsConnection.data());

    clearDtlsError();

    dtls.udpSocket = socket;

    if (q_DTLSv1_handle_timeout(dtls.tlsConnection.data()) > 0) {
        timeoutHandler->doubleTimeout();
        timeoutHandler->start();
    } else {
        timeoutHandler->start(dtlsutil::next_timeoutMs(dtls.tlsConnection.data()));
    }

    return true;
}

bool QDtlsPrivateOpenSSL::resumeHandshake(QUdpSocket *socket)
{
    Q_UNUSED(socket);
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::PeerVerificationFailed);

    clearDtlsError();

    if (tlsErrorsWereIgnored()) {
        handshakeState = QDtls::HandshakeComplete;
        connectionEncrypted = true;
        tlsErrors.clear();
        tlsErrorsToIgnore.clear();
        return true;
    }

    return false;
}

void QDtlsPrivateOpenSSL::abortHandshake(QUdpSocket *socket)
{
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::PeerVerificationFailed
             || handshakeState == QDtls::HandshakeInProgress);

    clearDtlsError();

    if (handshakeState == QDtls::PeerVerificationFailed) {
        // Yes, while peer verification failed, we were actually encrypted.
        // Let's play it nice - inform our peer about connection shut down.
        sendShutdownAlert(socket);
    } else {
        resetDtls();
    }
}

void QDtlsPrivateOpenSSL::sendShutdownAlert(QUdpSocket *socket)
{
    Q_ASSERT(socket);

    clearDtlsError();

    if (connectionEncrypted && !connectionWasShutdown) {
        dtls.udpSocket = socket;
        Q_ASSERT(dtls.tlsConnection.data());
        q_SSL_shutdown(dtls.tlsConnection.data());
    }

    resetDtls();
}

qint64 QDtlsPrivateOpenSSL::writeDatagramEncrypted(QUdpSocket *socket,
                                                   const QByteArray &dgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(dtls.tlsConnection.data());
    Q_ASSERT(connectionEncrypted);

    clearDtlsError();

    dtls.udpSocket = socket;
    const int written = q_SSL_write(dtls.tlsConnection.data(),
                                    dgram.constData(), dgram.size());
    if (written > 0)
        return written;

    const unsigned long errorCode = q_ERR_get_error();
    if (!dgram.size() && errorCode == SSL_ERROR_NONE) {
        // With OpenSSL <= 1.1 this can happen. For example, DTLS client
        // tries to reconnect (while re-using the same address/port) -
        // DTLS server drops a message with unexpected epoch but says - no
        // error. We leave to client code to resolve such problems until
        // OpenSSL provides something better.
        return 0;
    }

    switch (errorCode) {
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        // We do not set any error/description ... a user can probably re-try
        // sending a datagram.
        break;
    case SSL_ERROR_ZERO_RETURN:
        connectionWasShutdown = true;
        setDtlsError(QDtlsError::TlsFatalError, QDtls::tr("The DTLS connection has been closed"));
        handshakeState = QDtls::HandshakeNotStarted;
        dtls.reset();
        break;
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    default:
        // DTLSTODO: we don't know yet what to do. Tests needed - probably,
        // some errors can be just ignored (it's UDP, not TCP after all).
        // Unlike QSslSocket we do not abort though.
        QString description(QSslSocketBackendPrivate::getErrorsFromOpenSsl());
        if (socket->error() != QAbstractSocket::UnknownSocketError && description.isEmpty()) {
            setDtlsError(QDtlsError::UnderlyingSocketError, socket->errorString());
        } else {
            setDtlsError(QDtlsError::TlsFatalError,
                         QDtls::tr("Error while writing: %1").arg(description));
        }
    }

    return -1;
}

QByteArray QDtlsPrivateOpenSSL::decryptDatagram(QUdpSocket *socket, const QByteArray &tlsdgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(tlsdgram.size());

    Q_ASSERT(dtls.tlsConnection.data());
    Q_ASSERT(connectionEncrypted);

    dtls.dgram = tlsdgram;
    dtls.udpSocket = socket;

    clearDtlsError();

    QByteArray dgram;
    dgram.resize(tlsdgram.size());
    const int read = q_SSL_read(dtls.tlsConnection.data(), dgram.data(),
                                dgram.size());

    if (read > 0) {
        dgram.resize(read);
        return dgram;
    }

    dgram.clear();
    unsigned long errorCode = q_ERR_get_error();
    if (errorCode == SSL_ERROR_NONE) {
        const int shutdown = q_SSL_get_shutdown(dtls.tlsConnection.data());
        if (shutdown & SSL_RECEIVED_SHUTDOWN)
            errorCode = SSL_ERROR_ZERO_RETURN;
        else
            return dgram;
    }

    switch (errorCode) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return dgram;
    case SSL_ERROR_ZERO_RETURN:
        // "The connection was shut down cleanly" ... hmm, whatever,
        // needs testing (DTLSTODO).
        connectionWasShutdown = true;
        setDtlsError(QDtlsError::RemoteClosedConnectionError,
                     QDtls::tr("The DTLS connection has been shutdown"));
        dtls.reset();
        connectionEncrypted = false;
        handshakeState = QDtls::HandshakeNotStarted;
        return dgram;
    case SSL_ERROR_SYSCALL: // some IO error
    case SSL_ERROR_SSL:     // error in the SSL library
        // DTLSTODO: Apparently, some errors can be ignored, for example,
        // ECONNRESET etc. This all needs a lot of testing!!!
    default:
        setDtlsError(QDtlsError::TlsNonFatalError,
                     QDtls::tr("Error while reading: %1")
                               .arg(QSslSocketBackendPrivate::getErrorsFromOpenSsl()));
        return dgram;
    }
}

unsigned QDtlsPrivateOpenSSL::pskClientCallback(const char *hint, char *identity,
                                                unsigned max_identity_len,
                                                unsigned char *psk,
                                                unsigned max_psk_len)
{
    // The code below is taken (with some modifications) from qsslsocket_openssl
    // - alas, we cannot simply re-use it, it's in QSslSocketPrivate.

    Q_Q(QDtls);

    {
        QSslPreSharedKeyAuthenticator authenticator;
        // Fill in some read-only fields (for client code)
        if (hint) {
            identityHint.clear();
            identityHint.append(hint);
            // From the original code in QSslSocket:
            // "it's NULL terminated, but do not include the NULL" == this fromRawData(ptr/size).
            authenticator.d->identityHint = QByteArray::fromRawData(identityHint.constData(),
                                                                    int(std::strlen(hint)));
        }

        authenticator.d->maximumIdentityLength = int(max_identity_len) - 1; // needs to be NULL terminated
        authenticator.d->maximumPreSharedKeyLength = int(max_psk_len);

        pskAuthenticator.swap(authenticator);
    }

    // Let the client provide the remaining bits...
    emit q->pskRequired(&pskAuthenticator);

    // No PSK set? Return now to make the handshake fail
    if (pskAuthenticator.preSharedKey().isEmpty())
        return 0;

    // Copy data back into OpenSSL
    const int identityLength = qMin(pskAuthenticator.identity().length(),
                                    pskAuthenticator.maximumIdentityLength());
    std::memcpy(identity, pskAuthenticator.identity().constData(), identityLength);
    identity[identityLength] = 0;

    const int pskLength = qMin(pskAuthenticator.preSharedKey().length(),
                               pskAuthenticator.maximumPreSharedKeyLength());
    std::memcpy(psk, pskAuthenticator.preSharedKey().constData(), pskLength);

    return pskLength;
}

unsigned QDtlsPrivateOpenSSL::pskServerCallback(const char *identity, unsigned char *psk,
                                                unsigned max_psk_len)
{
    Q_Q(QDtls);

    {
        QSslPreSharedKeyAuthenticator authenticator;
        // Fill in some read-only fields (for the user)
        authenticator.d->identityHint = dtlsConfiguration.preSharedKeyIdentityHint;
        authenticator.d->identity = identity;
        authenticator.d->maximumIdentityLength = 0; // user cannot set an identity
        authenticator.d->maximumPreSharedKeyLength = int(max_psk_len);

        pskAuthenticator.swap(authenticator);
    }

    // Let the client provide the remaining bits...
    emit q->pskRequired(&pskAuthenticator);

    // No PSK set? Return now to make the handshake fail
    if (pskAuthenticator.preSharedKey().isEmpty())
        return 0;

    // Copy data back into OpenSSL
    const int pskLength = qMin(pskAuthenticator.preSharedKey().length(),
                               pskAuthenticator.maximumPreSharedKeyLength());

    std::memcpy(psk, pskAuthenticator.preSharedKey().constData(), pskLength);

    return pskLength;
}

// The definition is located in qsslsocket_openssl.cpp.
QSslError _q_OpenSSL_to_QSslError(int errorCode, const QSslCertificate &cert);

bool QDtlsPrivateOpenSSL::verifyPeer()
{
    // DTLSTODO: Windows-specific code for CA fetcher is not here yet.
    QVector<QSslError> errors;

    // Check the whole chain for blacklisting (including root, as we check for
    // subjectInfo and issuer)
    for (const QSslCertificate &cert : qAsConst(dtlsConfiguration.peerCertificateChain)) {
        if (QSslCertificatePrivate::isBlacklisted(cert))
            errors << QSslError(QSslError::CertificateBlacklisted, cert);
    }

    if (dtlsConfiguration.peerCertificate.isNull()) {
        errors << QSslError(QSslError::NoPeerCertificate);
    } else if (mode == QSslSocket::SslClientMode) {
        // Check the peer certificate itself. First try the subject's common name
        // (CN) as a wildcard, then try all alternate subject name DNS entries the
        // same way.

        // QSslSocket has a rather twisted logic: if verificationPeerName
        // is empty, we call QAbstractSocket::peerName(), which returns
        // either peerName (can be set by setPeerName) or host name
        // (can be set as a result of connectToHost).
        QString name = peerVerificationName;
        if (name.isEmpty()) {
            Q_ASSERT(dtls.udpSocket);
            name = dtls.udpSocket->peerName();
        }

        if (!QSslSocketPrivate::isMatchingHostname(dtlsConfiguration.peerCertificate, name))
            errors << QSslError(QSslError::HostNameMismatch, dtlsConfiguration.peerCertificate);
    }

    // Translate errors from the error list into QSslErrors
    errors.reserve(errors.size() + opensslErrors.size());
    for (const auto &error : qAsConst(opensslErrors)) {
        errors << _q_OpenSSL_to_QSslError(error.code,
                                          dtlsConfiguration.peerCertificateChain.value(error.depth));
    }

    tlsErrors = errors;
    return tlsErrors.isEmpty();
}

void QDtlsPrivateOpenSSL::storePeerCertificates()
{
    Q_ASSERT(dtls.tlsConnection.data());
    // Store the peer certificate and chain. For clients, the peer certificate
    // chain includes the peer certificate; for servers, it doesn't. Both the
    // peer certificate and the chain may be empty if the peer didn't present
    // any certificate.
    X509 *x509 = q_SSL_get_peer_certificate(dtls.tlsConnection.data());
    dtlsConfiguration.peerCertificate = QSslCertificatePrivate::QSslCertificate_from_X509(x509);
    q_X509_free(x509);
    if (dtlsConfiguration.peerCertificateChain.isEmpty()) {
        auto stack = q_SSL_get_peer_cert_chain(dtls.tlsConnection.data());
        dtlsConfiguration.peerCertificateChain = QSslSocketBackendPrivate::STACKOFX509_to_QSslCertificates(stack);
        if (!dtlsConfiguration.peerCertificate.isNull() && mode == QSslSocket::SslServerMode)
            dtlsConfiguration.peerCertificateChain.prepend(dtlsConfiguration.peerCertificate);
    }
}

bool QDtlsPrivateOpenSSL::tlsErrorsWereIgnored() const
{
    // check whether the errors we got are all in the list of expected errors
    // (applies only if the method QDtlsConnection::ignoreTlsErrors(const
    // QVector<QSslError> &errors) was called)
    for (const QSslError &error : tlsErrors) {
        if (!tlsErrorsToIgnore.contains(error))
            return false;
    }

    return !tlsErrorsToIgnore.empty();
}

void QDtlsPrivateOpenSSL::fetchNegotiatedParameters()
{
    Q_ASSERT(dtls.tlsConnection.data());

    const SSL_CIPHER *cipher = q_SSL_get_current_cipher(dtls.tlsConnection.data());
    sessionCipher = cipher ? QSslSocketBackendPrivate::QSslCipher_from_SSL_CIPHER(cipher)
                           : QSslCipher();

    // Note: cipher's protocol version will be reported as either TLS 1.0 or
    // TLS 1.2, that's how it's set by OpenSSL (and that's what they are?).

    switch (q_SSL_version(dtls.tlsConnection.data())) {
    case DTLS1_VERSION:
        sessionProtocol = QSsl::DtlsV1_0;
        break;
    case DTLS1_2_VERSION:
        sessionProtocol = QSsl::DtlsV1_2;
        break;
    default:
        qCWarning(lcSsl, "unknown protocol version");
        sessionProtocol = QSsl::UnknownProtocol;
    }
}

void QDtlsPrivateOpenSSL::reportTimeout()
{
    Q_Q(QDtls);

    emit q->handshakeTimeout();
}

void QDtlsPrivateOpenSSL::resetDtls()
{
    dtls.reset();
    connectionEncrypted = false;
    tlsErrors.clear();
    tlsErrorsToIgnore.clear();
    dtlsConfiguration.peerCertificate.clear();
    dtlsConfiguration.peerCertificateChain.clear();
    connectionWasShutdown = false;
    handshakeState = QDtls::HandshakeNotStarted;
    sessionCipher = {};
    sessionProtocol = QSsl::UnknownProtocol;
}

QT_END_NAMESPACE
