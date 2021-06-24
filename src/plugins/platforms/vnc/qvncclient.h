/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtGui module of the Qt Toolkit.
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

#ifndef QVNCCLIENT_H
#define QVNCCLIENT_H

#include <QObject>

#include "qvnc_p.h"

QT_BEGIN_NAMESPACE

class QTcpSocket;
class QVncServer;

class QVncClient : public QObject
{
    Q_OBJECT
public:
    enum ClientMsg {
        SetPixelFormat = 0,
        FixColourMapEntries = 1,
        SetEncodings = 2,
        FramebufferUpdateRequest = 3,
        KeyEvent = 4,
        PointerEvent = 5,
        ClientCutText = 6
    };

    explicit QVncClient(QTcpSocket *clientSocket, QVncServer *server);
    ~QVncClient();
    QTcpSocket *clientSocket() const;
    QVncServer *server() const { return m_server; }

    void setDirty(const QRegion &region);
    void setDirtyCursor() { if( m_state != Connected ) return; m_dirtyCursor = true; scheduleUpdate(); }
    QRegion dirtyRegion() const { return m_dirtyRegion; }
    inline bool isConnected() const { return m_state == Connected; }

    inline int clientBytesPerPixel() const {
        return m_pixelFormat.bitsPerPixel / 8;
    }

    void convertPixels(char *dst, const char *src, int count, int depth) const;
    inline bool doPixelConversion() const { return m_needConversion; }

signals:

private slots:
    void readClient();
    void discardClient();
    void checkUpdate();
    void scheduleUpdate();

protected:
    bool event(QEvent *event) override;

private:
    enum ClientState {
        Disconnected,
        Protocol,
        Authentication,
        Init,
        Connected
    };
    enum ProtocolVersion {
        V3_3,
        V3_7,
        V3_8
    };

    void setPixelFormat();
    void setEncodings();
    void frameBufferUpdateRequest();
    void pointerEvent();
    void keyEvent();
    void clientCutText();
    bool pixelConversionNeeded() const;

    QVncServer *m_server;
    QTcpSocket *m_clientSocket;
    QRfbEncoder *m_encoder;

    // Client State
    ClientState m_state;
    quint8 m_msgType;
    bool m_handleMsg;
    QRfbPixelFormat m_pixelFormat;
    bool m_sameEndian;
    bool m_needConversion;
    int m_encodingsPending;
    int m_cutTextPending;
    uint m_supportCopyRect : 1;
    uint m_supportRRE : 1;
    uint m_supportCoRRE : 1;
    uint m_supportHextile : 1;
    uint m_supportZRLE : 1;
    uint m_supportCursor : 1;
    uint m_supportDesktopSize : 1;
    bool m_wantUpdate;
    Qt::KeyboardModifiers m_keymod;
    bool m_dirtyCursor;
    bool m_updatePending;
#if Q_BYTE_ORDER == Q_BIG_ENDIAN
    bool m_swapBytes;
#endif
    QRegion m_dirtyRegion;
    ProtocolVersion m_protocolVersion;
};

QT_END_NAMESPACE

#endif // QVNCCLIENT_H
