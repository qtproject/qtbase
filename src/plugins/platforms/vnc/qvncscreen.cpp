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

#include "qvncscreen.h"
#include "qvnc_p.h"
#include <QtFbSupport/private/qfbwindow_p.h>
#include <QtFbSupport/private/qfbcursor_p.h>

#include <QtGui/QPainter>
#include <QtGui/QScreen>
#include <QtCore/QRegularExpression>


QT_BEGIN_NAMESPACE


QVncScreen::QVncScreen(const QStringList &args)
    : mArgs(args)
{
    initialize();
}

QVncScreen::~QVncScreen()
{
#if QT_CONFIG(cursor)
    if (clientCursor)
        delete clientCursor;
#endif
}

bool QVncScreen::initialize()
{
    QRegularExpression sizeRx(QLatin1String("size=(\\d+)x(\\d+)"));
    QRegularExpression mmSizeRx(QLatin1String("mmsize=(?<width>(\\d*\\.)?\\d+)x(?<height>(\\d*\\.)?\\d+)"));
    QRegularExpression depthRx(QLatin1String("depth=(\\d+)"));

    mGeometry = QRect(0, 0, 1024, 768);
    mFormat = QImage::Format_ARGB32_Premultiplied;
    mDepth = 32;
    mPhysicalSize = QSizeF(mGeometry.width()/96.*25.4, mGeometry.height()/96.*25.4);

    for (const QString &arg : qAsConst(mArgs)) {
        QRegularExpressionMatch match;
        if (arg.contains(mmSizeRx, &match)) {
            mPhysicalSize = QSizeF(match.captured("width").toDouble(), match.captured("height").toDouble());
        } else if (arg.contains(sizeRx, &match)) {
            mGeometry.setSize(QSize(match.captured(1).toInt(), match.captured(2).toInt()));
            mPhysicalSize = QSizeF(mGeometry.width()/96.*25.4, mGeometry.height()/96.*25.4);
        } else if (arg.contains(depthRx, &match)) {
            mDepth = match.captured(1).toInt();
        }
    }

    switch (depth()) {
    case 32:
        dirty = new QVncDirtyMapOptimized<quint32>(this);
        break;
    case 16:
        dirty = new QVncDirtyMapOptimized<quint16>(this);
        mFormat = QImage::Format_RGB16;
        break;
    case 8:
        dirty = new QVncDirtyMapOptimized<quint8>(this);
        break;
    default:
        qWarning("QVNCScreen::initDevice: No support for screen depth %d",
                 depth());
        dirty = nullptr;
        return false;
    }

    QFbScreen::initializeCompositor();

    setPowerState(PowerStateOff);

    return true;
}

QRegion QVncScreen::doRedraw()
{
    QRegion touched = QFbScreen::doRedraw();

    if (touched.isEmpty())
        return touched;
    dirtyRegion += touched;

    vncServer->setDirty();
    return touched;
}


void QVncScreen::enableClientCursor(QVncClient *client)
{
#if QT_CONFIG(cursor)
    delete mCursor;
    mCursor = nullptr;
    if (!clientCursor)
        clientCursor = new QVncClientCursor();
    clientCursor->addClient(client);
#else
    Q_UNUSED(client);
#endif
}

void QVncScreen::disableClientCursor(QVncClient *client)
{
#if QT_CONFIG(cursor)
    if (!clientCursor)
        return;

    uint clientCount = clientCursor->removeClient(client);
    if (clientCount == 0) {
        delete clientCursor;
        clientCursor = nullptr;
    }

    mCursor = new QFbCursor(this);
#else
    Q_UNUSED(client);
#endif
}

QPlatformCursor *QVncScreen::cursor() const
{
#if QT_CONFIG(cursor)
    return mCursor ? static_cast<QPlatformCursor *>(mCursor) : static_cast<QPlatformCursor *>(clientCursor);
#else
    return nullptr;
#endif
}

// grabWindow() grabs "from the screen" not from the backingstores.
// In linuxfb's case it will also include the mouse cursor.
QPixmap QVncScreen::grabWindow(WId wid, int x, int y, int width, int height) const
{
    if (!wid) {
        if (width < 0)
            width = mScreenImage.width() - x;
        if (height < 0)
            height = mScreenImage.height() - y;
        return QPixmap::fromImage(mScreenImage).copy(x, y, width, height);
    }

    QFbWindow *window = windowForId(wid);
    if (window) {
        const QRect geom = window->geometry();
        if (width < 0)
            width = geom.width() - x;
        if (height < 0)
            height = geom.height() - y;
        QRect rect(geom.topLeft() + QPoint(x, y), QSize(width, height));
        rect &= window->geometry();
        return QPixmap::fromImage(mScreenImage).copy(rect);
    }

    return QPixmap();
}

#if Q_BYTE_ORDER == Q_BIG_ENDIAN
bool QVncScreen::swapBytes() const
{
    return false;

    /* TODO
    if (depth() != 16)
        return false;

    if (screen())
        return screen()->frameBufferLittleEndian();
    return frameBufferLittleEndian();
    */
}
#endif

QFbScreen::Flags QVncScreen::flags() const
{
    return QFbScreen::DontForceFirstWindowToFullScreen;
}

QT_END_NAMESPACE

