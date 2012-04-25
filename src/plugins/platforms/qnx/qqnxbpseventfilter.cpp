/***************************************************************************
**
** Copyright (C) 2012 Research In Motion
** Contact: http://www.qt-project.org/
**
** This file is part of the plugins of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** GNU Lesser General Public License Usage
** This file may be used under the terms of the GNU Lesser General Public
** License version 2.1 as published by the Free Software Foundation and
** appearing in the file LICENSE.LGPL included in the packaging of this
** file. Please review the following information to ensure the GNU Lesser
** General Public License version 2.1 requirements will be met:
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Nokia gives you certain additional
** rights. These rights are described in the Nokia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU General
** Public License version 3.0 as published by the Free Software Foundation
** and appearing in the file LICENSE.GPL included in the packaging of this
** file. Please review the following information to ensure the GNU General
** Public License version 3.0 requirements will be met:
** http://www.gnu.org/copyleft/gpl.html.
**
** Other Usage
** Alternatively, this file may be used in accordance with the terms and
** conditions contained in a signed written agreement between you and Nokia.
**
**
**
**
**
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qqnxbpseventfilter.h"
#include "qqnxnavigatoreventhandler.h"
#include "qqnxfiledialoghelper.h"
#include "qqnxscreen.h"
#include "qqnxscreeneventhandler.h"
#include "qqnxvirtualkeyboardbps.h"

#include <QAbstractEventDispatcher>
#include <QDebug>

#include <bps/event.h>
#include <bps/navigator.h>
#include <bps/screen.h>

#ifdef QQNXBPSEVENTFILTER_DEBUG
#define qBpsEventFilterDebug qDebug
#else
#define qBpsEventFilterDebug QT_NO_QDEBUG_MACRO
#endif

QT_BEGIN_NAMESPACE

static QQnxBpsEventFilter *s_instance = 0;

QQnxBpsEventFilter::QQnxBpsEventFilter(QQnxNavigatorEventHandler *navigatorEventHandler,
                                       QQnxScreenEventHandler *screenEventHandler,
                                       QQnxVirtualKeyboardBps *virtualKeyboard, QObject *parent)
    : QObject(parent)
    , m_navigatorEventHandler(navigatorEventHandler)
    , m_screenEventHandler(screenEventHandler)
    , m_virtualKeyboard(virtualKeyboard)
{
    Q_ASSERT(s_instance == 0);

    s_instance = this;
}

QQnxBpsEventFilter::~QQnxBpsEventFilter()
{
    Q_ASSERT(s_instance == this);

    s_instance = 0;
}

void QQnxBpsEventFilter::installOnEventDispatcher(QAbstractEventDispatcher *dispatcher)
{
    qBpsEventFilterDebug() << Q_FUNC_INFO << "dispatcher=" << dispatcher;

    if (navigator_request_events(0) != BPS_SUCCESS)
        qWarning("QQNX: failed to register for navigator events");

    QAbstractEventDispatcher::EventFilter previousEventFilter = dispatcher->setEventFilter(dispatcherEventFilter);

    // the QPA plugin creates the event dispatcher so we are the first event
    // filter assert on that just in case somebody adds another event filter
    // in the QQnxIntegration constructor instead of adding a new section in here
    Q_ASSERT(previousEventFilter == 0);
    Q_UNUSED(previousEventFilter);
}

void QQnxBpsEventFilter::registerForScreenEvents(QQnxScreen *screen)
{
    if (screen_request_events(screen->nativeContext()) != BPS_SUCCESS)
        qWarning("QQNX: failed to register for screen events on screen %p", screen->nativeContext());
}

void QQnxBpsEventFilter::unregisterForScreenEvents(QQnxScreen *screen)
{
    if (screen_stop_events(screen->nativeContext()) != BPS_SUCCESS)
        qWarning("QQNX: failed to unregister for screen events on screen %p", screen->nativeContext());
}

void QQnxBpsEventFilter::registerForDialogEvents(QQnxFileDialogHelper *dialog)
{
    if (dialog_request_events(0) != BPS_SUCCESS)
        qWarning("QQNX: failed to register for dialog events");
    dialog_instance_t nativeDialog = dialog->nativeDialog();
    if (!m_dialogMapper.contains(nativeDialog))
        m_dialogMapper.insert(nativeDialog, dialog);
}

void QQnxBpsEventFilter::unregisterForDialogEvents(QQnxFileDialogHelper *dialog)
{
    int count = m_dialogMapper.remove(dialog->nativeDialog());
    if (count == 0)
        qWarning("QQNX: attempting to unregister dialog that was not registered");
}

bool QQnxBpsEventFilter::dispatcherEventFilter(void *message)
{
    qBpsEventFilterDebug() << Q_FUNC_INFO;

    if (s_instance == 0)
        return false;

    bps_event_t *event = static_cast<bps_event_t *>(message);
    return s_instance->bpsEventFilter(event);
}

bool QQnxBpsEventFilter::bpsEventFilter(bps_event_t *event)
{
    const int eventDomain = bps_event_get_domain(event);
    qBpsEventFilterDebug() << Q_FUNC_INFO << "event=" << event << "domain=" << eventDomain;

    if (eventDomain == screen_get_domain()) {
        screen_event_t screenEvent = screen_event_get_event(event);
        return m_screenEventHandler->handleEvent(screenEvent);
    }

    if (eventDomain == dialog_get_domain()) {
        dialog_instance_t nativeDialog = dialog_event_get_dialog_instance(event);
        QQnxFileDialogHelper *dialog = m_dialogMapper.value(nativeDialog, 0);
        if (dialog)
            return dialog->handleEvent(event);
    }

    if (eventDomain == navigator_get_domain())
        return handleNavigatorEvent(event);

    if (m_virtualKeyboard->handleEvent(event))
        return true;

    return false;
}

bool QQnxBpsEventFilter::handleNavigatorEvent(bps_event_t *event)
{
    switch (bps_event_get_code(event)) {
    case NAVIGATOR_ORIENTATION_CHECK: {
        const int angle = navigator_event_get_orientation_angle(event);
        qBpsEventFilterDebug() << Q_FUNC_INFO << "ORIENTATION CHECK event. angle=" << angle;

        const bool result = m_navigatorEventHandler->handleOrientationCheck(angle);
        qBpsEventFilterDebug() << Q_FUNC_INFO << "ORIENTATION CHECK event. result=" << result;

        // reply to navigator whether orientation is acceptable
        navigator_orientation_check_response(event, result);
        break;
    }

    case NAVIGATOR_ORIENTATION: {
        const int angle = navigator_event_get_orientation_angle(event);
        qBpsEventFilterDebug() << Q_FUNC_INFO << "ORIENTATION event. angle=" << angle;
        m_navigatorEventHandler->handleOrientationChange(angle);

        navigator_done_orientation(event);
        break;
    }

    case NAVIGATOR_SWIPE_DOWN:
        qBpsEventFilterDebug() << Q_FUNC_INFO << "SWIPE DOWN event";
        m_navigatorEventHandler->handleSwipeDown();
        break;

    case NAVIGATOR_EXIT:
        qBpsEventFilterDebug() << Q_FUNC_INFO << "EXIT event";
        m_navigatorEventHandler->handleExit();
        break;

    case NAVIGATOR_WINDOW_ACTIVE: {
        qBpsEventFilterDebug() << Q_FUNC_INFO << "WINDOW ACTIVE event";
        const QByteArray id(navigator_event_get_groupid(event));
        m_navigatorEventHandler->handleWindowGroupActivated(id);
        break;
    }

    case NAVIGATOR_WINDOW_INACTIVE: {
        qBpsEventFilterDebug() << Q_FUNC_INFO << "WINDOW INACTIVE event";
        const QByteArray id(navigator_event_get_groupid(event));
        m_navigatorEventHandler->handleWindowGroupDeactivated(id);
        break;
    }

    default:
        qBpsEventFilterDebug() << Q_FUNC_INFO << "Unhandled navigator event. code=" << bps_event_get_code(event);
        return false;
    }

    return true;
}

QT_END_NAMESPACE
