/****************************************************************************
**
** Copyright (C) 2020 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the plugins of the Qt Toolkit.
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

#include "qxcbconnection.h"
#include "qxcbkeyboard.h"
#include "qxcbscrollingdevice_p.h"
#include "qxcbscreen.h"
#include "qxcbwindow.h"
#include "QtCore/qmetaobject.h"
#include "QtCore/qmath.h"
#include <QtGui/qpointingdevice.h>
#include <QtGui/private/qpointingdevice_p.h>
#include <qpa/qwindowsysteminterface_p.h>
#include <QDebug>

#include <xcb/xinput.h>

using qt_xcb_input_device_event_t = xcb_input_button_press_event_t;

struct qt_xcb_input_event_mask_t {
    xcb_input_event_mask_t header;
    uint32_t               mask;
};

void QXcbConnection::xi2SelectStateEvents()
{
    // These state events do not depend on a specific X window, but are global
    // for the X client's (application's) state.
    qt_xcb_input_event_mask_t xiEventMask;
    xiEventMask.header.deviceid = XCB_INPUT_DEVICE_ALL;
    xiEventMask.header.mask_len = 1;
    xiEventMask.mask = XCB_INPUT_XI_EVENT_MASK_HIERARCHY;
    xiEventMask.mask |= XCB_INPUT_XI_EVENT_MASK_DEVICE_CHANGED;
    xiEventMask.mask |= XCB_INPUT_XI_EVENT_MASK_PROPERTY;
    xcb_input_xi_select_events(xcb_connection(), rootWindow(), 1, &xiEventMask.header);
}

void QXcbConnection::xi2SelectDeviceEvents(xcb_window_t window)
{
    if (window == rootWindow())
        return;

    uint32_t bitMask = XCB_INPUT_XI_EVENT_MASK_BUTTON_PRESS;
    bitMask |= XCB_INPUT_XI_EVENT_MASK_BUTTON_RELEASE;
    bitMask |= XCB_INPUT_XI_EVENT_MASK_MOTION;
    // There is a check for enter/leave events in plain xcb enter/leave event handler,
    // core enter/leave events will be ignored in this case.
    bitMask |= XCB_INPUT_XI_EVENT_MASK_ENTER;
    bitMask |= XCB_INPUT_XI_EVENT_MASK_LEAVE;
    if (isAtLeastXI22()) {
        bitMask |= XCB_INPUT_XI_EVENT_MASK_TOUCH_BEGIN;
        bitMask |= XCB_INPUT_XI_EVENT_MASK_TOUCH_UPDATE;
        bitMask |= XCB_INPUT_XI_EVENT_MASK_TOUCH_END;
    }

    qt_xcb_input_event_mask_t mask;
    mask.header.deviceid = XCB_INPUT_DEVICE_ALL_MASTER;
    mask.header.mask_len = 1;
    mask.mask = bitMask;
    xcb_void_cookie_t cookie =
            xcb_input_xi_select_events_checked(xcb_connection(), window, 1, &mask.header);
    xcb_generic_error_t *error = xcb_request_check(xcb_connection(), cookie);
    if (error) {
        qCDebug(lcQpaXInput, "failed to select events, window %x, error code %d", window, error->error_code);
        free(error);
    } else {
        QWindowSystemInterfacePrivate::TabletEvent::setPlatformSynthesizesMouse(false);
    }
}

static inline qreal fixed3232ToReal(xcb_input_fp3232_t val)
{
    return qreal(val.integral) + qreal(val.frac) / (1ULL << 32);
}

#if QT_CONFIG(tabletevent)
/*!
    \internal
    Find the existing QPointingDevice instance representing a particular tablet or stylus;
    or create and register a new instance if it was not found.

    An instance can be uniquely identified by its \a devType, \a pointerType and \a uniqueId.
    The rest of the arguments are necessary to create a new instance.

    If the instance represents a stylus, the instance representing the tablet
    itself must be given as \a master. Otherwise, \a master must be the xinput
    master device (core pointer) to which the tablet belongs.  It should not be
    null, because \a master is also the QObject::parent() for memory management.

    Proximity events have incomplete information. So as a side effect, if an
    existing instance is found, it is updated with the given \a usbId and
    \a toolId, and the seat ID of \a master, in case those values were only
    now discovered, or the seat assignment changed (?).
*/
static const QPointingDevice *tabletToolInstance(QPointingDevice *master, const QString &tabletName,
                                                 qint64 id, quint32 usbId, quint32 toolId, qint64 uniqueId,
                                                 QPointingDevice::PointerType pointerTypeOverride = QPointingDevice::PointerType::Unknown,
                                                 QPointingDevice::Capabilities capsOverride = QInputDevice::Capability::None)
{
    QInputDevice::DeviceType devType = QInputDevice::DeviceType::Stylus;
    QPointingDevice::PointerType pointerType = QPointingDevice::PointerType::Pen;
    QPointingDevice::Capabilities caps = QInputDevice::Capability::Position |
            QInputDevice::Capability::Pressure |
            QInputDevice::Capability::MouseEmulation |
            QInputDevice::Capability::Hover |
            capsOverride;
    int buttonCount = 3; // the tip, plus two barrel buttons
    // keep in sync with wacom_intuos_inout() in Linux kernel driver wacom_wac.c
    // TODO yeah really, there are many more now so this needs updating
    switch (toolId) {
    case 0xd12:
    case 0x912:
    case 0x112:
    case 0x913: /* Intuos3 Airbrush */
    case 0x902: /* Intuos4/5 13HD/24HD Airbrush */
    case 0x100902: /* Intuos4/5 13HD/24HD Airbrush */
        devType = QInputDevice::DeviceType::Airbrush;
        caps.setFlag(QInputDevice::Capability::XTilt);
        caps.setFlag(QInputDevice::Capability::YTilt);
        caps.setFlag(QInputDevice::Capability::TangentialPressure);
        buttonCount = 2;
        break;
    case 0x91b: /* Intuos3 Airbrush Eraser */
    case 0x90a: /* Intuos4/5 13HD/24HD Airbrush Eraser */
    case 0x10090a: /* Intuos4/5 13HD/24HD Airbrush Eraser */
        devType = QInputDevice::DeviceType::Airbrush;
        pointerType = QPointingDevice::PointerType::Eraser;
        caps.setFlag(QInputDevice::Capability::XTilt);
        caps.setFlag(QInputDevice::Capability::YTilt);
        caps.setFlag(QInputDevice::Capability::TangentialPressure);
        buttonCount = 2;
        break;
    case 0x007: /* Mouse 4D and 2D */
    case 0x09c:
    case 0x094:
        // TODO set something to indicate a multi-dimensional capability:
        // Capability::3D or 4D or QPointingDevice::setMaximumDimensions()?
        devType = QInputDevice::DeviceType::Mouse;
        buttonCount = 5; // TODO only if it's a 4D Mouse
        break;
    case 0x017: /* Intuos3 2D Mouse */
    case 0x806: /* Intuos4 Mouse */
        devType = QInputDevice::DeviceType::Mouse;
        break;
    case 0x096: /* Lens cursor */
    case 0x097: /* Intuos3 Lens cursor */
    case 0x006: /* Intuos4 Lens cursor */
        devType = QInputDevice::DeviceType::Puck;
        break;
    case 0x885:    /* Intuos3 Art Pen (Marker Pen) */
    case 0x100804: /* Intuos4/5 13HD/24HD Art Pen */
        caps.setFlag(QInputDevice::Capability::XTilt);
        caps.setFlag(QInputDevice::Capability::YTilt);
        caps.setFlag(QInputDevice::Capability::Rotation);
        buttonCount = 1;
        break;
    case 0x10080c: /* Intuos4/5 13HD/24HD Art Pen Eraser */
        pointerType = QPointingDevice::PointerType::Eraser;
        caps.setFlag(QInputDevice::Capability::XTilt);
        caps.setFlag(QInputDevice::Capability::YTilt);
        caps.setFlag(QInputDevice::Capability::Rotation);
        buttonCount = 1;
        break;
    case 0:
        pointerType = QPointingDevice::PointerType::Unknown;
        break;
    }
    if (pointerTypeOverride != QPointingDevice::PointerType::Unknown)
        pointerType = pointerTypeOverride;
    const QPointingDevice *ret = QPointingDevicePrivate::queryTabletDevice(devType, pointerType,
                                                                           QPointingDeviceUniqueId::fromNumericId(uniqueId), id);
    if (!ret) {
        ret = new QPointingDevice(tabletName, id, devType, pointerType, caps, 1, buttonCount,
                                  master ? master->seatName() : QString(),
                                  QPointingDeviceUniqueId::fromNumericId(uniqueId), master);
        QWindowSystemInterface::registerInputDevice(ret);
    }
    QPointingDevicePrivate *devPriv = QPointingDevicePrivate::get(const_cast<QPointingDevice *>(ret));
    devPriv->busId = QString::number(usbId, 16);
    devPriv->toolId = toolId;
    if (master)
        devPriv->seatName = master->seatName();
    return ret;
}

static const char *toolName(QInputDevice::DeviceType tool) {
    static const QMetaObject *metaObject = qt_getEnumMetaObject(tool);
    static const QMetaEnum me = metaObject->enumerator(metaObject->indexOfEnumerator(qt_getEnumName(tool)));
    return me.valueToKey(int(tool));
}

static const char *pointerTypeName(QPointingDevice::PointerType ptype) {
    static const QMetaObject *metaObject = qt_getEnumMetaObject(ptype);
    static const QMetaEnum me = metaObject->enumerator(metaObject->indexOfEnumerator(qt_getEnumName(ptype)));
    return me.valueToKey(int(ptype));
}
#endif

void QXcbConnection::xi2SetupSlavePointerDevice(void *info, bool removeExisting, QPointingDevice *master)
{
    auto *deviceInfo = reinterpret_cast<xcb_input_xi_device_info_t *>(info);
    if (removeExisting) {
#if QT_CONFIG(tabletevent)
        for (int i = 0; i < m_tabletData.count(); ++i) {
            if (m_tabletData.at(i).deviceId == deviceInfo->deviceid) {
                m_tabletData.remove(i);
                break;
            }
        }
#endif
        m_touchDevices.remove(deviceInfo->deviceid);
    }

    const QByteArray nameRaw = QByteArray(xcb_input_xi_device_info_name(deviceInfo),
                                    xcb_input_xi_device_info_name_length(deviceInfo));
    const QString name = QString::fromUtf8(nameRaw);
    qCDebug(lcQpaXInputDevices) << "input device " << name << "ID" << deviceInfo->deviceid;
#if QT_CONFIG(tabletevent)
    TabletData tabletData;
#endif
    QXcbScrollingDevicePrivate *scrollingDeviceP = nullptr;
    auto scrollingDevice = [&]() {
        if (!scrollingDeviceP)
            scrollingDeviceP = new QXcbScrollingDevicePrivate(name, deviceInfo->deviceid,
                                                              QInputDevice::Capability::Scroll);
        return scrollingDeviceP;
    };

    int buttonCount = 32;
    auto classes_it = xcb_input_xi_device_info_classes_iterator(deviceInfo);
    for (; classes_it.rem; xcb_input_device_class_next(&classes_it)) {
        xcb_input_device_class_t *classinfo = classes_it.data;
        switch (classinfo->type) {
        case XCB_INPUT_DEVICE_CLASS_TYPE_VALUATOR: {
            auto *vci = reinterpret_cast<xcb_input_valuator_class_t *>(classinfo);
            const int valuatorAtom = qatom(vci->label);
            qCDebug(lcQpaXInputDevices) << "   has valuator" << atomName(vci->label) << "recognized?" << (valuatorAtom < QXcbAtom::NAtoms);
#if QT_CONFIG(tabletevent)
            if (valuatorAtom < QXcbAtom::NAtoms) {
                TabletData::ValuatorClassInfo info;
                info.minVal = fixed3232ToReal(vci->min);
                info.maxVal = fixed3232ToReal(vci->max);
                info.number = vci->number;
                tabletData.valuatorInfo[valuatorAtom] = info;
            }
#endif // QT_CONFIG(tabletevent)
            if (valuatorAtom == QXcbAtom::RelHorizScroll || valuatorAtom == QXcbAtom::RelHorizWheel)
                scrollingDevice()->lastScrollPosition.setX(fixed3232ToReal(vci->value));
            else if (valuatorAtom == QXcbAtom::RelVertScroll || valuatorAtom == QXcbAtom::RelVertWheel)
                scrollingDevice()->lastScrollPosition.setY(fixed3232ToReal(vci->value));
            break;
        }
        case XCB_INPUT_DEVICE_CLASS_TYPE_SCROLL: {
            auto *sci = reinterpret_cast<xcb_input_scroll_class_t *>(classinfo);
            if (sci->scroll_type == XCB_INPUT_SCROLL_TYPE_VERTICAL) {
                auto dev = scrollingDevice();
                dev->orientations.setFlag(Qt::Vertical);
                dev->verticalIndex = sci->number;
                dev->verticalIncrement = fixed3232ToReal(sci->increment);
            } else if (sci->scroll_type == XCB_INPUT_SCROLL_TYPE_HORIZONTAL) {
                auto dev = scrollingDevice();
                dev->orientations.setFlag(Qt::Horizontal);
                dev->horizontalIndex = sci->number;
                dev->horizontalIncrement = fixed3232ToReal(sci->increment);
            }
            break;
        }
        case XCB_INPUT_DEVICE_CLASS_TYPE_BUTTON: {
            auto *bci = reinterpret_cast<xcb_input_button_class_t *>(classinfo);
            xcb_atom_t *labels = nullptr;
            if (bci->num_buttons >= 5) {
                labels = xcb_input_button_class_labels(bci);
                xcb_atom_t label4 = labels[3];
                xcb_atom_t label5 = labels[4];
                // Some drivers have no labels on the wheel buttons, some have no label on just one and some have no label on
                // button 4 and the wrong one on button 5. So we just check that they are not labelled with unrelated buttons.
                if ((!label4 || qatom(label4) == QXcbAtom::ButtonWheelUp || qatom(label4) == QXcbAtom::ButtonWheelDown) &&
                    (!label5 || qatom(label5) == QXcbAtom::ButtonWheelUp || qatom(label5) == QXcbAtom::ButtonWheelDown))
                    scrollingDevice()->legacyOrientations |= Qt::Vertical;
            }
            if (bci->num_buttons >= 7) {
                xcb_atom_t label6 = labels[5];
                xcb_atom_t label7 = labels[6];
                if ((!label6 || qatom(label6) == QXcbAtom::ButtonHorizWheelLeft) && (!label7 || qatom(label7) == QXcbAtom::ButtonHorizWheelRight))
                    scrollingDevice()->legacyOrientations |= Qt::Horizontal;
            }
            buttonCount = bci->num_buttons;
            qCDebug(lcQpaXInputDevices, "   has %d buttons", bci->num_buttons);
            break;
        }
        case XCB_INPUT_DEVICE_CLASS_TYPE_KEY:
            qCDebug(lcQpaXInputDevices) << "   it's a keyboard";
            break;
        case XCB_INPUT_DEVICE_CLASS_TYPE_TOUCH:
            // will be handled in populateTouchDevices()
            break;
        default:
            qCDebug(lcQpaXInputDevices) << "   has class" << classinfo->type;
            break;
        }
    }
    bool isTablet = false;
#if QT_CONFIG(tabletevent)
    // If we have found the valuators which we expect a tablet to have, it might be a tablet.
    if (tabletData.valuatorInfo.contains(QXcbAtom::AbsX) &&
            tabletData.valuatorInfo.contains(QXcbAtom::AbsY) &&
            tabletData.valuatorInfo.contains(QXcbAtom::AbsPressure))
        isTablet = true;

    // But we need to be careful not to take the touch and tablet-button devices as tablets.
    QByteArray nameLower = nameRaw.toLower();
    QString dbgType = QLatin1String("UNKNOWN");
    if (nameLower.contains("eraser")) {
        isTablet = true;
        tabletData.pointerType = QPointingDevice::PointerType::Eraser;
        dbgType = QLatin1String("eraser");
    } else if (nameLower.contains("cursor") && !(nameLower.contains("cursor controls") && nameLower.contains("trackball"))) {
        isTablet = true;
        tabletData.pointerType = QPointingDevice::PointerType::Cursor;
        dbgType = QLatin1String("cursor");
    } else if (nameLower.contains("wacom") && nameLower.contains("finger touch")) {
        isTablet = false;
    } else if ((nameLower.contains("pen") || nameLower.contains("stylus")) && isTablet) {
        tabletData.pointerType = QPointingDevice::PointerType::Pen;
        dbgType = QLatin1String("pen");
    } else if (nameLower.contains("wacom") && isTablet && !nameLower.contains("touch")) {
        // combined device (evdev) rather than separate pen/eraser (wacom driver)
        tabletData.pointerType = QPointingDevice::PointerType::Pen;
        dbgType = QLatin1String("pen");
    } else if (nameLower.contains("aiptek") /* && device == QXcbAtom::KEYBOARD */) {
        // some "Genius" tablets
        isTablet = true;
        tabletData.pointerType = QPointingDevice::PointerType::Pen;
        dbgType = QLatin1String("pen");
    } else if (nameLower.contains("waltop") && nameLower.contains("tablet")) {
        // other "Genius" tablets
        // WALTOP International Corp. Slim Tablet
        isTablet = true;
        tabletData.pointerType = QPointingDevice::PointerType::Pen;
        dbgType = QLatin1String("pen");
    } else if (nameLower.contains("uc-logic") && isTablet) {
        tabletData.pointerType = QPointingDevice::PointerType::Pen;
        dbgType = QLatin1String("pen");
    } else if (nameLower.contains("ugee")) {
        isTablet = true;
        tabletData.pointerType = QPointingDevice::PointerType::Pen;
        dbgType = QLatin1String("pen");
    } else {
        isTablet = false;
    }

    if (isTablet) {
        tabletData.deviceId = deviceInfo->deviceid;
        tabletData.name = name;
        m_tabletData.append(tabletData);
        qCDebug(lcQpaXInputDevices) << "   it's a tablet with pointer type" << dbgType;
        QPointingDevice::Capabilities capsOverride = QInputDevice::Capability::None;
        if (tabletData.valuatorInfo.contains(QXcbAtom::AbsTiltX))
            capsOverride.setFlag(QInputDevice::Capability::XTilt);
        if (tabletData.valuatorInfo.contains(QXcbAtom::AbsTiltY))
            capsOverride.setFlag(QInputDevice::Capability::YTilt);
        // TODO can we get USB ID?
        Q_ASSERT(deviceInfo->deviceid == tabletData.deviceId);
        const QPointingDevice *dev = tabletToolInstance(master,
                tabletData.name, deviceInfo->deviceid, 0, 0, tabletData.serialId,
                tabletData.pointerType, capsOverride);
        Q_ASSERT(dev);
    }
#endif // QT_CONFIG(tabletevent)

    if (scrollingDeviceP) {
        // Only use legacy wheel button events when we don't have real scroll valuators.
        scrollingDeviceP->legacyOrientations &= ~scrollingDeviceP->orientations;
        qCDebug(lcQpaXInputDevices) << "   it's a scrolling device";
    }

    if (!isTablet) {
        TouchDeviceData *dev = populateTouchDevices(deviceInfo, scrollingDeviceP);
        if (dev && lcQpaXInputDevices().isDebugEnabled()) {
            if (dev->qtTouchDevice->type() == QInputDevice::DeviceType::TouchScreen)
                qCDebug(lcQpaXInputDevices, "   it's a touchscreen with type %d capabilities 0x%X max touch points %d",
                        int(dev->qtTouchDevice->type()), qint32(dev->qtTouchDevice->capabilities()),
                        dev->qtTouchDevice->maximumPoints());
            else if (dev->qtTouchDevice->type() == QInputDevice::DeviceType::TouchPad)
                qCDebug(lcQpaXInputDevices, "   it's a touchpad with type %d capabilities 0x%X max touch points %d size %f x %f",
                        int(dev->qtTouchDevice->type()), qint32(dev->qtTouchDevice->capabilities()),
                        dev->qtTouchDevice->maximumPoints(),
                        dev->size.width(), dev->size.height());
        }
    }

    if (!QInputDevicePrivate::fromId(deviceInfo->deviceid)) {
        qCDebug(lcQpaXInputDevices) << "   it's a mouse";
        QInputDevice::Capabilities caps = QInputDevice::Capability::Position | QInputDevice::Capability::Hover;
        if (scrollingDeviceP) {
            scrollingDeviceP->capabilities |= caps;
            scrollingDeviceP->buttonCount = buttonCount;
            if (master)
                scrollingDeviceP->seatName = master->seatName();
            QWindowSystemInterface::registerInputDevice(new QXcbScrollingDevice(*scrollingDeviceP, master));
        } else {
            QWindowSystemInterface::registerInputDevice(new QPointingDevice(
                    name, deviceInfo->deviceid,
                    QInputDevice::DeviceType::Mouse, QPointingDevice::PointerType::Generic,
                    caps, 1, buttonCount, (master ? master->seatName() : QString()), QPointingDeviceUniqueId(), master));
        }
    }
}

void QXcbConnection::xi2SetupDevices()
{
#if QT_CONFIG(tabletevent)
    m_tabletData.clear();
#endif
    m_touchDevices.clear();
    m_xiMasterPointerIds.clear();

    auto reply = Q_XCB_REPLY(xcb_input_xi_query_device, xcb_connection(), XCB_INPUT_DEVICE_ALL);
    if (!reply) {
        qCDebug(lcQpaXInputDevices) << "failed to query devices";
        return;
    }

    // XInput doesn't provide a way to identify "seats"; but each device has an attachment to another device.
    // So we make up a seatId: master-keyboard-id << 16 | master-pointer-id.

    auto it = xcb_input_xi_query_device_infos_iterator(reply.get());
    for (; it.rem; xcb_input_xi_device_info_next(&it)) {
        xcb_input_xi_device_info_t *deviceInfo = it.data;
        switch (deviceInfo->type) {
        case XCB_INPUT_DEVICE_TYPE_MASTER_KEYBOARD: {
            auto dev = new QInputDevice(QString::fromUtf8(xcb_input_xi_device_info_name(deviceInfo)),
                                        deviceInfo->deviceid, QInputDevice::DeviceType::Keyboard,
                                        QString::number(deviceInfo->deviceid << 16 | deviceInfo->attachment, 16), this);
            QWindowSystemInterface::registerInputDevice(dev);
        } break;
        case XCB_INPUT_DEVICE_TYPE_MASTER_POINTER: {
            m_xiMasterPointerIds.append(deviceInfo->deviceid);
            auto dev = new QXcbScrollingDevice(QString::fromUtf8(xcb_input_xi_device_info_name(deviceInfo)), deviceInfo->deviceid,
                               QInputDevice::Capability::Position | QInputDevice::Capability::Scroll | QInputDevice::Capability::Hover,
                               32, QString::number(deviceInfo->attachment << 16 | deviceInfo->deviceid, 16), this);
            QWindowSystemInterface::registerInputDevice(dev);
            continue;
        } break;
        default:
            break;
        }
    }

    it = xcb_input_xi_query_device_infos_iterator(reply.get());
    for (; it.rem; xcb_input_xi_device_info_next(&it)) {
        xcb_input_xi_device_info_t *deviceInfo = it.data;
        switch (deviceInfo->type) {
        case XCB_INPUT_DEVICE_TYPE_MASTER_KEYBOARD:
        case XCB_INPUT_DEVICE_TYPE_MASTER_POINTER:
            // already registered
            break;
        case XCB_INPUT_DEVICE_TYPE_SLAVE_POINTER: {
            QInputDevice *master = const_cast<QInputDevice *>(QInputDevicePrivate::fromId(deviceInfo->attachment));
            Q_ASSERT(master);
            xi2SetupSlavePointerDevice(deviceInfo, false, qobject_cast<QPointingDevice *>(master));
        } break;
        case XCB_INPUT_DEVICE_TYPE_SLAVE_KEYBOARD: {
            QInputDevice *master = const_cast<QInputDevice *>(QInputDevicePrivate::fromId(deviceInfo->attachment));
            Q_ASSERT(master);
            QWindowSystemInterface::registerInputDevice(new QInputDevice(
                QString::fromUtf8(xcb_input_xi_device_info_name(deviceInfo)), deviceInfo->deviceid,
                QInputDevice::DeviceType::Keyboard, master->seatName(), master));
        } break;
        case XCB_INPUT_DEVICE_TYPE_FLOATING_SLAVE:
            break;
        }
    }

    if (m_xiMasterPointerIds.size() > 1)
        qCDebug(lcQpaXInputDevices) << "multi-pointer X detected";
}

QXcbConnection::TouchDeviceData *QXcbConnection::touchDeviceForId(int id)
{
    TouchDeviceData *dev = nullptr;
    if (m_touchDevices.contains(id))
        dev = &m_touchDevices[id];
    return dev;
}

QXcbConnection::TouchDeviceData *QXcbConnection::populateTouchDevices(void *info, QXcbScrollingDevicePrivate *scrollingDeviceP)
{
    auto *deviceInfo = reinterpret_cast<xcb_input_xi_device_info_t *>(info);
    QPointingDevice::Capabilities caps;
    QInputDevice::DeviceType type = QInputDevice::DeviceType::Unknown;
    int maxTouchPoints = 1;
    bool isTouchDevice = false;
    bool hasRelativeCoords = false;
    TouchDeviceData dev;
    auto classes_it = xcb_input_xi_device_info_classes_iterator(deviceInfo);
    for (; classes_it.rem; xcb_input_device_class_next(&classes_it)) {
        xcb_input_device_class_t *classinfo = classes_it.data;
        switch (classinfo->type) {
        case XCB_INPUT_DEVICE_CLASS_TYPE_TOUCH: {
            auto *tci = reinterpret_cast<xcb_input_touch_class_t *>(classinfo);
            maxTouchPoints = tci->num_touches;
            qCDebug(lcQpaXInputDevices, "   has touch class with mode %d", tci->mode);
            switch (tci->mode) {
            case XCB_INPUT_TOUCH_MODE_DEPENDENT:
                type = QInputDevice::DeviceType::TouchPad;
                break;
            case XCB_INPUT_TOUCH_MODE_DIRECT:
                type = QInputDevice::DeviceType::TouchScreen;
                break;
            }
            break;
        }
        case XCB_INPUT_DEVICE_CLASS_TYPE_VALUATOR: {
            auto *vci = reinterpret_cast<xcb_input_valuator_class_t *>(classinfo);
            const QXcbAtom::Atom valuatorAtom = qatom(vci->label);
            if (valuatorAtom < QXcbAtom::NAtoms) {
                TouchDeviceData::ValuatorClassInfo info;
                info.min = fixed3232ToReal(vci->min);
                info.max = fixed3232ToReal(vci->max);
                info.number = vci->number;
                info.label = valuatorAtom;
                dev.valuatorInfo.append(info);
            }
            // Some devices (mice) report a resolution of 0; they will be excluded later,
            // for now just prevent a division by zero
            const int vciResolution = vci->resolution ? vci->resolution : 1;
            if (valuatorAtom == QXcbAtom::AbsMTPositionX)
                caps |= QInputDevice::Capability::Position | QInputDevice::Capability::NormalizedPosition;
            else if (valuatorAtom == QXcbAtom::AbsMTTouchMajor)
                caps |= QInputDevice::Capability::Area;
            else if (valuatorAtom == QXcbAtom::AbsMTOrientation)
                dev.providesTouchOrientation = true;
            else if (valuatorAtom == QXcbAtom::AbsMTPressure || valuatorAtom == QXcbAtom::AbsPressure)
                caps |= QInputDevice::Capability::Pressure;
            else if (valuatorAtom == QXcbAtom::RelX) {
                hasRelativeCoords = true;
                dev.size.setWidth((fixed3232ToReal(vci->max) - fixed3232ToReal(vci->min)) * 1000.0 / vciResolution);
            } else if (valuatorAtom == QXcbAtom::RelY) {
                hasRelativeCoords = true;
                dev.size.setHeight((fixed3232ToReal(vci->max) - fixed3232ToReal(vci->min)) * 1000.0 / vciResolution);
            } else if (valuatorAtom == QXcbAtom::AbsX) {
                caps |= QInputDevice::Capability::Position;
                dev.size.setWidth((fixed3232ToReal(vci->max) - fixed3232ToReal(vci->min)) * 1000.0 / vciResolution);
            } else if (valuatorAtom == QXcbAtom::AbsY) {
                caps |= QInputDevice::Capability::Position;
                dev.size.setHeight((fixed3232ToReal(vci->max) - fixed3232ToReal(vci->min)) * 1000.0 / vciResolution);
            } else if (valuatorAtom == QXcbAtom::RelVertWheel || valuatorAtom == QXcbAtom::RelHorizWheel) {
                caps |= QInputDevice::Capability::Scroll;
            }
            break;
        }
        default:
            break;
        }
    }
    if (type == QInputDevice::DeviceType::Unknown && caps && hasRelativeCoords) {
        type = QInputDevice::DeviceType::TouchPad;
        if (dev.size.width() < 10 || dev.size.height() < 10 ||
                dev.size.width() > 10000 || dev.size.height() > 10000)
            dev.size = QSizeF(130, 110);
    }
    if (!isAtLeastXI22() || type == QInputDevice::DeviceType::TouchPad)
        caps |= QInputDevice::Capability::MouseEmulation;

    if (type == QInputDevice::DeviceType::TouchScreen || type == QInputDevice::DeviceType::TouchPad) {
        QInputDevice *master = const_cast<QInputDevice *>(QInputDevicePrivate::fromId(deviceInfo->attachment));
        Q_ASSERT(master);
        if (scrollingDeviceP) {
            // valuators were already discovered in QXcbConnection::xi2SetupSlavePointerDevice, so just finish initialization
            scrollingDeviceP->deviceType = type;
            scrollingDeviceP->pointerType = QPointingDevice::PointerType::Finger;
            scrollingDeviceP->capabilities |= caps;
            scrollingDeviceP->maximumTouchPoints = maxTouchPoints;
            scrollingDeviceP->buttonCount = 3;
            scrollingDeviceP->seatName = master->seatName();
            dev.qtTouchDevice = new QXcbScrollingDevice(*scrollingDeviceP, master);
            if (Q_UNLIKELY(!caps.testFlag(QInputDevice::Capability::Scroll)))
                qCDebug(lcQpaXInputDevices) << "unexpectedly missing RelVert/HorizWheel atoms for touchpad with scroll capability" << dev.qtTouchDevice;
        } else {
            dev.qtTouchDevice = new QPointingDevice(QString::fromUtf8(xcb_input_xi_device_info_name(deviceInfo),
                                                                      xcb_input_xi_device_info_name_length(deviceInfo)),
                                                    deviceInfo->deviceid,
                                                    type, QPointingDevice::PointerType::Finger, caps, maxTouchPoints, 0,
                                                    master->seatName(), QPointingDeviceUniqueId(), master);
        }
        if (caps != 0)
            QWindowSystemInterface::registerInputDevice(dev.qtTouchDevice);
        m_touchDevices[deviceInfo->deviceid] = dev;
        isTouchDevice = true;
    }

    return isTouchDevice ? &m_touchDevices[deviceInfo->deviceid] : nullptr;
}

static inline qreal fixed1616ToReal(xcb_input_fp1616_t val)
{
    return qreal(val) / 0x10000;
}

void QXcbConnection::xi2HandleEvent(xcb_ge_event_t *event)
{
    auto *xiEvent = reinterpret_cast<qt_xcb_input_device_event_t *>(event);
    int sourceDeviceId = xiEvent->deviceid; // may be the master id
    qt_xcb_input_device_event_t *xiDeviceEvent = nullptr;
    xcb_input_enter_event_t *xiEnterEvent = nullptr;
    QXcbWindowEventListener *eventListener = nullptr;

    switch (xiEvent->event_type) {
    case XCB_INPUT_BUTTON_PRESS:
    case XCB_INPUT_BUTTON_RELEASE:
    case XCB_INPUT_MOTION:
    case XCB_INPUT_TOUCH_BEGIN:
    case XCB_INPUT_TOUCH_UPDATE:
    case XCB_INPUT_TOUCH_END:
    {
        xiDeviceEvent = xiEvent;
        eventListener = windowEventListenerFromId(xiDeviceEvent->event);
        sourceDeviceId = xiDeviceEvent->sourceid; // use the actual device id instead of the master
        break;
    }
    case XCB_INPUT_ENTER:
    case XCB_INPUT_LEAVE: {
        xiEnterEvent = reinterpret_cast<xcb_input_enter_event_t *>(event);
        eventListener = windowEventListenerFromId(xiEnterEvent->event);
        sourceDeviceId = xiEnterEvent->sourceid; // use the actual device id instead of the master
        break;
    }
    case XCB_INPUT_HIERARCHY:
        xi2HandleHierarchyEvent(event);
        return;
    case XCB_INPUT_DEVICE_CHANGED:
        xi2HandleDeviceChangedEvent(event);
        return;
    default:
        break;
    }

    if (eventListener) {
        if (eventListener->handleNativeEvent(reinterpret_cast<xcb_generic_event_t *>(event)))
            return;
    }

#if QT_CONFIG(tabletevent)
    if (!xiEnterEvent) {
        // TODO we need the UID here; tabletDataForDevice doesn't have enough to go on (?)
        QXcbConnection::TabletData *tablet = tabletDataForDevice(sourceDeviceId);
        if (tablet && xi2HandleTabletEvent(event, tablet))
            return;
    }
#endif // QT_CONFIG(tabletevent)

    if (auto device = QPointingDevicePrivate::pointingDeviceById(sourceDeviceId))
        xi2HandleScrollEvent(event, device);

    if (xiDeviceEvent) {
        switch (xiDeviceEvent->event_type) {
        case XCB_INPUT_BUTTON_PRESS:
        case XCB_INPUT_BUTTON_RELEASE:
        case XCB_INPUT_MOTION:
            if (eventListener && !(xiDeviceEvent->flags & XCB_INPUT_POINTER_EVENT_FLAGS_POINTER_EMULATED))
                eventListener->handleXIMouseEvent(event);
            break;

        case XCB_INPUT_TOUCH_BEGIN:
        case XCB_INPUT_TOUCH_UPDATE:
        case XCB_INPUT_TOUCH_END:
            if (Q_UNLIKELY(lcQpaXInputEvents().isDebugEnabled()))
                qCDebug(lcQpaXInputEvents, "XI2 touch event type %d seq %d detail %d pos %6.1f, %6.1f root pos %6.1f, %6.1f on window %x",
                        event->event_type, xiDeviceEvent->sequence, xiDeviceEvent->detail,
                        fixed1616ToReal(xiDeviceEvent->event_x), fixed1616ToReal(xiDeviceEvent->event_y),
                        fixed1616ToReal(xiDeviceEvent->root_x), fixed1616ToReal(xiDeviceEvent->root_y),xiDeviceEvent->event);
            if (QXcbWindow *platformWindow = platformWindowFromId(xiDeviceEvent->event))
                xi2ProcessTouch(xiDeviceEvent, platformWindow);
            break;
        }
    } else if (xiEnterEvent && eventListener) {
        switch (xiEnterEvent->event_type) {
        case XCB_INPUT_ENTER:
        case XCB_INPUT_LEAVE:
            eventListener->handleXIEnterLeave(event);
            break;
        }
    }
}

bool QXcbConnection::isTouchScreen(int id)
{
    auto device = touchDeviceForId(id);
    return device && device->qtTouchDevice->type() == QInputDevice::DeviceType::TouchScreen;
}

void QXcbConnection::xi2ProcessTouch(void *xiDevEvent, QXcbWindow *platformWindow)
{
    auto *xiDeviceEvent = reinterpret_cast<xcb_input_touch_begin_event_t *>(xiDevEvent);
    TouchDeviceData *dev = touchDeviceForId(xiDeviceEvent->sourceid);
    Q_ASSERT(dev);
    const bool firstTouch = dev->touchPoints.isEmpty();
    if (xiDeviceEvent->event_type == XCB_INPUT_TOUCH_BEGIN) {
        QWindowSystemInterface::TouchPoint tp;
        tp.id = xiDeviceEvent->detail % INT_MAX;
        tp.state = QEventPoint::State::Pressed;
        tp.pressure = -1.0;
        dev->touchPoints[tp.id] = tp;
    }
    QWindowSystemInterface::TouchPoint &touchPoint = dev->touchPoints[xiDeviceEvent->detail];
    QXcbScreen* screen = platformWindow->xcbScreen();
    qreal x = fixed1616ToReal(xiDeviceEvent->root_x);
    qreal y = fixed1616ToReal(xiDeviceEvent->root_y);
    qreal nx = -1.0, ny = -1.0;
    qreal w = 0.0, h = 0.0;
    bool majorAxisIsY = touchPoint.area.height() > touchPoint.area.width();
    for (const TouchDeviceData::ValuatorClassInfo &vci : qAsConst(dev->valuatorInfo)) {
        double value;
        if (!xi2GetValuatorValueIfSet(xiDeviceEvent, vci.number, &value))
            continue;
        if (Q_UNLIKELY(lcQpaXInputEvents().isDebugEnabled()))
            qCDebug(lcQpaXInputEvents, "   valuator %20s value %lf from range %lf -> %lf",
                    atomName(vci.label).constData(), value, vci.min, vci.max);
        if (value > vci.max)
            value = vci.max;
        if (value < vci.min)
            value = vci.min;
        qreal valuatorNormalized = (value - vci.min) / (vci.max - vci.min);
        if (vci.label == QXcbAtom::RelX) {
            nx = valuatorNormalized;
        } else if (vci.label == QXcbAtom::RelY) {
            ny = valuatorNormalized;
        } else if (vci.label == QXcbAtom::AbsX) {
            nx = valuatorNormalized;
        } else if (vci.label == QXcbAtom::AbsY) {
            ny = valuatorNormalized;
        } else if (vci.label == QXcbAtom::AbsMTPositionX) {
            nx = valuatorNormalized;
        } else if (vci.label == QXcbAtom::AbsMTPositionY) {
            ny = valuatorNormalized;
        } else if (vci.label == QXcbAtom::AbsMTTouchMajor) {
            const qreal sw = screen->geometry().width();
            const qreal sh = screen->geometry().height();
            w = valuatorNormalized * qHypot(sw, sh);
        } else if (vci.label == QXcbAtom::AbsMTTouchMinor) {
            const qreal sw = screen->geometry().width();
            const qreal sh = screen->geometry().height();
            h = valuatorNormalized * qHypot(sw, sh);
        } else if (vci.label == QXcbAtom::AbsMTOrientation) {
            // Find the closest axis.
            // 0 corresponds to the Y axis, vci.max to the X axis.
            // Flipping over the Y axis and rotating by 180 degrees
            // don't change the result, so normalize value to range
            // [0, vci.max] first.
            value = qAbs(value);
            while (value > vci.max)
                value -= 2 * vci.max;
            value = qAbs(value);
            majorAxisIsY = value < vci.max - value;
        } else if (vci.label == QXcbAtom::AbsMTPressure || vci.label == QXcbAtom::AbsPressure) {
            touchPoint.pressure = valuatorNormalized;
        }

    }
    // If any value was not updated, use the last-known value.
    if (nx == -1.0) {
        x = touchPoint.area.center().x();
        nx = x / screen->geometry().width();
    }
    if (ny == -1.0) {
        y = touchPoint.area.center().y();
        ny = y / screen->geometry().height();
    }
    if (xiDeviceEvent->event_type != XCB_INPUT_TOUCH_END) {
        if (!dev->providesTouchOrientation) {
            if (w == 0.0)
                w = touchPoint.area.width();
            h = w;
        } else {
            if (w == 0.0)
                w = qMax(touchPoint.area.width(), touchPoint.area.height());
            if (h == 0.0)
                h = qMin(touchPoint.area.width(), touchPoint.area.height());
            if (majorAxisIsY)
                qSwap(w, h);
        }
    }

    switch (xiDeviceEvent->event_type) {
    case XCB_INPUT_TOUCH_BEGIN:
        if (firstTouch) {
            dev->firstPressedPosition = QPointF(x, y);
            dev->firstPressedNormalPosition = QPointF(nx, ny);
        }
        dev->pointPressedPosition.insert(touchPoint.id, QPointF(x, y));

        // Touches must be accepted when we are grabbing touch events. Otherwise the entire sequence
        // will get replayed when the grab ends.
        if (m_xiGrab) {
            xcb_input_xi_allow_events(xcb_connection(), XCB_CURRENT_TIME, xiDeviceEvent->deviceid,
                                      XCB_INPUT_EVENT_MODE_ACCEPT_TOUCH,
                                      xiDeviceEvent->detail, xiDeviceEvent->event);
        }
        break;
    case XCB_INPUT_TOUCH_UPDATE:
        if (dev->qtTouchDevice->type() == QInputDevice::DeviceType::TouchPad && dev->pointPressedPosition.value(touchPoint.id) == QPointF(x, y)) {
            qreal dx = (nx - dev->firstPressedNormalPosition.x()) *
                dev->size.width() * screen->geometry().width() / screen->physicalSize().width();
            qreal dy = (ny - dev->firstPressedNormalPosition.y()) *
                dev->size.height() * screen->geometry().height() / screen->physicalSize().height();
            x = dev->firstPressedPosition.x() + dx;
            y = dev->firstPressedPosition.y() + dy;
            touchPoint.state = QEventPoint::State::Updated;
        } else if (touchPoint.area.center() != QPoint(x, y)) {
            touchPoint.state = QEventPoint::State::Updated;
            if (dev->qtTouchDevice->type() == QInputDevice::DeviceType::TouchPad)
                dev->pointPressedPosition[touchPoint.id] = QPointF(x, y);
        }

        if (dev->qtTouchDevice->type() == QInputDevice::DeviceType::TouchScreen &&
            xiDeviceEvent->event == m_startSystemMoveResizeInfo.window &&
            xiDeviceEvent->sourceid == m_startSystemMoveResizeInfo.deviceid &&
            xiDeviceEvent->detail == m_startSystemMoveResizeInfo.pointid) {
            QXcbWindow *window = platformWindowFromId(m_startSystemMoveResizeInfo.window);
            if (window) {
                xcb_input_xi_allow_events(xcb_connection(), XCB_CURRENT_TIME, xiDeviceEvent->deviceid,
                                          XCB_INPUT_EVENT_MODE_REJECT_TOUCH,
                                          xiDeviceEvent->detail, xiDeviceEvent->event);
                window->doStartSystemMoveResize(QPoint(x, y), m_startSystemMoveResizeInfo.edges);
                m_startSystemMoveResizeInfo.window = XCB_NONE;
            }
        }
        break;
    case XCB_INPUT_TOUCH_END:
        touchPoint.state = QEventPoint::State::Released;
        if (dev->qtTouchDevice->type() == QInputDevice::DeviceType::TouchPad && dev->pointPressedPosition.value(touchPoint.id) == QPointF(x, y)) {
            qreal dx = (nx - dev->firstPressedNormalPosition.x()) *
                dev->size.width() * screen->geometry().width() / screen->physicalSize().width();
            qreal dy = (ny - dev->firstPressedNormalPosition.y()) *
                dev->size.width() * screen->geometry().width() / screen->physicalSize().width();
            x = dev->firstPressedPosition.x() + dx;
            y = dev->firstPressedPosition.y() + dy;
        }
        dev->pointPressedPosition.remove(touchPoint.id);
    }
    touchPoint.area = QRectF(x - w/2, y - h/2, w, h);
    touchPoint.normalPosition = QPointF(nx, ny);

    if (Q_UNLIKELY(lcQpaXInputEvents().isDebugEnabled()))
        qCDebug(lcQpaXInputEvents) << "   touchpoint "  << touchPoint.id << " state " << touchPoint.state << " pos norm " << touchPoint.normalPosition <<
            " area " << touchPoint.area << " pressure " << touchPoint.pressure;
    Qt::KeyboardModifiers modifiers = keyboard()->translateModifiers(xiDeviceEvent->mods.effective);
    QWindowSystemInterface::handleTouchEvent(platformWindow->window(), xiDeviceEvent->time, dev->qtTouchDevice, dev->touchPoints.values(), modifiers);
    if (touchPoint.state == QEventPoint::State::Released)
        // If a touchpoint was released, we can forget it, because the ID won't be reused.
        dev->touchPoints.remove(touchPoint.id);
    else
        // Make sure that we don't send TouchPointPressed/Moved in more than one QTouchEvent
        // with this touch point if the next XI2 event is about a different touch point.
        touchPoint.state = QEventPoint::State::Stationary;
}

bool QXcbConnection::startSystemMoveResizeForTouch(xcb_window_t window, int edges)
{
    QHash<int, TouchDeviceData>::const_iterator devIt = m_touchDevices.constBegin();
    for (; devIt != m_touchDevices.constEnd(); ++devIt) {
        TouchDeviceData deviceData = devIt.value();
        if (deviceData.qtTouchDevice->type() == QInputDevice::DeviceType::TouchScreen) {
            auto pointIt = deviceData.touchPoints.constBegin();
            for (; pointIt != deviceData.touchPoints.constEnd(); ++pointIt) {
                QEventPoint::State state = pointIt.value().state;
                if (state == QEventPoint::State::Updated || state == QEventPoint::State::Pressed || state == QEventPoint::State::Stationary) {
                    m_startSystemMoveResizeInfo.window = window;
                    m_startSystemMoveResizeInfo.deviceid = devIt.key();
                    m_startSystemMoveResizeInfo.pointid = pointIt.key();
                    m_startSystemMoveResizeInfo.edges = edges;
                    return true;
                }
            }
        }
    }
    return false;
}

void QXcbConnection::abortSystemMoveResizeForTouch()
{
    m_startSystemMoveResizeInfo.window = XCB_NONE;
}

bool QXcbConnection::xi2SetMouseGrabEnabled(xcb_window_t w, bool grab)
{
    bool ok = false;

    if (grab) { // grab
        uint32_t mask = XCB_INPUT_XI_EVENT_MASK_BUTTON_PRESS
                | XCB_INPUT_XI_EVENT_MASK_BUTTON_RELEASE
                | XCB_INPUT_XI_EVENT_MASK_MOTION
                | XCB_INPUT_XI_EVENT_MASK_ENTER
                | XCB_INPUT_XI_EVENT_MASK_LEAVE
                | XCB_INPUT_XI_EVENT_MASK_TOUCH_BEGIN
                | XCB_INPUT_XI_EVENT_MASK_TOUCH_UPDATE
                | XCB_INPUT_XI_EVENT_MASK_TOUCH_END;

        for (int id : qAsConst(m_xiMasterPointerIds)) {
            xcb_generic_error_t *error = nullptr;
            auto cookie = xcb_input_xi_grab_device(xcb_connection(), w, XCB_CURRENT_TIME, XCB_CURSOR_NONE, id,
                                                   XCB_INPUT_GRAB_MODE_22_ASYNC, XCB_INPUT_GRAB_MODE_22_ASYNC,
                                                   false, 1, &mask);
            auto *reply = xcb_input_xi_grab_device_reply(xcb_connection(), cookie, &error);
            if (error) {
                qCDebug(lcQpaXInput, "failed to grab events for device %d on window %x"
                                     "(error code %d)", id, w, error->error_code);
                free(error);
            } else {
                // Managed to grab at least one of master pointers, that should be enough
                // to properly dismiss windows that rely on mouse grabbing.
                ok = true;
            }
            free(reply);
        }
    } else { // ungrab
        for (int id : qAsConst(m_xiMasterPointerIds)) {
            auto cookie = xcb_input_xi_ungrab_device_checked(xcb_connection(), XCB_CURRENT_TIME, id);
            xcb_generic_error_t *error = xcb_request_check(xcb_connection(), cookie);
            if (error) {
                qCDebug(lcQpaXInput, "XIUngrabDevice failed - id: %d (error code %d)", id, error->error_code);
                free(error);
            }
        }
        // XIUngrabDevice does not seem to wait for a reply from X server (similar to
        // xcb_ungrab_pointer). Ungrabbing won't fail, unless NoSuchExtension error
        // has occurred due to a programming error somewhere else in the stack. That
        // would mean that things will crash soon anyway.
        ok = true;
    }

    if (ok)
        m_xiGrab = grab;

    return ok;
}

void QXcbConnection::xi2HandleHierarchyEvent(void *event)
{
    auto *xiEvent = reinterpret_cast<xcb_input_hierarchy_event_t *>(event);
    // We only care about hotplugged devices
    if (!(xiEvent->flags & (XCB_INPUT_HIERARCHY_MASK_SLAVE_REMOVED | XCB_INPUT_HIERARCHY_MASK_SLAVE_ADDED)))
        return;

    xi2SetupDevices();
}

void QXcbConnection::xi2HandleDeviceChangedEvent(void *event)
{
    auto *xiEvent = reinterpret_cast<xcb_input_device_changed_event_t *>(event);
    switch (xiEvent->reason) {
    case XCB_INPUT_CHANGE_REASON_DEVICE_CHANGE: {
        auto reply = Q_XCB_REPLY(xcb_input_xi_query_device, xcb_connection(), xiEvent->sourceid);
        if (!reply || reply->num_infos <= 0)
            return;
        auto it = xcb_input_xi_query_device_infos_iterator(reply.get());
        xi2SetupSlavePointerDevice(it.data);
        break;
    }
    case XCB_INPUT_CHANGE_REASON_SLAVE_SWITCH: {
        if (auto *scrollingDevice = scrollingDeviceForId(xiEvent->sourceid))
            xi2UpdateScrollingDevice(scrollingDevice);
        break;
    }
    default:
        qCDebug(lcQpaXInputEvents, "unknown device-changed-event (device %d)", xiEvent->sourceid);
        break;
    }
}

void QXcbConnection::xi2UpdateScrollingDevice(QInputDevice *dev)
{
    QXcbScrollingDevice *scrollDev = qobject_cast<QXcbScrollingDevice *>(dev);
    if (!scrollDev || !scrollDev->capabilities().testFlag(QInputDevice::Capability::Scroll))
        return;
    QXcbScrollingDevicePrivate *scrollingDevice = QXcbScrollingDevice::get(scrollDev);

    auto reply = Q_XCB_REPLY(xcb_input_xi_query_device, xcb_connection(), scrollingDevice->systemId);
    if (!reply || reply->num_infos <= 0) {
        qCDebug(lcQpaXInputDevices, "scrolling device %lld no longer present", scrollingDevice->systemId);
        return;
    }
    QPointF lastScrollPosition;
    if (lcQpaXInputEvents().isDebugEnabled())
        lastScrollPosition = scrollingDevice->lastScrollPosition;

    xcb_input_xi_device_info_t *deviceInfo = xcb_input_xi_query_device_infos_iterator(reply.get()).data;
    auto classes_it = xcb_input_xi_device_info_classes_iterator(deviceInfo);
    for (; classes_it.rem; xcb_input_device_class_next(&classes_it)) {
        xcb_input_device_class_t *classInfo = classes_it.data;
        if (classInfo->type == XCB_INPUT_DEVICE_CLASS_TYPE_VALUATOR) {
            auto *vci = reinterpret_cast<xcb_input_valuator_class_t *>(classInfo);
            const int valuatorAtom = qatom(vci->label);
            if (valuatorAtom == QXcbAtom::RelHorizScroll || valuatorAtom == QXcbAtom::RelHorizWheel)
                scrollingDevice->lastScrollPosition.setX(fixed3232ToReal(vci->value));
            else if (valuatorAtom == QXcbAtom::RelVertScroll || valuatorAtom == QXcbAtom::RelVertWheel)
                scrollingDevice->lastScrollPosition.setY(fixed3232ToReal(vci->value));
        }
    }
    if (Q_UNLIKELY(lcQpaXInputEvents().isDebugEnabled() && lastScrollPosition != scrollingDevice->lastScrollPosition))
        qCDebug(lcQpaXInputEvents, "scrolling device %lld moved from (%f, %f) to (%f, %f)", scrollingDevice->systemId,
                lastScrollPosition.x(), lastScrollPosition.y(),
                scrollingDevice->lastScrollPosition.x(),
                scrollingDevice->lastScrollPosition.y());
}

void QXcbConnection::xi2UpdateScrollingDevices()
{
    const auto &devices = QInputDevice::devices();
    for (const QInputDevice *dev : devices) {
        if (dev->capabilities().testFlag(QInputDevice::Capability::Scroll))
            xi2UpdateScrollingDevice(const_cast<QInputDevice *>(dev));
    }
}

QXcbScrollingDevice *QXcbConnection::scrollingDeviceForId(int id)
{
    const QPointingDevice *dev = QPointingDevicePrivate::pointingDeviceById(id);
    if (!dev|| !dev->capabilities().testFlag(QInputDevice::Capability::Scroll))
        return nullptr;
    return qobject_cast<QXcbScrollingDevice *>(const_cast<QPointingDevice *>(dev));
}

void QXcbConnection::xi2HandleScrollEvent(void *event, const QPointingDevice *dev)
{
    auto *xiDeviceEvent = reinterpret_cast<qt_xcb_input_device_event_t *>(event);

    const QXcbScrollingDevice *scrollDev = qobject_cast<const QXcbScrollingDevice *>(dev);
    if (!scrollDev || !scrollDev->capabilities().testFlag(QInputDevice::Capability::Scroll))
        return;
    const QXcbScrollingDevicePrivate *scrollingDevice = QXcbScrollingDevice::get(scrollDev);

    if (xiDeviceEvent->event_type == XCB_INPUT_MOTION && scrollingDevice->orientations) {
        if (QXcbWindow *platformWindow = platformWindowFromId(xiDeviceEvent->event)) {
            QPoint rawDelta;
            QPoint angleDelta;
            double value;
            if (scrollingDevice->orientations & Qt::Vertical) {
                if (xi2GetValuatorValueIfSet(xiDeviceEvent, scrollingDevice->verticalIndex, &value)) {
                    double delta = scrollingDevice->lastScrollPosition.y() - value;
                    scrollingDevice->lastScrollPosition.setY(value);
                    angleDelta.setY((delta / scrollingDevice->verticalIncrement) * 120);
                    // With most drivers the increment is 1 for wheels.
                    // For libinput it is hardcoded to a useless 15.
                    // For a proper touchpad driver it should be in the same order of magnitude as 120
                    if (scrollingDevice->verticalIncrement > 15)
                        rawDelta.setY(delta);
                    else if (scrollingDevice->verticalIncrement < -15)
                        rawDelta.setY(-delta);
                }
            }
            if (scrollingDevice->orientations & Qt::Horizontal) {
                if (xi2GetValuatorValueIfSet(xiDeviceEvent, scrollingDevice->horizontalIndex, &value)) {
                    double delta = scrollingDevice->lastScrollPosition.x() - value;
                    scrollingDevice->lastScrollPosition.setX(value);
                    angleDelta.setX((delta / scrollingDevice->horizontalIncrement) * 120);
                    // See comment under vertical
                    if (scrollingDevice->horizontalIncrement > 15)
                        rawDelta.setX(delta);
                    else if (scrollingDevice->horizontalIncrement < -15)
                        rawDelta.setX(-delta);
                }
            }
            if (!angleDelta.isNull()) {
                QPoint local(fixed1616ToReal(xiDeviceEvent->event_x), fixed1616ToReal(xiDeviceEvent->event_y));
                QPoint global(fixed1616ToReal(xiDeviceEvent->root_x), fixed1616ToReal(xiDeviceEvent->root_y));
                Qt::KeyboardModifiers modifiers = keyboard()->translateModifiers(xiDeviceEvent->mods.effective);
                if (modifiers & Qt::AltModifier) {
                    angleDelta = angleDelta.transposed();
                    rawDelta = rawDelta.transposed();
                }
                qCDebug(lcQpaXInputEvents) << "scroll wheel from device" << scrollingDevice->systemId
                                           << "@ window pos" << local << "delta px" << rawDelta << "angle" << angleDelta;
                QWindowSystemInterface::handleWheelEvent(platformWindow->window(), xiDeviceEvent->time, dev,
                                                         local, global, rawDelta, angleDelta, modifiers);
            }
        }
    } else if (xiDeviceEvent->event_type == XCB_INPUT_BUTTON_RELEASE && scrollingDevice->legacyOrientations) {
        if (QXcbWindow *platformWindow = platformWindowFromId(xiDeviceEvent->event)) {
            QPoint angleDelta;
            if (scrollingDevice->legacyOrientations & Qt::Vertical) {
                if (xiDeviceEvent->detail == 4)
                    angleDelta.setY(120);
                else if (xiDeviceEvent->detail == 5)
                    angleDelta.setY(-120);
            }
            if (scrollingDevice->legacyOrientations & Qt::Horizontal) {
                if (xiDeviceEvent->detail == 6)
                    angleDelta.setX(120);
                else if (xiDeviceEvent->detail == 7)
                    angleDelta.setX(-120);
            }
            if (!angleDelta.isNull()) {
                QPoint local(fixed1616ToReal(xiDeviceEvent->event_x), fixed1616ToReal(xiDeviceEvent->event_y));
                QPoint global(fixed1616ToReal(xiDeviceEvent->root_x), fixed1616ToReal(xiDeviceEvent->root_y));
                Qt::KeyboardModifiers modifiers = keyboard()->translateModifiers(xiDeviceEvent->mods.effective);
                if (modifiers & Qt::AltModifier)
                    angleDelta = angleDelta.transposed();
                qCDebug(lcQpaXInputEvents) << "scroll wheel (button" << xiDeviceEvent->detail << ") @ window pos" << local << "delta angle" << angleDelta;
                QWindowSystemInterface::handleWheelEvent(platformWindow->window(), xiDeviceEvent->time, dev,
                                                         local, global, QPoint(), angleDelta, modifiers);
            }
        }
    }
}

static int xi2ValuatorOffset(const unsigned char *maskPtr, int maskLen, int number)
{
    int offset = 0;
    for (int i = 0; i < maskLen; i++) {
        if (number < 8) {
            if ((maskPtr[i] & (1 << number)) == 0)
                return -1;
        }
        for (int j = 0; j < 8; j++) {
            if (j == number)
                return offset;
            if (maskPtr[i] & (1 << j))
                offset++;
        }
        number -= 8;
    }
    return -1;
}

bool QXcbConnection::xi2GetValuatorValueIfSet(const void *event, int valuatorNum, double *value)
{
    auto *xideviceevent = static_cast<const qt_xcb_input_device_event_t *>(event);
    auto *buttonsMaskAddr = reinterpret_cast<const unsigned char *>(&xideviceevent[1]);
    auto *valuatorsMaskAddr = buttonsMaskAddr + xideviceevent->buttons_len * 4;
    auto *valuatorsValuesAddr = reinterpret_cast<const xcb_input_fp3232_t *>(valuatorsMaskAddr + xideviceevent->valuators_len * 4);

    int valuatorOffset = xi2ValuatorOffset(valuatorsMaskAddr, xideviceevent->valuators_len, valuatorNum);
    if (valuatorOffset < 0)
        return false;

    *value = valuatorsValuesAddr[valuatorOffset].integral;
    *value += ((double)valuatorsValuesAddr[valuatorOffset].frac / (1 << 16) / (1 << 16));
    return true;
}

Qt::MouseButton QXcbConnection::xiToQtMouseButton(uint32_t b)
{
    switch (b) {
    case 1: return Qt::LeftButton;
    case 2: return Qt::MiddleButton;
    case 3: return Qt::RightButton;
    // 4-7 are for scrolling
    default: break;
    }
    if (b >= 8 && b <= Qt::MaxMouseButton)
        return static_cast<Qt::MouseButton>(Qt::BackButton << (b - 8));
    return Qt::NoButton;
}

#if QT_CONFIG(tabletevent)
bool QXcbConnection::xi2HandleTabletEvent(const void *event, TabletData *tabletData)
{
    bool handled = true;
    const auto *xiDeviceEvent = reinterpret_cast<const qt_xcb_input_device_event_t *>(event);

    switch (xiDeviceEvent->event_type) {
    case XCB_INPUT_BUTTON_PRESS: {
        Qt::MouseButton b = xiToQtMouseButton(xiDeviceEvent->detail);
        tabletData->buttons |= b;
        xi2ReportTabletEvent(event, tabletData);
        break;
    }
    case XCB_INPUT_BUTTON_RELEASE: {
        Qt::MouseButton b = xiToQtMouseButton(xiDeviceEvent->detail);
        tabletData->buttons ^= b;
        xi2ReportTabletEvent(event, tabletData);
        break;
    }
    case XCB_INPUT_MOTION:
        xi2ReportTabletEvent(event, tabletData);
        break;
    case XCB_INPUT_PROPERTY: {
        // This is the wacom driver's way of reporting tool proximity.
        // The evdev driver doesn't do it this way.
        const auto *ev = reinterpret_cast<const xcb_input_property_event_t *>(event);
        if (ev->what == XCB_INPUT_PROPERTY_FLAG_MODIFIED) {
            if (ev->property == atom(QXcbAtom::WacomSerialIDs)) {
                enum WacomSerialIndex {
                    _WACSER_USB_ID = 0,
                    _WACSER_LAST_TOOL_SERIAL,
                    _WACSER_LAST_TOOL_ID,
                    _WACSER_TOOL_SERIAL,
                    _WACSER_TOOL_ID,
                    _WACSER_COUNT
                };

                auto reply = Q_XCB_REPLY(xcb_input_xi_get_property, xcb_connection(), tabletData->deviceId, 0,
                                         ev->property, XCB_GET_PROPERTY_TYPE_ANY, 0, 100);
                if (reply) {
                    if (reply->type == atom(QXcbAtom::INTEGER) && reply->format == 32 && reply->num_items == _WACSER_COUNT) {
                        quint32 *ptr = reinterpret_cast<quint32 *>(xcb_input_xi_get_property_items(reply.get()));
                        quint32 tool = ptr[_WACSER_TOOL_ID];
                        // Workaround for http://sourceforge.net/p/linuxwacom/bugs/246/
                        // e.g. on Thinkpad Helix, tool ID will be 0 and serial will be 1
                        if (!tool && ptr[_WACSER_TOOL_SERIAL])
                            tool = ptr[_WACSER_TOOL_SERIAL];

                        // The property change event informs us which tool is in proximity or which one left proximity.
                        if (tool) {
                            const QPointingDevice *dev = tabletToolInstance(nullptr, tabletData->name,
                                    tabletData->deviceId, ptr[_WACSER_USB_ID], tool,
                                    qint64(ptr[_WACSER_TOOL_SERIAL])); // TODO look up the master
                            tabletData->inProximity = true;
                            tabletData->tool = dev->type();
                            tabletData->serialId = qint64(ptr[_WACSER_TOOL_SERIAL]);
                            QWindowSystemInterface::handleTabletEnterProximityEvent(ev->time,
                                int(tabletData->tool), int(tabletData->pointerType), tabletData->serialId);
                        } else {
                            tool = ptr[_WACSER_LAST_TOOL_ID];
                            // Workaround for http://sourceforge.net/p/linuxwacom/bugs/246/
                            // e.g. on Thinkpad Helix, tool ID will be 0 and serial will be 1
                            if (!tool)
                                tool = ptr[_WACSER_LAST_TOOL_SERIAL];
                            const QInputDevice *dev = QInputDevicePrivate::fromId(tabletData->deviceId);
                            Q_ASSERT(dev);
                            tabletData->tool = dev->type();
                            tabletData->inProximity = false;
                            tabletData->serialId = qint64(ptr[_WACSER_LAST_TOOL_SERIAL]);
                            // TODO why doesn't it just take QPointingDevice*
                            QWindowSystemInterface::handleTabletLeaveProximityEvent(ev->time,
                                int(tabletData->tool), int(tabletData->pointerType), tabletData->serialId);
                        }
                        // TODO maybe have a hash of tabletData->deviceId to device data so we can
                        // look up the tablet name here, and distinguish multiple tablets
                        if (Q_UNLIKELY(lcQpaXInputEvents().isDebugEnabled()))
                            qCDebug(lcQpaXInputDevices, "XI2 proximity change on tablet %d %s (USB %x): last tool: %x id %x current tool: %x id %x %s",
                                    tabletData->deviceId, qPrintable(tabletData->name), ptr[_WACSER_USB_ID],
                                    ptr[_WACSER_LAST_TOOL_SERIAL], ptr[_WACSER_LAST_TOOL_ID],
                                    ptr[_WACSER_TOOL_SERIAL], ptr[_WACSER_TOOL_ID], toolName(tabletData->tool));
                    }
                }
            }
        }
        break;
    }
    default:
        handled = false;
        break;
    }

    return handled;
}

inline qreal scaleOneValuator(qreal normValue, qreal screenMin, qreal screenSize)
{
    return screenMin + normValue * screenSize;
}

// TODO QPointingDevice not TabletData
void QXcbConnection::xi2ReportTabletEvent(const void *event, TabletData *tabletData)
{
    auto *ev = reinterpret_cast<const qt_xcb_input_device_event_t *>(event);
    QXcbWindow *xcbWindow = platformWindowFromId(ev->event);
    if (!xcbWindow)
        return;
    QWindow *window = xcbWindow->window();
    const Qt::KeyboardModifiers modifiers = keyboard()->translateModifiers(ev->mods.effective);
    QPointF local(fixed1616ToReal(ev->event_x), fixed1616ToReal(ev->event_y));
    QPointF global(fixed1616ToReal(ev->root_x), fixed1616ToReal(ev->root_y));
    double pressure = 0, rotation = 0, tangentialPressure = 0;
    int xTilt = 0, yTilt = 0;
    static const bool useValuators = !qEnvironmentVariableIsSet("QT_XCB_TABLET_LEGACY_COORDINATES");

    // Valuators' values are relative to the physical size of the current virtual
    // screen. Therefore we cannot use QScreen/QWindow geometry and should use
    // QPlatformWindow/QPlatformScreen instead.
    QRect physicalScreenArea;
    if (Q_LIKELY(useValuators)) {
        const QList<QPlatformScreen *> siblings = window->screen()->handle()->virtualSiblings();
        for (const QPlatformScreen *screen : siblings)
            physicalScreenArea |= screen->geometry();
    }

    for (QHash<int, TabletData::ValuatorClassInfo>::iterator it = tabletData->valuatorInfo.begin(),
            ite = tabletData->valuatorInfo.end(); it != ite; ++it) {
        int valuator = it.key();
        TabletData::ValuatorClassInfo &classInfo(it.value());
        xi2GetValuatorValueIfSet(event, classInfo.number, &classInfo.curVal);
        double normalizedValue = (classInfo.curVal - classInfo.minVal) / (classInfo.maxVal - classInfo.minVal);
        switch (valuator) {
        case QXcbAtom::AbsX:
            if (Q_LIKELY(useValuators)) {
                const qreal value = scaleOneValuator(normalizedValue, physicalScreenArea.x(), physicalScreenArea.width());
                global.setX(value);
                local.setX(xcbWindow->mapFromGlobalF(global).x());
            }
            break;
        case QXcbAtom::AbsY:
            if (Q_LIKELY(useValuators)) {
                qreal value = scaleOneValuator(normalizedValue, physicalScreenArea.y(), physicalScreenArea.height());
                global.setY(value);
                local.setY(xcbWindow->mapFromGlobalF(global).y());
            }
            break;
        case QXcbAtom::AbsPressure:
            pressure = normalizedValue;
            break;
        case QXcbAtom::AbsTiltX:
            xTilt = classInfo.curVal;
            break;
        case QXcbAtom::AbsTiltY:
            yTilt = classInfo.curVal;
            break;
        case QXcbAtom::AbsWheel:
            switch (tabletData->tool) {
            case QInputDevice::DeviceType::Airbrush:
                tangentialPressure = normalizedValue * 2.0 - 1.0; // Convert 0..1 range to -1..+1 range
                break;
            case QInputDevice::DeviceType::Stylus:
                rotation = normalizedValue * 360.0 - 180.0; // Convert 0..1 range to -180..+180 degrees
                break;
            default:    // Other types of styli do not use this valuator
                break;
            }
            break;
        default:
            break;
        }
    }

    if (Q_UNLIKELY(lcQpaXInputEvents().isDebugEnabled()))
        qCDebug(lcQpaXInputEvents, "XI2 event on tablet %d with tool %s %llx type %s seq %d detail %d time %d "
            "pos %6.1f, %6.1f root pos %6.1f, %6.1f buttons 0x%x pressure %4.2lf tilt %d, %d rotation %6.2lf modifiers 0x%x",
            tabletData->deviceId, toolName(tabletData->tool), tabletData->serialId, pointerTypeName(tabletData->pointerType),
            ev->sequence, ev->detail, ev->time,
            local.x(), local.y(), global.x(), global.y(),
            (int)tabletData->buttons, pressure, xTilt, yTilt, rotation, (int)modifiers);

    QWindowSystemInterface::handleTabletEvent(window, ev->time, local, global,
                                              int(tabletData->tool), int(tabletData->pointerType),
                                              tabletData->buttons, pressure,
                                              xTilt, yTilt, tangentialPressure,
                                              rotation, 0, tabletData->serialId, modifiers);
}

QXcbConnection::TabletData *QXcbConnection::tabletDataForDevice(int id)
{
    for (int i = 0; i < m_tabletData.count(); ++i) {
        if (m_tabletData.at(i).deviceId == id)
            return &m_tabletData[i];
    }
    return nullptr;
}

#endif // QT_CONFIG(tabletevent)
