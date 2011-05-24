/****************************************************************************
**
** Copyright (C) 2011 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the test suite of the Qt Toolkit.
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
** $QT_END_LICENSE$
**
****************************************************************************/


#include <QtTest/QtTest>

#include <qgraphicsitemanimation.h>
#include <QtCore/qtimeline.h>
#include <QtGui/qmatrix.h>

//TESTED_CLASS=
//TESTED_FILES=

class tst_QGraphicsItemAnimation : public QObject
{
    Q_OBJECT

private slots:
    void construction();
    void linearMove();
    void linearRotation();
    void checkReturnedLists();
    void overwriteValueForStep();
    void setTimeLine();
};

void tst_QGraphicsItemAnimation::construction()
{
    QGraphicsItemAnimation animation;
    QVERIFY(!animation.item());
    QVERIFY(!animation.timeLine());
    QCOMPARE(animation.posAt(0), QPointF());
    QCOMPARE(animation.posAt(0.5), QPointF());
    QCOMPARE(animation.posAt(1), QPointF());
    QCOMPARE(animation.matrixAt(0), QMatrix());
    QCOMPARE(animation.matrixAt(0.5), QMatrix());
    QCOMPARE(animation.matrixAt(1), QMatrix());
    QCOMPARE(animation.rotationAt(0), qreal(0.0));
    QCOMPARE(animation.rotationAt(0.5), qreal(0.0));
    QCOMPARE(animation.rotationAt(1), qreal(0.0));
    QCOMPARE(animation.xTranslationAt(0), qreal(0.0));
    QCOMPARE(animation.xTranslationAt(0.5), qreal(0.0));
    QCOMPARE(animation.xTranslationAt(1), qreal(0.0));
    QCOMPARE(animation.yTranslationAt(0), qreal(0.0));
    QCOMPARE(animation.yTranslationAt(0.5), qreal(0.0));
    QCOMPARE(animation.yTranslationAt(1), qreal(0.0));
    QCOMPARE(animation.verticalScaleAt(0), qreal(1.0));
    QCOMPARE(animation.horizontalScaleAt(0), qreal(1.0));
    QCOMPARE(animation.verticalShearAt(0), qreal(0.0));
    QCOMPARE(animation.horizontalShearAt(0), qreal(0.0));
    animation.clear(); // don't crash
}

void tst_QGraphicsItemAnimation::linearMove()
{
    QGraphicsItemAnimation animation;

    for (int i = 0; i <= 10; ++i) {
        QCOMPARE(animation.posAt(i / 10.0).x(), qreal(0));
        QCOMPARE(animation.posAt(i / 10.0).y(), qreal(0));
    }

    animation.setPosAt(1, QPointF(10, -10));

    for (int i = 0; i <= 10; ++i) {
        QCOMPARE(animation.posAt(i / 10.0).x(), qreal(i));
        QCOMPARE(animation.posAt(i / 10.0).y(), qreal(-i));
    }

    animation.setPosAt(2, QPointF(10, -10));

    QCOMPARE(animation.posAt(11).x(), qreal(10));
}

void tst_QGraphicsItemAnimation::linearRotation()
{
    QGraphicsItemAnimation animation;
    animation.setRotationAt(1, 1);

    for (int i = 0; i <= 10; ++i)
        QCOMPARE(animation.rotationAt(i / 10.0), qreal(i / 10.0));
}

void tst_QGraphicsItemAnimation::checkReturnedLists()
{
    QGraphicsItemAnimation animation;

    animation.setPosAt(1.0, QPointF(10, -10));
    animation.setPosAt(0.5, QPointF(5, -5));

    animation.setRotationAt(0.3, 2.3);
    animation.setTranslationAt(0.3, 15, 15);
    animation.setScaleAt(0.3, 2.5, 1.8);
    animation.setShearAt(0.3, 5, 5);

    QCOMPARE(animation.posList().at(0), (QPair<qreal, QPointF>(0.5, QPointF(5, -5))));
    QCOMPARE(animation.posList().at(1), (QPair<qreal, QPointF>(1.0, QPointF(10, -10))));
    QCOMPARE(animation.rotationList().at(0), (QPair<qreal, qreal>(0.3, 2.3)));
    QCOMPARE(animation.translationList().at(0), (QPair<qreal, QPointF>(0.3, QPointF(15, 15))));
    QCOMPARE(animation.scaleList().at(0), (QPair<qreal, QPointF>(0.3, QPointF(2.5, 1.8))));
    QCOMPARE(animation.shearList().at(0), (QPair<qreal, QPointF>(0.3, QPointF(5, 5))));

    QCOMPARE(animation.posList().size(), 2);
    QCOMPARE(animation.rotationList().size(), 1);
    QCOMPARE(animation.translationList().size(), 1);
    QCOMPARE(animation.scaleList().size(), 1);
    QCOMPARE(animation.shearList().size(), 1);
}

void tst_QGraphicsItemAnimation::overwriteValueForStep()
{
    QGraphicsItemAnimation animation;

    for (int i=0; i<3; i++){
        animation.setPosAt(0.3, QPointF(3, -3.1));
        animation.setRotationAt(0.3, 2.3);
        animation.setTranslationAt(0.3, 15, 15);
        animation.setScaleAt(0.3, 2.5, 1.8);
        animation.setShearAt(0.3, 5, 5);

        QCOMPARE(animation.posList().size(), 1);
        QCOMPARE(animation.rotationList().size(), 1);
        QCOMPARE(animation.translationList().size(), 1);
        QCOMPARE(animation.scaleList().size(), 1);
        QCOMPARE(animation.shearList().size(), 1);
    }
}

void tst_QGraphicsItemAnimation::setTimeLine()
{
    QGraphicsItemAnimation animation;
    QCOMPARE(animation.timeLine(), (QTimeLine *)0);

    QPointer<QTimeLine> line1 = new QTimeLine;
    animation.setTimeLine(line1);
    QCOMPARE(animation.timeLine(), (QTimeLine *)line1);
    animation.setTimeLine(line1);
    QVERIFY(line1);
    QCOMPARE(animation.timeLine(), (QTimeLine *)line1);

    animation.setTimeLine(0);
    QCOMPARE(animation.timeLine(), (QTimeLine *)0);
    QVERIFY(!line1);

    QTimeLine *line2 = new QTimeLine;
    animation.setTimeLine(line2);
    QCOMPARE(animation.timeLine(), (QTimeLine *)line2);

    delete line2;
    QCOMPARE(animation.timeLine(), (QTimeLine *)0);
}

QTEST_MAIN(tst_QGraphicsItemAnimation)
#include "tst_qgraphicsitemanimation.moc"
