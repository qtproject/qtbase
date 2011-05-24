/****************************************************************************
**
** Copyright (C) 2011 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the QtGui module of the Qt Toolkit.
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

#include "qglobal.h"

#if !defined(QT_NO_RAWFONT)

#include "qglyphrun.h"
#include "qglyphrun_p.h"

QT_BEGIN_NAMESPACE

/*!
    \class QGlyphRun
    \brief The QGlyphRun class provides direct access to the internal glyphs in a font.
    \since 4.8

    \ingroup text
    \mainclass

    When Qt displays a string of text encoded in Unicode, it will first convert the Unicode points
    into a list of glyph indexes and a list of positions based on one or more fonts. The Unicode
    representation of the text and the QFont object will in this case serve as a convenient
    abstraction that hides the details of what actually takes place when displaying the text
    on-screen. For instance, by the time the text actually reaches the screen, it may be represented
    by a set of fonts in addition to the one specified by the user, e.g. in case the originally
    selected font did not support all the writing systems contained in the text.

    Under certain circumstances, it can be useful as an application developer to have more low-level
    control over which glyphs in a specific font are drawn to the screen. This could for instance
    be the case in applications that use an external font engine and text shaper together with Qt.
    QGlyphRun provides an interface to the raw data needed to get text on the screen. It
    contains a list of glyph indexes, a position for each glyph and a font.

    It is the user's responsibility to ensure that the selected font actually contains the
    provided glyph indexes.

    QTextLayout::glyphRuns() or QTextFragment::glyphRuns() can be used to convert unicode encoded
    text into a list of QGlyphRun objects, and QPainter::drawGlyphRun() can be used to draw the
    glyphs.

    \note Please note that QRawFont is considered local to the thread in which it is constructed.
    This in turn means that a new QRawFont will have to be created and set on the QGlyphRun if it is
    moved to a different thread. If the QGlyphRun contains a reference to a QRawFont from a different
    thread than the current, it will not be possible to draw the glyphs using a QPainter, as the
    QRawFont is considered invalid and inaccessible in this case.
*/


/*!
    Constructs an empty QGlyphRun object.
*/
QGlyphRun::QGlyphRun() : d(new QGlyphRunPrivate)
{
}

/*!
    Constructs a QGlyphRun object which is a copy of \a other.
*/
QGlyphRun::QGlyphRun(const QGlyphRun &other)
{
    d = other.d;
}

/*!
    Destroys the QGlyphRun.
*/
QGlyphRun::~QGlyphRun()
{
    // Required for QExplicitlySharedDataPointer
}

/*!
    \internal
*/
void QGlyphRun::detach()
{
    if (d->ref != 1)
        d.detach();
}

/*!
    Assigns \a other to this QGlyphRun object.
*/
QGlyphRun &QGlyphRun::operator=(const QGlyphRun &other)
{
    d = other.d;
    return *this;
}

/*!
    Compares \a other to this QGlyphRun object. Returns true if the list of glyph indexes,
    the list of positions and the font are all equal, otherwise returns false.
*/
bool QGlyphRun::operator==(const QGlyphRun &other) const
{
    return ((d == other.d)
            || (d->glyphIndexes == other.d->glyphIndexes
                && d->glyphPositions == other.d->glyphPositions
                && d->overline == other.d->overline
                && d->underline == other.d->underline
                && d->strikeOut == other.d->strikeOut
                && d->rawFont == other.d->rawFont));
}

/*!
    Compares \a other to this QGlyphRun object. Returns true if any of the list of glyph
    indexes, the list of positions or the font are different, otherwise returns false.
*/
bool QGlyphRun::operator!=(const QGlyphRun &other) const
{
    return !(*this == other);
}

/*!
    \internal

    Adds together the lists of glyph indexes and positions in \a other and this QGlyphRun
    object and returns the result. The font in the returned QGlyphRun will be the same as in
    this QGlyphRun object.
*/
QGlyphRun QGlyphRun::operator+(const QGlyphRun &other) const
{
    QGlyphRun ret(*this);
    ret += other;
    return ret;
}

/*!
    \internal

    Appends the glyph indexes and positions in \a other to this QGlyphRun object and returns
    a reference to the current object.
*/
QGlyphRun &QGlyphRun::operator+=(const QGlyphRun &other)
{
    detach();

    d->glyphIndexes += other.d->glyphIndexes;
    d->glyphPositions += other.d->glyphPositions;

    return *this;
}

/*!
    Returns the font selected for this QGlyphRun object.

    \sa setRawFont()
*/
QRawFont QGlyphRun::rawFont() const
{
    return d->rawFont;
}

/*!
    Sets the font in which to look up the glyph indexes to \a font.

    \sa rawFont(), setGlyphIndexes()
*/
void QGlyphRun::setRawFont(const QRawFont &rawFont)
{
    detach();
    d->rawFont = rawFont;
}

/*!
    Returns the glyph indexes for this QGlyphRun object.

    \sa setGlyphIndexes(), setPositions()
*/
QVector<quint32> QGlyphRun::glyphIndexes() const
{
    return d->glyphIndexes;
}

/*!
    Set the glyph indexes for this QGlyphRun object to \a glyphIndexes. The glyph indexes must
    be valid for the selected font.
*/
void QGlyphRun::setGlyphIndexes(const QVector<quint32> &glyphIndexes)
{
    detach();
    d->glyphIndexes = glyphIndexes;
}

/*!
    Returns the position of the edge of the baseline for each glyph in this set of glyph indexes.
*/
QVector<QPointF> QGlyphRun::positions() const
{
    return d->glyphPositions;
}

/*!
    Sets the positions of the edge of the baseline for each glyph in this set of glyph indexes to
    \a positions.
*/
void QGlyphRun::setPositions(const QVector<QPointF> &positions)
{
    detach();
    d->glyphPositions = positions;
}

/*!
    Clears all data in the QGlyphRun object.
*/
void QGlyphRun::clear()
{
    detach();
    d->glyphPositions = QVector<QPointF>();
    d->glyphIndexes = QVector<quint32>();
    d->rawFont = QRawFont();
    d->strikeOut = false;
    d->overline = false;
    d->underline = false;
}

/*!
   Returns true if this QGlyphRun should be painted with an overline decoration.

   \sa setOverline()
*/
bool QGlyphRun::overline() const
{
    return d->overline;
}

/*!
  Indicates that this QGlyphRun should be painted with an overline decoration if \a overline is true.
  Otherwise the QGlyphRun should be painted with no overline decoration.

  \sa overline()
*/
void QGlyphRun::setOverline(bool overline)
{
    detach();
    d->overline = overline;
}

/*!
   Returns true if this QGlyphRun should be painted with an underline decoration.

   \sa setUnderline()
*/
bool QGlyphRun::underline() const
{
    return d->underline;
}

/*!
  Indicates that this QGlyphRun should be painted with an underline decoration if \a underline is
  true. Otherwise the QGlyphRun should be painted with no underline decoration.

  \sa underline()
*/
void QGlyphRun::setUnderline(bool underline)
{
    detach();
    d->underline = underline;
}

/*!
   Returns true if this QGlyphRun should be painted with a strike out decoration.

   \sa setStrikeOut()
*/
bool QGlyphRun::strikeOut() const
{
    return d->strikeOut;
}

/*!
  Indicates that this QGlyphRun should be painted with an strike out decoration if \a strikeOut is
  true. Otherwise the QGlyphRun should be painted with no strike out decoration.

  \sa strikeOut()
*/
void QGlyphRun::setStrikeOut(bool strikeOut)
{
    detach();
    d->strikeOut = strikeOut;
}

/*!
  Returns the smallest rectangle that contains all glyphs in this QGlyphRun.

  \since 5.0
*/
QRectF QGlyphRun::boundingRect() const
{
    qreal minX, minY, maxX, maxY;

    for (int i=0; i<qMin(d->glyphPositions.size(), d->glyphIndexes.size()); ++i) {
        QRectF glyphRect = d->rawFont.boundingRect(d->glyphIndexes.at(i));
        glyphRect.translate(d->glyphPositions.at(i));

        if (i == 0) {
            minX = glyphRect.left();
            minY = glyphRect.top();
            maxX = glyphRect.right();
            maxY = glyphRect.bottom();
        } else {
            minX = qMin(glyphRect.left(), minX);
            minY = qMin(glyphRect.top(), minY);
            maxX = qMax(glyphRect.right(),maxX);
            maxY = qMax(glyphRect.bottom(), maxY);
        }
    }

    return QRectF(QPointF(minX, minY), QPointF(maxX, maxY));
}

QT_END_NAMESPACE

#endif // QT_NO_RAWFONT
