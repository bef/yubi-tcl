#!/bin/sh

if [ "x$2" = "x" ]; then
	echo "usage: $0 <tmpdir> <name>"
	exit 1
fi

TMPDIR=$1
NAME=$2
CONTROLDIR=`dirname $0`/debian

cd $TMPDIR
mkdir debtmp
cd debtmp
tar zxf ../$NAME.tar.gz
DTMP=debtmp/$NAME

cd $TMPDIR

mkdir -p debian/etc/data
mkdir -p debian/usr/bin
mkdir -p debian/var/cache/yubi

mkdir -p debian/usr/share/tcltk
cp -a $DTMP/yubi debian/usr/share/tcltk/

mkdir -p debian/usr/share/yubi-tcl
cp -a $DTMP/test debian/usr/share/yubi-tcl/
cp -a $DTMP/tools debian/usr/share/yubi-tcl/
cp -a $DTMP/*.tcl debian/usr/share/yubi-tcl/

mkdir -p debian/usr/share/doc/yubi-tcl
cp -a $DTMP/doc debian/usr/share/doc/yubi-tcl/wiki
cp -a $DTMP/etc debian/usr/share/doc/yubi-tcl/
cp -a $DTMP/data debian/usr/share/doc/yubi-tcl/etc/
cp -a $DTMP/examples debian/usr/share/doc/yubi-tcl/
cp -a $CONTROLDIR/copyright debian/usr/share/doc/yubi-tcl/
# cp $CONTROLDIR/changelog debian/usr/share/doc/yubi-tcl/

mkdir -p debian/DEBIAN
cp -a $CONTROLDIR/control debian/DEBIAN
cp -a $CONTROLDIR/postinst debian/DEBIAN
cp -a $CONTROLDIR/prerm debian/DEBIAN

fakeroot dpkg-deb --build debian .
