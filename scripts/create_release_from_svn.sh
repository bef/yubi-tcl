#!/bin/sh

if [ "x$1" = "x" ]; then
	echo "usage: $0 <version>"
	exit 1
fi

TMPDIR=/tmp/yubi-tmp-$$
NAME=yubi-tcl-$1

mkdir $TMPDIR
cd $TMPDIR

echo "== checkout trunk"
svn checkout http://yubi-tcl.googlecode.com/svn/trunk/ $NAME

echo "== checkout wiki"
svn checkout http://yubi-tcl.googlecode.com/svn/wiki/ $NAME/doc

echo "== packing"
tar zcvf $NAME.tar.gz --exclude .svn $NAME

# echo "== creating debian package"
# $TMPDIR/$NAME/scripts/create_deb.sh $TMPDIR $NAME

echo "== look here --> $TMPDIR"
