#! /bin/bash
#
#  Copyright (C) 2011 Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

PREFIX=/usr/local/bin
PGPRING=$PREFIX/pgpring
PROCESSKEYS=$PREFIX/process-keys.py
GREP=/bin/grep
CUT=/usr/bin/cut

OUTDIR=$1
DUMPDIR=$2

if [ ! -e $OUTDIR ]; then
    mkdir -p $OUTDIR
fi

echo -n > $OUTDIR/pgpring.dump

for k in $DUMPDIR/*.pgp; do
   echo Processing $k
   $PGPRING -PS -k $k >> $OUTDIR/pgpring.dump
done

echo "Preprocessing keys"
$PROCESSKEYS $OUTDIR
# TODO make kayanalyze able to directly read process-keys.py output
$CUT -d\; -f1 $OUTDIR/preprocessed >$OUTDIR/preprocessed.ka

