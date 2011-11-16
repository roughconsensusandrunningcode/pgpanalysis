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
KEYANALYZE=$PREFIX/keyanalyze
CENTRALITY=$PREFIX/wot-centrality
#GREP=/bin/grep
#CUT=/usr/bin/cut
#SORT=/usr/bin/sort

OUTDIR=$1

echo "Running keyanalyze"
time $KEYANALYZE -N -n -i $OUTDIR/preprocessed.ka -o $OUTDIR
#$GREP -e '^\*\*\*' $OUTDIR/othersets.txt | $CUT -d' ' -f2 | $SORT -rn >$OUTDIR/sets_size.txt

echo "Running wot-centrality"
time $CENTRALITY $OUTDIR/preprocessed.strongset > $OUTDIR/centrality.csv
