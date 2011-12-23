#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

import sys
import os.path

__author__    = "Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>"
__copyright__ = "Copyright (c) 2011 Fabrizio Tarizzo"
__license__   = "GNU General Public License version 3 or later"

def gexf_print_nodes (nodes, outfile=sys.stdout):
	print >>outfile, '<nodes>'
	for n in nodes:
		print >>outfile, '<node id="%s" label="%s"/>' % (n, n)
	print >>outfile, '</nodes>'
	
def gexf_print_edges (edges, outfile=sys.stdout):
	print >>outfile, '<edges>'
	for (signer, signee) in edges:
		print >>outfile, '<edge id="%s-%s" source="%s" target="%s"/>' % (signer, signee, signer, signee)
	print >>outfile, '</edges>'

def gexf_print_header (outfile=sys.stdout):
	print >>outfile, """<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://www.gexf.net/1.1draft"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://www.gexf.net/1.1draft http://www.gexf.net/1.1draft/gexf.xsd"
	version="1.1">
	<graph mode="static" defaultedgetype="directed">
"""

def gexf_print_footer (outfile=sys.stdout):
	print >>outfile, '</graph></gexf>'


infile = sys.stdin

nodes = set()
edges = set()

infile = sys.stdin
for line in infile:
	line = line.strip()
	
	if line[0] == 'p':
		signee = line[1:17]
		nodes.add (signee)
	elif line[0] == 's':
		signer = line[1:17]
		edges.add ((signer, signee))

outfile = sys.stdout

gexf_print_header (outfile)
gexf_print_nodes  (nodes, outfile)
gexf_print_edges  (edges, outfile)
gexf_print_footer (outfile)

