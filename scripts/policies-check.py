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
import csv
import urllib
import re
import xml.sax.saxutils
from StringIO import StringIO
from HTMLParser import HTMLParser
import socket
socket.setdefaulttimeout(15)

__author__    = "Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>"
__copyright__ = "Copyright (c) 2011 Fabrizio Tarizzo"
__license__   = "GNU General Public License version 3 or later"

class Parser (HTMLParser):
	def __init__ (self):
		HTMLParser.__init__ (self)
		self.in_title = False
		self.title    = ''
		self.charset  = None
		self.charset_patt = re.compile('charset=([^)]*)')

	def handle_starttag (self, tag, attrs):
		attrs = dict (attrs)
		if tag == 'title':
			self.in_title = True
		elif tag == 'meta':
			if 'http-equiv' in attrs and attrs['http-equiv'] == 'Content-Type' and 'content' in attrs:
				match = self.charset_patt.search (attrs['content'])
				if match:
					self.charset = match.group(1)
			elif 'charset' in attrs:
				self.charset = attrs['charset']
            
	def handle_endtag (self, tag):
		if tag == 'title':
			self.in_title = False
        
	def handle_data (self, data):
		if self.in_title:
			self.title = data.strip()
			
def print_uri (uri):
	policy_uri, real_url, title, size, content_type = uri
	policy_uri_print = policy_uri
	if len (policy_uri) > 80:
		policy_uri_print = policy_uri[:75] + '[...]'
	output = ''
	
	if not title:
		title = policy_uri_print
		
	policy_uri = xml.sax.saxutils.escape (policy_uri)
	real_url   = xml.sax.saxutils.escape (real_url)
		
	output += '<div class="policytitle"><a href="%s">%s</a></div>' % (policy_uri, title)
	if title != policy_uri_print:
		output += '<div class="policyurl">%s</div>' % (policy_uri)
		
	return output

def print_ko_uri (uri):
	policy_uri, err = uri
	policy_uri_print = policy_uri
	if len (policy_uri) > 80:
		policy_uri_print = policy_uri[:75] + '[...]'
		
	output = ''
	policy_uri = xml.sax.saxutils.escape (policy_uri)
	
	output += '<div class="policytitle"><a rel="nofollow" href="%s">%s</a></div>' % (policy_uri, policy_uri_print)
	if title != policy_uri_print:
		output += '<div class="policyurl">%s</div>' % (err)
		
	return output
	
	
if __name__ == '__main__':
	datadir = sys.argv[1]
    
	f_ok = file (os.path.join (datadir, 'policyuris.ok.csv'), 'w')
	f_ko = file (os.path.join (datadir, 'policyuris.ko.csv'), 'w')
	csv_ok = csv.writer (f_ok, delimiter=';')
	csv_ko = csv.writer (f_ko, delimiter=';')
     
	f = file (os.path.join (datadir, 'policyuris.csv'), 'r')
	r = csv.reader (f, delimiter=';')
	ok = {}
	ko = {}
	names = {}
	charset_patt = re.compile('charset=([^)]*)')
	xml_charset_patt = re.compile('encoding="([^"]*)"')

	for row in r:
		key, name, policy_uri, n_used, last_used = row
		names[key] = name
            
		print policy_uri,
        
		try:
			u        = urllib.urlopen (policy_uri)
			code     = u.getcode()
			real_url = u.geturl()     # Handle 30x redirects
			info     = u.info()
			headers  = info.items()
			
			charset  = 'utf-8'
			if 'content-type' in info:
				match = charset_patt.search (info['content-type'])
				if match:
					charset = match.group(1)
            
			# Handle special cases
			# anize.org redirects to http://anize.org/404.html instead of
			# return a regular 404 code for file not found
			if policy_uri != real_url and real_url == 'http://anize.org/404.html':
				code = 404
			# pobox.com returns a response w/o headers if user unknown
			# (example: http://www.pobox.com/~antani/)
			if len(headers) == 0:
				code = 404
            	
			if code == 200:
				content = u.read().strip()
					
				size = len(content)
				content_type = info.gettype()
				title = ''
				
				if content_type == 'text/html':
					if content[:5] == '<?xml':
						line = StringIO(content).readline()
						match = xml_charset_patt.search (line)
						if match:
							charset = match.group(1)
						
					p = Parser()
					try:
						p.feed (content)
					except Exception, e:
						print "HTML Parsing error: %s" % str(e),
                        
					title = p.title
					
					if p.charset:
						charset = p.charset
					
					if charset != 'utf-8':
						title = title.decode(charset)
						title = title.encode('utf-8')
						
					p = None
					
				csv_ok.writerow ([key, name, policy_uri, real_url, title, size, content_type, charset])
				if key not in ok:
					ok[key] = []
				ok[key].append ([policy_uri, real_url, title, size, content_type])
				print 'OK'
			else:
				if key not in ko:
					ko[key] = []
				ko[key].append([policy_uri, 'HTTP code %d' % code])
				
				csv_ko.writerow ([key, name, policy_uri, 'HTTP code %d' % code])
				print 'FAIL: HTTP code %d' % code
		except IOError, e:
			if key not in ko:
				ko[key] = []
			ko[key].append([policy_uri, str(e)])
        		
			csv_ko.writerow ([key, name, policy_uri, str(e)])
			print 'FAIL: %s' % str(e)
    
	f.close()
	f_ok.close()
	f_ko.close()
	
	f_html = file (os.path.join (datadir, 'policyuris.html'), 'w')
	print >>f_html, """<!DOCTYPE html>
<html>
 <head>
  <meta charset="utf-8">
  <title>Policy URIs</title>
  <style type="text/css">
  table, td {border:solid 1px;border-collapse:collapse;vertical-align:top}
  div.policyurl {font-size:x-small}
  </style>
 </head>
 <body>"""
	
	print >>f_html, '<table><tbody>'
	for k in sorted (ok, key=lambda k:names[k]):
		if len(ok[k]) == 1:
			print >>f_html, '<tr>'
			print >>f_html, '<td>0x%s<br>%s</td>' % (k, names[k])
			print >>f_html, '<td>%s</td>' % print_uri(ok[k][0])
			print >>f_html, '</tr>'
		else:
			print >>f_html, '<tr>'
			print >>f_html, '<td rowspan="%d">0x%s<br>%s</td>' % (len(ok[k]), k, names[k])
			print >>f_html, '<td>%s</td></tr>' % print_uri(ok[k][0])
			for u in ok[k][1:]:
				print >>f_html, '<tr><td>%s</td></tr>' % print_uri(u)
			
	print >>f_html, '</tbody></table>'
	
	print >>f_html, '<table><tbody>'
	for k in sorted (ko, key=lambda k:names[k]):
		if len(ko[k]) == 1:
			print >>f_html, '<tr>'
			print >>f_html, '<td>0x%s<br>%s</td>' % (k, names[k])
			print >>f_html, '<td>%s</td>' % print_ko_uri(ko[k][0])
			print >>f_html, '</tr>'
		else:
			print >>f_html, '<tr>'
			print >>f_html, '<td rowspan="%d">0x%s<br>%s</td>' % (len(ko[k]), k, names[k])
			print >>f_html, '<td>%s</td></tr>' % print_ko_uri(ko[k][0])
			for u in ko[k][1:]:
				print >>f_html, '<tr><td>%s</td></tr>' % print_ko_uri(u)
	
	print >>f_html, '</tbody></table>'
	
	print >>f_html, '</body></html>'
	f_html.close()
