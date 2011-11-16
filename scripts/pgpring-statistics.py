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
from   scipy    import stats
from   datetime import date, datetime

__author__    = "Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>"
__copyright__ = "Copyright (c) 2011 Fabrizio Tarizzo"
__license__   = "GNU General Public License version 3 or later"


# See [RFC4880]
hash_algorithms = {
    0 : 'Unknown',
    1 : 'MD5',
    2 : 'SHA1',
    3 : 'RIPEMD160',
    4 : 'Reserved',
    5 : 'Reserved',
    6 : 'Reserved',
    7 : 'Reserved',
    8 : 'SHA256',
    9 : 'SHA384',
    10: 'SHA512',
    11: 'SHA224',
    100:'Private/Experimental'
}

pk_algorithms = {
    0 : 'Unknown',
    1 : 'RSA Encrypt or Sign',
    2 : 'RSA Encrypt-Only',
    3 : 'RSA Sign-Only',
    16: 'Elgamal (Encrypt-Only)',
    17: 'DSA',
    18: 'Elliptic Curve',
    19: 'ECDSA',
    20: 'Elgamal Encrypt or Sign (deprecated)',
    21: 'Diffie-Hellman (X9.42)',
    100:'Private/Experimental'
}

counter = {
    'valid'    : 0,
    'trusted'  : 0,
    'reachable': 0,
    'strong'   : 0
}
sig_counter = {
    'valid'    : 0,
    'reachable': 0,
    'strong'   : 0
}

count_by_pkalgo = {}
for pkalgo in pk_algorithms:
    count_by_pkalgo[pkalgo] = counter.copy()

sig_count_by_hashalgo = {}
for halgo in hash_algorithms:
    sig_count_by_hashalgo[halgo] = sig_counter.copy()

sig_count_by_version = {
    0: sig_counter.copy(),
    2: sig_counter.copy(),
    3: sig_counter.copy(),
    4: sig_counter.copy()
}

sig_count_by_level_lbl = {
    0: 'Generic',
    1: 'Persona',
    2: 'Casual',
    3: 'Positive'
}
sig_count_by_level = {
    0: sig_counter.copy(),
    1: sig_counter.copy(),
    2: sig_counter.copy(),
    3: sig_counter.copy()
}

count_by_key_version = {
    0: counter.copy(),
    2: counter.copy(),
    3: counter.copy(),
    4: counter.copy()
}

count_by_keylen_lbl = {
	0   : 'Less than 1024',
	1025: 'Between 1024 and 2048',
	2049: 'Between 2048 and 4096',
	9999: 'More than 4096'
}

count_by_keylen = {
	0   : counter.copy(),
	1024: counter.copy(),
	1025: counter.copy(),
	2048: counter.copy(),
	2049: counter.copy(),
	4096: counter.copy(),
	9999: counter.copy()
}

count_by_year_lbl = {0:'Before 1992', 9999:'In the future'}
count_by_year = {
	0   : counter.copy(),
	9999: counter.copy()
}
for y in xrange (1992, date.today().year+1):
	count_by_year[y] = counter.copy()

def print_descriptive_stats (data, stream=sys.stdin, fmt = 'html', **kwargs):
	if fmt == 'csv':
		print >>stream,'Count;%d' % data['count']
		print >>stream,'Min;%f' % data['min']
		print >>stream,'1st Quartile;%f' % data['1st Quartile']
		print >>stream,'2nd Quartile (median);%f' % data['2nd Quartile']
		print >>stream,'3rd Quartile;%f' % data['3rd Quartile']
		print >>stream,'Max;%f' % data['max']
		print >>stream,'Mean;%f' % data['mean']
		print >>stream,'Variance;%f' % data['var']
		print >>stream,'Skewness;%f' % data['skewness']
		print >>stream,'Kurtosis;%f' % data['kurtosis']
	elif fmt == 'html':
		tableattrs  = kwargs.get('tableattrs')
		caption     = kwargs.get('caption')
		beforetable = kwargs.get('beforetable')
		aftertable  = kwargs.get('aftertable')
		
		if tableattrs:
			attrs = ' '.join(['%s="%s"' % (k,v) for (k,v) in tableattrs.items()])
			print >>stream,'<table %s>' % attrs
		else:
			print >>stream,'<table>'
		if caption:
			print >>stream,'<caption>%s</caption>' % caption
		
		print >>stream, '<tbody>'	
		print >>stream,'<tr><td>Count</td><td>%d</td></tr>' % data['count']
		print >>stream,'<tr><td>Min</td><td>%f</td></tr>' % data['min']
		print >>stream,'<tr><td>1st Quartile</td><td>%f</td></tr>' % data['1st Quartile']
		print >>stream,'<tr><td>2nd Quartile (median)</td><td>%f</td></tr>' % data['2nd Quartile']
		print >>stream,'<tr><td>3rd Quartile</td><td>%f</td></tr>' % data['3rd Quartile']
		print >>stream,'<tr><td>Max</td><td>%f</td></tr>' % data['max']
		print >>stream,'<tr><td>Mean</td><td>%f</td></tr>' % data['mean']
		print >>stream,'<tr><td>Variance</td><td>%f</td></tr>' % data['var']
		print >>stream,'<tr><td>Skewness</td><td>%f</td></tr>' % data['skewness']
		print >>stream,'<tr><td>Kurtosis</td><td>%f</td></tr>' % data['kurtosis']
		print >>stream,'</tbody></table>'
		
def descriptive_stats (data):
	s = stats.describe (data)
	result = {
		'count'   : s[0],
		'min'     : s[1][0],
		'max'     : s[1][1],
		'mean'    : s[2],
		'var'     : s[3],
		'skewness': s[4],
		'kurtosis':	s[5]
	}
	result['1st Quartile'] = stats.scoreatpercentile (data, 25)
	result['2nd Quartile'] = stats.scoreatpercentile (data, 50)
	result['3rd Quartile'] = stats.scoreatpercentile (data, 75)
	return result

def print_table (data, totals, labels=None, stream=sys.stdout, fmt='html', **kwargs):
	if fmt == 'csv':
		for k in sorted(data.keys()):
			lbl = k
			if labels and k in labels:
				lbl = labels[k]
			print >>stream, "%s;%d;%d;%d;%d" % (lbl, data[k]['valid'], data[k]['trusted'], data[k]['reachable'], data[k]['strong'])
			
	elif fmt == 'html':
		tableattrs  = kwargs.get('tableattrs')
		caption     = kwargs.get('caption')
		beforetable = kwargs.get('beforetable')
		aftertable  = kwargs.get('aftertable')
		headings    = kwargs.get('headings')
		
		if tableattrs:
			attrs = ' '.join(['%s="%s"' % (k,v) for (k,v) in tableattrs.items()])
			print >>stream,'<table %s>' % attrs
		else:
			print >>stream,'<table>'
		if caption:
			print >>stream,'<caption>%s</caption>' % caption
		if headings:
			print >>stream, '<thead><tr>'
			for th in headings:
				print >>stream, '<th>%s</th>' % th
			print >>stream, '</tr></thead>'
		
		perc = lambda x,y:100.0*x/y
		
		print >>stream, '<tbody>'
		for k in sorted(data.keys()):
			lbl = k
			if labels and k in labels:
				lbl = labels[k]
			print >>stream, '<tr>'
			print >>stream, '<td>%s</td>' % lbl
			print >>stream, '<td>%d</td><td>%.2f%%</td>' % (data[k]['valid'], perc (data[k]['valid'], totals['valid']))
			if 'trusted' in data[k]:
				print >>stream, '<td>%d</td><td>%.2f%%</td>' % (data[k]['trusted'], perc (data[k]['trusted'], totals['trusted']))
			print >>stream, '<td>%d</td><td>%.2f%%</td>' % (data[k]['reachable'], perc (data[k]['reachable'], totals['reachable']))
			print >>stream, '<td>%d</td><td>%.2f%%</td>' % (data[k]['strong'], perc (data[k]['strong'], totals['strong']))
			print >>stream, '</tr>'
		print >>stream,'</tbody></table>'
    
datadir = sys.argv[1]
infiles = {}
#for fname in ('msd.txt', 'pgpring', 'keys-list.csv'):
for fname in ('msd.csv', 'keystatus.csv', 'centrality.csv', 'preprocessed'):
    infiles[fname] = file (os.path.join (datadir, fname), 'r')

outfiles = {}
for fname in ('strongset.csv','degree_distribution.csv','eccentricity_distribution.csv','tables.html'):
	outfiles[fname] = file (os.path.join (datadir, fname), 'w')

reachable_set     = set()
strong_set        = set()
strong_set_data   = {}
reachable_set_msd = []
matrix = {}

max_degree       = 0
tot_in_degree    = 0
tot_out_degree   = 0
tot_cross_degree = 0

#Read msd.txt
for line in infiles['msd.csv']:
	fields = line.strip().split(';')
	
	keyid            = fields[0]
	keymsd           = float(fields[1])
	in_deg           = int(fields[2])
	out_deg          = int(fields[3])
	cross_deg        = int(fields[4])
	in_deg_strong    = int(fields[5])
	out_deg_strong   = int(fields[6])
	cross_deg_strong = int(fields[7])
	eccentricity     = int(fields[8])
	in_strong_set    = int(fields[9])
	
	reachable_set.add (keyid)
	reachable_set_msd.append (keymsd)

	if in_strong_set == 1:
		strong_set.add (keyid)
		
		if in_deg_strong > max_degree:
			max_degree = in_deg_strong
		if out_deg_strong > max_degree:
			max_degree = out_deg_strong
		if cross_deg_strong > max_degree:
			max_degree = cross_deg_strong
			
		tot_in_degree    += in_deg_strong
		tot_out_degree   += out_deg_strong
		tot_cross_degree += cross_deg_strong
						
		strong_set_data[keyid] = {
			'keyid'         : keyid,
			'msd'           : keymsd,
			'in_degree'     : in_deg_strong,
			'out_degree'    : out_deg_strong,
			'cross_degree'  : cross_deg_strong,
			'eccentricity'  : eccentricity,
			'centrality_abs': 0.0,
			'centrality_rel': 0.0,
			'clustering': 0.0
		}
		matrix[keyid] = {'in': set(), 'out': set(), 'all': set()}

if tot_in_degree != tot_out_degree:
	print >>sys.stderr, "Something gone wrong: tot_in_degree=%d, tot_out_degree=%d" % (tot_in_degree,tot_out_degree)
	
strong_set_size = len (strong_set)
reachable_set_size = len (reachable_set)
print "Reachable set size:", reachable_set_size
print "Strong set size:", strong_set_size

msd_stats = descriptive_stats (reachable_set_msd)
print_descriptive_stats (msd_stats,stream=outfiles['tables.html'])
reachable_set_msd = None

msd_stats = descriptive_stats ([strong_set_data[k]['msd'] for k in strong_set_data])
print_descriptive_stats (msd_stats,stream=outfiles['tables.html'])

ecc_stats = descriptive_stats ([strong_set_data[k]['eccentricity'] for k in strong_set_data])
print_descriptive_stats (ecc_stats,stream=outfiles['tables.html'])

ecc_distribution = {}
for i in xrange (ecc_stats['min'], ecc_stats['max']+1):
	ecc_distribution[i] = 0
	
degree_distribution = {}
for i in xrange (max_degree + 1):
	degree_distribution[i] = {'in':0, 'out':0, 'cross':0}
	
for k in strong_set_data:
	kd = strong_set_data[k]
	ecc_distribution[kd['eccentricity']]             += 1
	degree_distribution[kd['in_degree']]['in']       += 1
	degree_distribution[kd['out_degree']]['out']     += 1
	degree_distribution[kd['cross_degree']]['cross'] += 1

in_deg_cum    = strong_set_size
out_deg_cum   = strong_set_size
cross_deg_cum = strong_set_size
stream        = outfiles['degree_distribution.csv']
for deg in degree_distribution:
	kd = degree_distribution[deg]
	print >>stream, "%d;%d;%d;%d;%d;%d;%d" % (deg,kd['in'],in_deg_cum,kd['out'],out_deg_cum,kd['cross'],cross_deg_cum)
	in_deg_cum     -= kd['in']
	out_deg_cum    -= kd['out']
	cross_deg_cum  -= kd['cross']
stream.close()

stream = outfiles['eccentricity_distribution.csv']
for ecc in ecc_distribution:
	print >>stream, "%d;%d" % (ecc, ecc_distribution[ecc])

stream.close()

infiles['msd.csv'].close()

# Read centrality
max_centrality = -1.0
for line in infiles['centrality.csv']:
	keyid, centrality = line.strip().split(';')
	if keyid not in strong_set:
		print >>sys.stderr, "Something wrong with key %s" % keyid
	centrality = float(centrality)
	if centrality > max_centrality:
		max_centrality = centrality
		
	strong_set_data[keyid]['centrality_abs'] = centrality
	strong_set_data[keyid]['centrality_rel'] = centrality/((strong_set_size-1)*(strong_set_size-2))
	
# Calculate graph centralization
centr_sum = 0.0
max_centrality /= ((strong_set_size-1)*(strong_set_size-2))
for k in strong_set_data:
    centr_sum += (max_centrality - strong_set_data[k]['centrality_rel'])
    
graph_centralization = centr_sum / (strong_set_size - 1)
print 'max centrality', max_centrality
print 'graph_centralization:', graph_centralization

# Compute clustering coefficient and signature statistics
valid_signatures         = 0
reachable_set_signatures = 0
strong_set_signatures    = 0

for line in infiles['preprocessed']:
	line = line.strip()
	
	if line[0] == 'p':
		signee = line[1:]
	elif line[0] == 's':
		fields   = line.split(';')
		signer   = fields[0][1:]
		sigdate  = fields[1]
		sigexp   = fields[2]
		flags    = fields[3]
		level    = int(fields[4])
		pkalgo   = int(fields[5])
		hashalgo = int(fields[6])
		version  = int(fields[7])
		
		valid_signatures += 1
		
		if hashalgo >= 100:
			hashalgo = 100
		elif not hashalgo in hash_algorithms:
			hashalgo = 0
			
		sig_count_by_hashalgo[hashalgo]['valid'] += 1
		sig_count_by_version[version]['valid']   += 1
		sig_count_by_level[level]['valid']   += 1

		if signee in reachable_set and signer in reachable_set:
			reachable_set_signatures += 1
			sig_count_by_hashalgo[hashalgo]['reachable'] += 1
			sig_count_by_version[version]['reachable']   += 1
			sig_count_by_level[level]['reachable']   += 1
		
		if signee in strong_set and signer in strong_set:
			strong_set_signatures += 1
			sig_count_by_hashalgo[hashalgo]['strong'] += 1
			sig_count_by_version[version]['strong']   += 1
			sig_count_by_level[level]['strong']   += 1
			
			# Data for clustering coefficient computation
			matrix[signee]['in'].add  (signer)
			matrix[signer]['out'].add (signee)
			matrix[signee]['all'].add (signer)
			matrix[signer]['all'].add (signee)

sig_totals = {
	'valid'    : valid_signatures,
	'reachable': reachable_set_signatures,
	'strong'   : strong_set_signatures,
}


# Clustering coefficient
print 'Compute clustering coefficient...',
global_tot = 0.0
for i in strong_set:
	kd = strong_set_data[i]
	deg_tot = kd['in_degree'] + kd['out_degree']
	denom = 2 * (deg_tot * (deg_tot - 1) - 2 * kd['cross_degree'])
	tot = 0
	
	vi = matrix[i]
	i_in  = vi['in']
	i_out = vi['out']
	i_all = vi['all']
	if len (i_all) < 2:
		kd['clustering'] = 0.0
	else:
		for j in i_all:
			vj    = matrix[j]
			j_in  = vj['in']
			j_out = vj['out']
			j_all = vj['all']
			ij_ji = int (j in i_out) + int (j in i_in)
			tot_h = 0
			for h in (j_all & i_all):
				ih_hi = int (h in i_out) + int (h in i_in)
				if ih_hi:
					jh_hj = int (h in j_out) + int (h in j_in)
					tot_h += ih_hi * jh_hj

			tot += ij_ji * tot_h
			
		coeff = float(tot) / denom
		global_tot += coeff
		kd['clustering'] = coeff

print 'done.'
print "Global clustering coefficient: %.5f" % (global_tot / strong_set_size)
infiles['preprocessed'].close()
matrix = None

fields = ('keyid','msd','in_degree','out_degree','cross_degree','eccentricity','centrality_abs','centrality_rel','clustering')
print >>outfiles['strongset.csv'], ';'.join (fields)
for k in strong_set_data:
	kd = strong_set_data[k]
	print >>outfiles['strongset.csv'], "%(keyid)s;%(msd).5f;%(in_degree)d;%(out_degree)d;%(cross_degree)d;%(eccentricity)d;%(centrality_abs).9f;%(centrality_rel).9f;%(clustering).5f" % kd
	
outfiles['strongset.csv'].close()

# Read key status and compute key statistics
# Get rid of duplicates
done_keys = set()
# Totals
expired_keys   = 0
revoked_keys   = 0
invalid_keys   = 0
valid_keys     = 0
certified_keys = 0
revoked_keys_owner = 0
revoked_keys_deleg = 0

print "Read key status and compute key statistics...",

for line in infiles['keystatus.csv']:
	fields = line.strip().split(';')
	
	keystatus  = fields[0]
	keyid      = fields[1]
	pkalgo     = int(fields[2])
	keylen     = int(fields[3])
	create     = fields[4]
	expire     = fields[5]
	keyversion = int(fields[6])
	userids    = int(fields[7])

	if keyid in done_keys:
		continue

	done_keys.add(keyid)
	
	year = int(create[:4])
	if year < 1992:
		year = 0
	elif year > date.today().year:
		year = 9999
	
	if pkalgo >= 100:
		pkalgo = 100
	elif not pkalgo in pk_algorithms:
		pkalgo = 0
	
	if keylen < 1024:
		kl = 0
	elif keylen>1024 and keylen<2048:
		kl = 1025
	elif keylen>2048 and keylen<4096:
		kl = 2049
	elif keylen > 4096:
		kl = 9999
	else:
		kl = keylen
	
	if keystatus == 'E':
		expired_keys += 1
		
	elif keystatus == 'Ro':
		revoked_keys += 1
		revoked_keys_owner +=1
		
	elif keystatus == 'Rd':
		revoked_keys += 1
		revoked_keys_deleg +=1
		
	elif keystatus == 'I':
		invalid_keys += 1
					
	elif keystatus[0] == 'V':
		valid_keys += 1
		count_by_key_version[keyversion]['valid'] +=1
		count_by_pkalgo[pkalgo]['valid'] +=1
		count_by_keylen[kl]['valid'] += 1
		count_by_year[year]['valid'] += 1
		#...
		
		if len(keystatus) == 2 and keystatus[1] == 'C':
			certified_keys += 1
			count_by_key_version[keyversion]['trusted'] +=1
			count_by_pkalgo[pkalgo]['trusted'] +=1
			count_by_keylen[kl]['trusted'] += 1
			count_by_year[year]['trusted'] += 1
			#...
		
	if keyid in reachable_set:
		count_by_key_version[keyversion]['reachable'] +=1
		count_by_pkalgo[pkalgo]['reachable'] +=1
		count_by_keylen[kl]['reachable'] += 1
		count_by_year[year]['reachable'] += 1
		#...
				
	if keyid in strong_set:
		count_by_key_version[keyversion]['strong'] +=1
		count_by_pkalgo[pkalgo]['strong'] +=1
		count_by_keylen[kl]['strong'] += 1
		count_by_year[year]['strong'] += 1
		#...


totals = {
	'expired'  : expired_keys,
	'revoked'  : revoked_keys,
	'invalid'  : invalid_keys,	
	'valid'    : valid_keys,
	'trusted'  : certified_keys,
	'reachable': reachable_set_size,
	'strong'   : strong_set_size,
}

print "done."

print_table (count_by_key_version, totals, stream=outfiles['tables.html'])
print_table (count_by_pkalgo, totals, pk_algorithms, stream=outfiles['tables.html'])
print_table (count_by_keylen, totals, count_by_keylen_lbl, stream=outfiles['tables.html'])
print_table (count_by_year, totals, count_by_year_lbl, stream=outfiles['tables.html'])

print_table (sig_count_by_version, sig_totals, stream=outfiles['tables.html'])
print_table (sig_count_by_level, sig_totals, sig_count_by_level_lbl, stream=outfiles['tables.html'])
print_table (sig_count_by_hashalgo, sig_totals, hash_algorithms, stream=outfiles['tables.html'])
