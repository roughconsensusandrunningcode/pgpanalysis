#!/usr/bin/perl -w

#
# Copyright (c) 2005 Matthias Bauer <matthiasb@acm.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

# The program keeps almost all state in files on disk
# This allows a trivial continuity over iterrupts or
# migration to faster hardware.
# It's not elegant.
#
# It relies on two other programs:
#   fetchid.pl  -  queries keyserver for username to the
#                  most central keyids
#   wot         -  does the actual betweeness centrality
#                  algorithm. It's written in C. Takes
#                  about 9 hours on an amd64 2Ghz/1Gb RAM
#                  to work the 2005-08-08 keydumps.
#

use strict;
use warnings "all";

use IO::File;
use DB_File;
use LWP::Simple;
use Carp;
use Getopt::Std;

sub mymkdir;
sub getindex;
sub ownfetch;
sub jharrisfetch;
sub parsethedumps;
sub parsekeydump;
sub wot;
sub tops;
sub alltable;
sub allcompress;
sub mkindex;
sub usage;

our ($opt_d, $opt_j);

### main 
getopts('dj');

my $date;
unless ( $date = $ARGV[0] ) {
    my @tmp = gmtime(time);
    $date = $tmp[5] + 1900;
    $date .= "-";
    $date .= "0" if length( $tmp[4] ) < 2;
    $date .= ++$tmp[4];
    $date .= "-";
    $date .= "0" if length( $tmp[3] ) < 2;
    $date .= $tmp[3];
}

my $KEYDB   = '../keyid.db';
my $PGPDUMP = 'http://pgpkeys.telering.at/public/keydump/';
my $WOT     = '../wot';
my $JHARRIS = 'http://keyserver.kjsl.com/~jharris/ka/';
my $index   = "$PGPDUMP/MD5SUMS";
my $tmpfile = "$date/$date-preprocess.keys";
my $outfile = "$date/$date-ranks";

my @flist;

unless ( -e $date ) {
    mymkdir $date;
}

unless ($opt_j) {
	print STDERR "no -j\n";
	unless ( -e "$date/MD5SUMS" ) {
	    getindex;
	}
	@flist = ownfetch;
	@flist = grep { !-f "$date/$_" . ".parsedump" } @flist;
	parsethedumps @flist;
} else {
	jharrisfetch ($date);
} 

unless ($opt_d) {
    if ( -e $outfile ) {
        my $bak = "$outfile" . ".bak";
        rename $outfile, $bak;
    }
    wot;
}
tops(1000);

###  end of main

# makes $date dir or dies
sub mymkdir {
    print STDERR "making dir $date\n";
    mkdir $date or die "Could not mkdir $date: $@";
}

# get the keyserver index with md5sums from $PGPDUMP
# args: none
# return: nothing
# creates $date/MD5SUMS
sub getindex {
    chdir $date or die "Could not chdir $date: $@";
    print STDERR "fetching/parsing $PGPDUMP\n";
    $ENV{http_proxy} = ""; # Some proxies don't grok HEAD requests
    my @head = head("$PGPDUMP/MD5SUMS");
    croak "could not head $PGPDUMP/MD5SUMS" unless $head[2];
    print STDERR "Last Mod: ", scalar localtime( $head[2] ), "\n";

    my $mdsums = get("$PGPDUMP/MD5SUMS");
    croak "could not get $PGPDUMP/MD5SUMS" unless defined $mdsums;

    {
    local $/;
    undef $/;
    open O, ">MD5SUMS" or croak "Could not create MD5SUMS";
    print O $mdsums;
    close O;
    }

    chdir "..";
}


# check if we got all dumpfiles. If not, fetch from $PGPDUMP
# args: none
# returns: list of downloaded keydump files
# creates keydump files in $date
sub ownfetch {
#   delete $ENV{'http_proxy'};
    my ( @urls, $mdsums, %checks, @files );
    if ( -d $date ) {
        chdir $date or die "Could not chdir $date: $@";
    }
    {
	my $l;
        open I, "<MD5SUMS" or die "could not read MD5SUMS";
        while ($l = <I>) {
            chomp $l;
            my ( $md, $url ) = split /\s+/, $l;
            $url = $PGPDUMP . "/$url";
            push @urls, $url;
            $checks{$url} = $md;
        }
        close I;
    }

    # We have to dump the keyrings to disk because
    # pgpring doesn't read from stdin :-(
    opendir HERE, ".";
    my @herefiles = grep /\.pgp/, readdir HERE;
    my %alreadyhere = map { ( $_, 1 ) } @herefiles;
    closedir HERE;
    foreach my $url (@urls) {
        $url =~ m,/([^/]+)$,;
        my $fname = $1;
        push @files, $fname;
        print STDERR "working on |$fname|\n";
        if ( $alreadyhere{$fname} ) {
            my $mdout = `md5 $fname`;
            chomp $mdout;
            my $fcheck = ( split /\s+=\s+/, $mdout )[1];
            next if ( $fcheck eq $checks{$url} );
            print STDERR
              "$url:\nshould be:\t|$checks{$url}|\nis:\t\t|$fcheck|\n";
        }
        else {
            print STDERR "Not there: |$fname|\n";
        }
        unless ( is_success( getstore( $url, $fname ) ) ) {
            die "could not get $url";
        }
        my $mdout = `md5 $fname`;
        chomp $mdout;
        my $fcheck = ( split /\s+=\s+/, $mdout )[1];
        if ( not $fcheck eq $checks{$url} ) {
            croak
"AArg! $PGPDUMP/MD5SUMS is lying!\nMD5SUMS said |$checks{$url}|, md5 says |$fcheck|";
        }
    }
    print STDERR "finished download\n";
    chdir "..";
    return @files;
}

# fetch preprocess.keys.bz2 from $JHARRIS
# in: date to look for
# out: void
# creates a file $date-preprocess.keys
# exits on error (e.g. if no subdir $date exists at $JHARRIS)
sub jharrisfetch {
    my $date = shift;
    if ( -d $date ) {
        chdir $date or die "Could not chdir $date: $@";
    }
    return if -e "$date-preprocess.keys";
    print "Fetching $JHARRIS/$date/preprocess.keys.bz2\n";
    if (not is_success(getstore ("$JHARRIS/$date/preprocess.keys.bz2",
	"$date-preprocess.keys.bz2"))) {
	die "Could not download $JHARRIS/$date/preprocess.keys.bz2";
    }

    `bzip2 -d $date-preprocess.keys.bz2`;
    if ($@) {
	die "bzip2 failed: $@";
    }
    chdir "..";
}

	

# parse the keydumps for keyids and signatures
# args: list of files
# returns: nothing
# creates a file with extension ".parsedump" for
# each file. Appends content of those files to $tmpfile
sub parsethedumps {
    my @files = @_;
    my ( %ids, %checks, $mdsums );
    if ( -d $date ) {
        chdir $date or die "Could not chdir $date: $@";
    }
    print STDERR "parsing the keydumps with pgpring and writing to $tmpfile\n";

    my $basetmp;
    $basetmp = $tmpfile;
    $basetmp =~ s,^.*/,,;
    foreach my $file (@files) {
        my $ff = "$file" . ".parsedump";
        print STDERR "Calling parsekeydump on $file to $ff\n";
        parsekeydump( $file, $ff );
	# XXX better do this after all files are parsed
        `cat $date/$ff >> $date/$basetmp`;
        if ($?) {
            croak "cat $ff >> $basetmp failed";
        }
    }

    chdir "..";
}

# Lets pgpring print the keys and sigs and transforms
# the output to preprocess.keys form
# args: keydump filename, output filename
# returns: nothing
# prints to output filename
sub parsekeydump {
    my ( $file, $fname ) = @_;

    if ( -d $date ) {
        chdir $date or die "Could not chdir $date: $@";
    }

    open( K, '>>', "$fname" ) or croak "could not append to $fname: $@";
    local $SIG{PIPE} = sub { croak "pgpring died on input $file" };
    open( L, "pgpring -S -k $file |" )
      or croak "could not call pgpring on $file";
    my %d; 	# maps pubkeyid to keyids that signed it
    my $cur;    # the pubkey we're currently working on
    while (<L>) {
        my ( $type, $id, $name ) = ( split /:/ )[ 0, 4, 9 ];

        # End of list of sigs on $cur?
        if ( $type eq "pub" ) {
            if ( $cur && exists $d{$cur} ) {
                my @k = keys %{ $d{$cur} };
                if ( exists $d{$cur}->{rev} ) {

                    # don't list revoked keys.
                    # wot will take care of dangling sigs
                    # for that id.
                    delete $d{$cur};
                }
                elsif ( ( scalar @k ) == 0 ) {

                    # key has no sigs, delete it
                    delete $d{$cur};
                }
                elsif ( ( scalar @k ) == 1 && $k[0] eq $cur ) {

                    # key's only sig is the self-sign
                    delete $d{$cur};
                }
                else {

                    # dump the key and its sigs in
                    # preprocess.keys format
                    # ignore self-sigs
                    print K "p$cur\n";
                    foreach my $j ( keys %{ $d{$cur} } ) {
                        print K "s$j\n" unless $j eq $cur;
                    }
                }
            }

            # Next key
            $cur = $id;
            next;
        }
        if ( $type eq "rev" ) {
            $d{$cur}->{rev}++;
        }
        if ( $type eq "sig" ) {
            $d{$cur}->{$id}++;
        }
    }
    close L;
    chdir "..";
}

# Old
# sub fetch {
#     my $JHARRIS = 'http://keyserver.kjsl.com/~jharris/ka/';
#
#     # fetch the preprocessed keys from Jason Harris
#     my $where = $JHARRIS . $date . "/preprocess.keys.bz2";
#
#     print STDERR "fetching $where\n";
#     die "Could not fetch $where"
#       unless ( is_success( getstore( $where, $tmpfile ) ) );
# }

# calls wot on the preprocessed sigfile
# args: none
# returns: nothing
# writes sorted betweeness centralities of
# all keyids to $outfile
sub wot {
    if ( -d $date ) {
        chdir $date or die "could not chdir to $date: $@";
    }
    my $basetmp = $tmpfile;
    $basetmp =~ s,^.*/,,;

    # compute the betweenness centrality
    # the computation takes about 4 hours on a amd64 at 2Ghz.
    print STDERR "Running wot on $tmpfile\n";
    sleep 4;
    my $out = $outfile;
    $out =~ s,^.*/,,;

    print STDERR "$WOT -l 16 $basetmp > $out \n";
    `$WOT -l 16 $basetmp > $out`;
    die "Error from wot: $!" unless $? == 0;
    chdir "..";
}

# creates html-ified list of the top ranking keys
# args: number of keys to include
# returns: nothing
# writes to $date/top$num.html
# Needs keyid -> username mapping in $KEYDB,
# which can be created by calling
#  perl fetchid.pl $date/$date-rank $num
# after the wot is through all keys
sub tops {
    my $num = shift;
    my (%ident, %rank, %prettyrank);

    # now sort the results
    my $ranksfh = new IO::File;
    $ranksfh->open("< $outfile") or croak "Could not open $outfile: $!";

    while (<$ranksfh>) {
        chomp;
        my ( $r, $id ) = split /\s*:\s*/;
        push @{ $rank{$r} }, $id;
    }
    $ranksfh->close;

    if ( -d $date ) {
        chdir $date or die "could not chdir to $date: $@";
    }

    # Now create a pretty HTML table
    my $c = 0;

    # We use fetchid.pl to build a database of (keyid,  username
    # XXX Better: parse the usernames from the keydumps
    # directly, with pgpring or openpgpsdk
    tie( %ident, 'DB_File', $KEYDB ) or die "Could not tie to $KEYDB: $!";

    print STDERR "creating $date/top$num.html\n";
    foreach my $r ( sort { $b <=> $a } keys %rank ) {
        last if $c == $num;
        $c++;
        foreach my $id ( sort @{ $rank{$r} } ) {
            my $thid = $id;
            my $theuid;
            if ( exists $ident{$id} ) {
                $theuid = $ident{$id};
            }
            else {
                print STDERR "Unknown ID $id, you should run\n perl fetchid.pl $date/$date-rank $c\n";
                $theuid = "Unkown ID";
            }

            # split keyid into two parts
            $thid =~ s|(([A-F0-9]{8})([A-F0-9]{8}))|$2\&nbsp;$3|;
            $prettyrank{$c} .= "<tr><td>$c:</td><td><code>$thid</code></td>";

            # make it a bit more complicated for spammers
            $theuid =~ s/\@/\./g;

            # HTML 4.01-ify 
            # not necessary since we get the usernames from a HTML page
            # $theuid =~ s/\&/\&amp;/g;
            # $theuid =~ s/</\&lt;/g;
            # $theuid =~ s/>/\&gt;/g;

            $prettyrank{$c} .= "<td>$theuid</td>";
            $prettyrank{$c} .= '<td>' . $r . "</td>";
            $prettyrank{$c} .= "</tr>\n";
        }
    }

    untie %ident;
    my $topname = "top" . $num . ".html";
    open TOP, ">$topname"
      or die "Could not open $date/$topname";

    # Wow, this really is something. Next version will be
    # XHTML :-)

    print TOP <<OFF;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
       "http://www.w3.org/TR/html4/loose.dtd">
<html>
<title>Top$num centrality betweenness on $date</title>
<body>
<table width="100%">
<colgroup>
<col>
<col>
<col>
<col align="char" char="." >
</colgroup>
<tr><td><b>Rank</b></td><td><b>Key ID </b></td>
<td><b>Key Name (Identifier)</b></td>
<td align="right"><b>centrality</b></td></tr>
OFF

    foreach my $i ( 1 .. $num ) {
        if ( exists $prettyrank{$i} ) {
            print TOP $prettyrank{$i};
        }
    }

    print TOP <<ZUMFF;
</table>
</body>
</html>
ZUMFF

    close TOP;
    chdir "..";
}

sub usage {
	print <<"EOF";
usage: $0 [-d] [-j] [yyyy-mm-dd]
	computes the betweenness centrality of keys in a large keyring.
	It calls the program $WOT to do the actual graph theory.
	If no date and no -j option is given, the keyring is downloaded
	from $PGPDUMP.
	If a date yyyy-mm-dd is given, the keyring is expected to 
	reside in a directory named yyyy-mm-dd in the current directory.
	If the -d option is given, $WOT is not called, and the
	file yyyy-mm-dd-ranks of a previous invokation of WOT is used to
	produce a ranking of keys by centrality.
	If the -j option is given, the graph representing the keyring
	is downloaded  from Jason Harris' site $JHARRIS.
EOF
}
