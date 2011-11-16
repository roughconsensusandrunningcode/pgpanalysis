# Copyright (c) Matthias Bauer <bauerm@shoestringfoundation.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use LWP::UserAgent;
use DB_File;

use strict;
use warnings "all";

my ( @keyids, %id );
my ( $list, $num ) = ( $ARGV[0], $ARGV[1] );
$num--;    # off-by-one

# my $keyserverurl = "http://keyserver.noreply.org/pks/lookup?search=0x";
my $keyserverurl = "http://wwwkeys.pgp.net:11371/pks/lookup?op=index&search=0x";

my $iddb = "keyid.db";
tie( %id, 'DB_File', $iddb ) or die "Could not DB_File-tie to $iddb: $!";

# We'll fetch the usernames by http
$ENV{PERL_LWP_USE_HTTP_10} = 1;
my $ua = new LWP::UserAgent;
$ua->timeout(120);
$ua->env_proxy;

# get the top $num entries of the ranking
open IN, "<$list" or die "mist: $!";
while (<IN>) {
    chomp;
    my ( $rank, $id ) = split /:\s+/;
    unshift @keyids, $id;
}
close IN;

my @ids;
foreach my $i ( 0 .. $num ) {
    push @ids, $keyids[$i];
}

my $c = 1;
my %rank = map {($_,$c++)} @ids;

# pull info from the keyserver
foreach my $i (@ids) {
    next if ( exists $id{$i} );    # Already know a username
    print STDERR "Fetching $i (rank $rank{$i})\n";
    my $sid = substr $i, 8, 8;
    my $url = $keyserverurl . $sid;
   RETRY:
    my $r   = $ua->get($url);
    if ( !$r->is_error ) {
        my $text = $r->content;

        # First line of usernames  (at least for the keyservers above)
        $text =~ s/^.*<a href="[^"]+">//s;
        $text =~ s,</a>.*,,s;
        $id{$i} = $text;
    }
    else {
        print STDERR $r->content, "\n";
	goto RETRY;
    }
}
foreach my $i (@ids) {
    print STDOUT "$i $id{$i}\n";
}
