package App::squidauth;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;
use Log::ger;

our %SPEC;

$SPEC{squidauth} = {
    v => 1.1,
    summary => 'A simple authenticator program for Squid',
    description => <<'_',

This utility can be used as an authenticator program for Squid. It reads users &
passwords from a simple, htpasswd-format text file (by default at
`/etc/proxypasswd`) with the format like:

    user1:$apr1$YFFyJK3J$PfuotoLCk7XQqQiH6I3Cb/
    user2:$apr1$NOvdp7LN$YnH5zmfCn0IhNt/fKZdL2.
    ...

To add entries to this file, you can use <prog:htpasswd> (usually comes with
Apache httpd in an OS package like `httpd-tools`) to add users to this file,
e.g.:

    % htpasswd -c /etc/proxypasswd user1
    % htpasswd    /etc/proxypasswd user2
    ...

_
    args => {
        passwd_file => {
            summary => 'Location of password file',
            schema => 'pathname*',
            default => '/etc/proxypasswd',
        },
    },
};
sub squidauth {
    require Crypt::PasswdMD5;

    my %args;

    my $passwd_file = $args{passwd_file} // "/etc/proxypasswd";
    my $passwd_file_mtime = 0;

    my %passwords; # key=username, val=[salt, pass]

    my $code_read_passwd_file = sub {
        log_debug "Rereading password file '$passwd_file' ...";
        open my $fh, "<", $auth_file
            or die "Can't open password file '$passwd_file': $!\n";
        $passwd_file_mtime = (-M $passwd_file);
        %passwords = ();
        while (<$fh>) {
            chomp;
            my ($user, $pass) = split /\:/, $_, 2;
            $passwords{$user} = $pass;
        }
    };
    # returns 1 if password is correct
    my $code_cmp_pass = sub {
        my ($pass, $enc) = @_;
        my $salt;

        #DEBUG "Comparing enc($pass, $salt) with $enc...";
        if ($enc =~ /^\$apr1\$(.*?)\$/) {
            # apache MD5
            $salt = $1;
            return Crypt::PasswdM5::apache_md5_crypt($pass, $salt) eq $enc;
        } else {
            # assume it's crypt()
            $salt = $enc;
            return crypt($pass, $salt) eq $enc;
        }
    };

    $code_read_passwd_file->();

    while (<STDIN>) {
        $code_read_passwd_file->() if $passwd_file_mtime > (-M $passwd_file);
        chomp;
        my ($user, $pass) = split / /, $_, 2; $user ||= "";
        if ($passwords{$user} && $code_cmp_pass->($pass, $passwords{$user})) {
            print "OK\n";
        } else {
            print "ERR\n";
        }
    }

    [200]; # won't be reached
}

1;
# ABSTRACT:

=head1 SYNOPSIS

See included script L<squidauth>.


=head1 HISTORY

The C<squidauth> script was created back in early 2000's or even late 1990's.

Converted to use L<Perinci::CmdLine> and packaged as a CPAN distribution in Jan
2018.


=head1 SEE ALSO
