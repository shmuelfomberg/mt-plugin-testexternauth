package MT::Auth::TestExtern;

use strict;
use base 'MT::Auth::MT';
use MT::Author qw(AUTHOR);
use MT::Util qw( encode_url caturl );

sub can_recover_password { 0 }
sub is_profile_needed { 1 }
sub password_exists { 0 }
sub delegate_auth { 0 }
sub can_logout { 1 }

sub new_user {
    my ($auth, $app, $user) = @_;
    $user->password('(none)');
    0;
}

sub validate_credentials {
    my $auth = shift;
    my ($ctx, %credentials) = @_;

    my $app = $ctx->{app};
    my $username = $ctx->{username};
    my $author;

    if ((defined $username) && ($username ne '')) {
        # load author from db
		my $user_class = $app->user_class;
		($author) = $user_class->load({ name => $username, type => AUTHOR, });
	}

	if ($author) {
		if (!$author->is_active) {
		    if ( MT::Author::INACTIVE() == $author->status ) {
			$app->user(undef);
			MT->log({ message => "Failed login attempt: account for $username is inactive" });
			return MT::Auth::INACTIVE();
		    }
		    elsif ( MT::Author::PENDING() == $author->status ) {
			MT->log({ message => "Failed login attempt: account for $username is pending" });
			return MT::Auth::PENDING();
		    }
		}
	    if ($ctx->{session_id}) {
	    	my $sess = $app->model('session')->load($ctx->{session_id});
	    	if ($sess and ($sess->get('author_id') == $author->id) ) {
				$app->user($author);
				return MT::Auth::SUCCESS();
	    	}
			$app->errtrans("Invalid request.");
            return MT::Auth::SESSION_EXPIRED();
	    }
	}

	my $password = $ctx->{password};
	if ($username and $password) {
		open my $fh, "<", "plugins/TestExtrnAuth/userlist.txt" or die "Password file not found";
		while (my $line = <$fh>) {
			chomp $line;
			next if !$line or $line =~ /^\s*$/; 
			my ($user, $pass) = split ',', $line;
			if ( ( $user eq $username ) && ( $pass eq $password ) ) {
				if ($author) {
					$app->user($author);
					return MT::Auth::NEW_LOGIN();
				} else {
					return MT::Auth::NEW_USER()
				}
			}
		}
	}

	return $author ? MT::Auth::INVALID_PASSWORD() : MT::Auth::UNKNOWN();
}

sub login_credentials {
    my $auth = shift;
    my ($ctx) = @_;

    my $app = $ctx->{app} or return;
    if ( $app->param('username') && length( scalar $app->param('password') ) )
    {
        my ( $user, $pass, $remember );
        $user     = $app->param('username');
        $pass     = $app->param('password');
        $remember = $app->param('remember') ? 1 : 0;
        return {
            %$ctx,
            username  => $user,
            password  => $pass,
            permanent => $remember,
            auth_type => 'TestExtern'
        };
    }
    return undef;
}

sub session_credentials {
    my $auth = shift;
    my ($ctx) = @_;

    my $app = $ctx->{app} or return;
    my $cookies = $app->cookies;
    if ($cookies->{$app->user_cookie}) {
        my ($user, $session_id, $remember) = split /::/, $cookies->{$app->user_cookie}->value;
        return { %$ctx, username => $user, session_id => $session_id, permanent => $remember, auth_type => 'TestExtern' };
    }
    return undef;
}

sub fetch_credentials {
    my $auth = shift;
    my ($ctx) = @_;
    return $auth->login_credentials(@_) || $auth->session_credentials(@_);
}

#is_valid_password
#invalidate_credentials
#synchronize
#synchronize_author
#synchronize_group 
#new_login
#login_form

1;
