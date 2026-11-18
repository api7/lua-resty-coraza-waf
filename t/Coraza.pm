package t::Coraza;

# Common setup of the test-nginx suites: resty.coraza from lib/ and
# coraza_waf.so from $CORAZA_WAF_LIB (default ./coraza_waf.so), loaded in
# init_worker as a real deployment does.
use Test::Nginx::Socket::Lua -Base;
use Cwd qw(cwd);

my $pwd = cwd();
my $lib = $ENV{CORAZA_WAF_LIB} || "$pwd/coraza_waf.so";

master_on();
workers(1);
log_level('info');
no_long_string();
no_shuffle();

add_block_preprocessor(sub {
    my ($block) = @_;

    my $http_config = $block->http_config // '';
    $block->set_value("http_config", <<_EOC_);
    lua_package_path "$pwd/lib/?.lua;$pwd/t/lib/?.lua;;";
    init_worker_by_lua_block {
        local coraza = require("resty.coraza")
        assert(coraza.load("$lib"))
    }
    $http_config
_EOC_

    if (!defined $block->request) {
        $block->set_value("request", "GET /t");
    }
    if (!defined $block->no_error_log && !defined $block->error_log) {
        $block->set_value("no_error_log", "[error]");
    }
});

1;
