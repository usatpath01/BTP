import re
from re import search
import pprint
import sys
import string
pp = pprint.PrettyPrinter(indent=4)

def build_regex_from_lms(i):
    given_string = i
    given_string = given_string.strip()

    testing = "(%(?:[0-9]*[.][0-9]+)s)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%s", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)d)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%d", given_string)

    
    testing = "(%(?:[0-9]+)d)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%d", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)l)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%l", given_string)

    
    testing = "(%(?:[0-9]+)l)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%l", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)h)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%h", given_string)

    
    testing = "(%(?:[0-9]+)h)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%h", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)u)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%u", given_string)

    
    testing = "(%(?:[0-9]+)u)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%u", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)f)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%f", given_string)

    
    testing = "(%(?:[0-9]+)f)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%f", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)L)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%L", given_string)

    
    testing = "(%(?:[0-9]+)L)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%L", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)p)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%p", given_string)

    
    testing = "(%(?:[0-9]+)p)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%p", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)i)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%i", given_string)

    
    testing = "(%(?:[0-9]+)i)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%i", given_string)

    testing = "(%(?:[0-9]*[.][0-9]+)x)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%x", given_string)

    
    testing = "(%(?:[0-9]+)X)"
    expressions = re.findall(testing,given_string)
    for exp in expressions:
        given_string = re.sub(exp, "%X", given_string)

    print(given_string)

    given_string = given_string.translate(str.maketrans({"+":  r"\+",
                                          "]": r"\]",
                                          "[": r"\[",
                                          "(": r"\(",
                                          ")": r"\)",
                                          "{": r"\{",
                                          "}": r"\}",
                                          "|": r"\|",
                                          "\\": r"\\",
                                          "^":  r"\^",
                                          "$":  r"\$",
                                          "*":  r"\*",
                                          ".":  r"\."}))


    given_string = re.sub("%c", ".", given_string)
    given_string = re.sub("%s", ".*", given_string)
    given_string = re.sub("%m", ".*", given_string)
    given_string = re.sub("%M", ".*", given_string)
    
    #ADD %0i
    regex_for_oct = "[-+]?[0-7]+"
    given_string = re.sub("%o", regex_for_oct, given_string)

     #ADD %0i
    regex_for_pos_int = "[0-9]+"
    given_string = re.sub("%hu", regex_for_pos_int, given_string)
    given_string = re.sub("%lu", regex_for_pos_int, given_string)
    given_string = re.sub("%llu", regex_for_pos_int, given_string)
    given_string = re.sub("%u", regex_for_pos_int, given_string)

    #ADD %0.0 something
    regex_for_float_double = "[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)"
    given_string = re.sub("%f", regex_for_float_double, given_string)
    given_string = re.sub("%lf", regex_for_float_double, given_string)
    given_string = re.sub("%Lf", regex_for_float_double, given_string)

    # regex_for_address = ""
    regex_for_address = "(0x|0X)?[0-9a-f]{8}/i"
    given_string = re.sub("%p", regex_for_address, given_string)

    regex_for_hexadeciaml = "(0x)?[0-9a-f]{8}/i"
    given_string = re.sub("%x", regex_for_hexadeciaml, given_string)
    given_string = re.sub("%lx", regex_for_hexadeciaml, given_string)
    given_string = re.sub("%X", regex_for_hexadeciaml, given_string)

    #ADD %0i
    regex_for_int = "-?[0-9]+"
    given_string = re.sub("%hd", regex_for_int, given_string)
    given_string = re.sub("%hi", regex_for_int, given_string)
    given_string = re.sub("%i", regex_for_int, given_string)
    given_string = re.sub("%d", regex_for_int, given_string)
    given_string = re.sub("%ld", regex_for_int, given_string)
    given_string = re.sub("%li", regex_for_int, given_string)
    given_string = re.sub("%lld", regex_for_int, given_string)
    given_string = re.sub("%lli", regex_for_int, given_string)
    given_string = re.sub("%l", regex_for_int, given_string)

    return given_string

def find_rank(string):
    total_words = len(re.findall(r'\w+', string))
    regex_for_float_double = "[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)"
    regex_for_oct = "[-+]?[0-7]+"
    regex_for_int = "-?[0-9]+"
    regex_for_pos_int = "[0-9]+"
    regex_for_address = "(0x|0X)?[0-9a-f]{8}/i"
    regex_for_hexadeciaml = "(0x)?[0-9a-f]{8}/i"
    special_chars = [r"\*",r"\.",r"\{",r"\}",r"\[",r"\]",r"\<",r"\>",r"\(",r"\)",r"\+",r"\\",r"\|"]

    for ele in special_chars:
        string = string.replace(ele,"")

    cnt = 0
    
    cnt += string.count(regex_for_float_double)
    string = string.replace(regex_for_float_double,"")
    
    cnt += string.count(regex_for_int)
    string = string.replace(regex_for_int,"")

    cnt += string.count(regex_for_pos_int)
    string = string.replace(regex_for_pos_int,"")

    cnt += string.count(regex_for_oct)
    string = string.replace(regex_for_oct,"")

    cnt += string.count(regex_for_address)
    string = string.replace(regex_for_address,"")

    cnt += string.count(regex_for_hexadeciaml)
    string = string.replace(regex_for_hexadeciaml,"")

    cnt += string.count(".*") 
    string = string.replace(".*","")

    cnt += string.count(".")

    return total_words-cnt

if __name__ == '__main__':
    req_strings = {'sec', 'User: name="%s" id=%lu%s\n', '%s (%lu bytes)', 'map_to_storage',
                   'AH00561: Request header exceeds LimitRequestFieldSize%s%.*s',
                   ' not supported for current URL.<br />\n',
                   'Request received from client: %s',
                   'will flush because of %s', 'main.c', 'AH02539: client sent unknown Transfer-Encoding (%s): %s',
                   'AH01575: loaded module %s from %s', 'AH00017: Pre-configuration failed, exiting', 'Cache-Control',
                   ' Port ', ' -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT', 'AH00646: Error writing to %s',
                   '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>', '\t ', 'no-etag',
                   '%s:%d', 'access_checker', 'stop', '  Date: %s',
                   'AH00547: Could not resolve host name %s -- ignoring!',
                   '<p>Server timeout waiting for the HTTP request from the client.</p>\n',
                   '<p>The expectation given in the Expect request-header\nfield could not be met by this server.\nThe client sent<pre>\n    Expect: ',
                   'protocol.c', 'AH02401: HTTP Request Line; Rejected HTTP/0.9 request',
                   'AH10036: %s: could not open syslog error log %s.', 'memory exhausted', '/usr/lib/apache2/suexec',
                   'httpd (pid %d) already running', 'mpm_query',
                   'Cannot define multiple Listeners on the same IP:port', 'insert_filter', '  ', 'Syntax OK',
                   'AH02173: Invalid parameters for %s',
                   '<p>The proxy server received an invalid\r\nresponse from an upstream server.<br />\r\n', 'Date',
                   '%d', 'httpd (pid %d?) not running', 'only inside <Directory>, <Files>, <Location>, or <If>',
                   'AH00034: dir_walk error, could not determine the root path of filename %s%s for uri %s',
                   'open_logs', 'header_parser', ' -D AP_TYPES_CONFIG_FILE="mime.types"', '0123456789abcdef',
                   'GATEWAY_INTERFACE', '[no address given]', 'mpm', '\tAllowed in *.conf ',
                   'AH02174: Must be uid 0 to raise maximum %s', 'Size of a request header field exceeds server limit.',
                   '  %s\n', 'ap_logio_get_last_bytes',
                   'brigade contains: bytes: %lu, non-file bytes: %lu, eor buckets: %d, morphing buckets: %d', 'Expect',
                   'logs/error_log', '_default_',
                   '<p>An appropriate representation of the requested resource could not be found on this server.</p>\n',
                   'Content-Length', 'Unary operator', 'pre_connection', 'core.c', ' at offset ', 'DUMP_MODULES',
                   "Module specifier '%s' must be followed by a log level keyword",
                   '<Else> or <ElseIf> section without previous <If> or <ElseIf> section in same scope', 'mailto:',
                   ' is not a directory', 'REDIRECT_URL', 'pre_close_connection', 'none',
                   'AH02974: Watchdog: found parent providers.', '%s (%s)\n', 'generate_log_id', 'protocol_switch',
                   'verbose-error-to', 'Missing address for VirtualHost', '--\r\n', 'bytes %ld-%ld/%ld', 'charset=',
                   'AH02555: Unknown Transfer-Encoding: %s; using read-until-close',
                   "Variable name must not contain ':'", 'AH00566: request failed: malformed request line',
                   '<p>The requested resource is currently locked.\nThe lock must be released or proper identification\ngiven before the method can be applied.</p>\n',
                   'local', 'Setting LogLevel for module %s to %s',
                   'Exceeded maximum include depth of %u, There appears to be a recursion.', 'true', 'auth_checker',
                   'Allow', 'DOCUMENT_ROOT', 'AH02422: HTTP Request Line; URI must not contain a username/password',
                   'k:C:c:D:d:E:e:f:vVlLtTSMh?X',
                   '<p>The server understands the media type of the\nrequest entity, but was unable to process the\ncontained instructions.</p>\n',
                   'access_checker_ex', '[%s] [crit] (%d) %s: %s failed to initial context, exiting\n', '%ld-%ld',
                   ' -D APR_USE_SYSVSEM_SERIALIZE',
                   '<p>The server terminated an operation because\nit encountered an infinite loop.</p>\n',
                   'AH00058: Error retrieving pid file %s', 'Options', 'FLUSH bucket',
                   "API module structure '%s' in file %s is garbled - expected signature %08lx but saw %08lx - perhaps this is not an Apache module DSO, or was compiled for a different Apache version?",
                   'AH02656: Error while reading HTTP trailer: %i%s%s', 'redirect-keeps-vary',
                   '<p>The server refused this request because\nthe request header fields are too large.</p>\n',
                   ' [no per-dir config]', '%8s port %u ',
                   '<p>A variant for the requested resource\n<pre>\n\n</pre>\nis itself a negotiable resource. This indicates a configuration error.</p>\n',
                   'AH01571: Watchdog: Failed to create parent worker thread.', 'timeout=%d',
                   'AH00552: Internal error: pcfg_openfile() called with NULL filename', '%u', '\n</pre>\n',
                   'AH03155: select protocol from %s, choices=%s for server %s', 'ChrootDir: "%s"%s\n', 'mod_so.c',
                   'Connection', 'ap_signal_server', 'http/1.1', 'CLF',
                   '<p>The server is temporarily unable to service your\nrequest due to maintenance downtime or capacity\nproblems. Please try again later.</p>\n',
                   'AH00064: sigaction(SIGABRT)', 'TRACE cannot be controlled by <Limit>, see TraceEnable', 'enabled)',
                   'Transfer-Encoding', '[client %s:%d] ', 'Via',
                   #"<p>The requested URL's length exceeds the capacity\nlimit for this server.<br />\n",
                   '500 Internal Server Error', ' -D DYNAMIC_MODULE_LIMIT=%ld\n', '%ld-%ld/%ld\r\n\r\n', 'monitor',
                   '.htaccess', 'Expected </', 'Error reading %s at line %d: Line too long',
                   '                util_fcgi.c', 'graceful', 'AH02977: Watchdog: found child providers.',
                   'AH01591: Read content length of %ld is larger than the configured limit of %ld'}
    
    req_strings_list = list(req_strings)
    regx_strings = []
    print('Building LMS Regular Expressions ->')
    while req_strings_list:
        req_string = req_strings_list.pop(0)
        regx_strings.append(build_regex_from_lms(req_string))
    pp.pprint(regx_strings)

    ####Start from here
    #Given event log
    # e = "File size too large"
    # e = "AH00646: Error writing to assasasas" #this is appication log
    # e = 'User: name="utkal" id=01AS'
    # e = 'AH01591: Read content length of 10222 is larger than the configured limit of 22222'
    # e = "05/04/2020 test[123934] AH00646: Error writing to 10"
    e = "-D DYNAMIC_MODULE_LIMIT=10921"
    #e = "05/04/2020 test[123934] key 'huppp': invalid initialization method 'sssss'"
    #e = 'AH00646: Error writing to asasas'
    # print("Event - ", e)
    # print('Matching the event to a known LMS for the application ->')

    candidates_lms = []
    for i in regx_strings:
        pattern = re.compile(i)
        if pattern.fullmatch(e):
            candidates_lms.append(i)
    print(candidates_lms)

    final_regex_lms = ""
    mx = 0
    #Do ranking now
    #Number of non-regex words = total_words - regex_words
    for string in candidates_lms:
        temp_cmp = find_rank(string)
        if temp_cmp>mx:
            mx = temp_cmp
            final_regex_lms = string
    print(final_regex_lms)


                