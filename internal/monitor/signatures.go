package monitor

// Signature database for the malware scanner.
//
// String patterns are sourced from YARA rule databases and community intel:
//   - github.com/php-malware-finder/php-malware-finder
//   - github.com/Neo23x0/signature-base (webshells.yar, thor-hacktools.yar)
//   - MalwareBazaar crypto-miner process intel
//
// No external YARA engine or CGO is used — patterns run via strings.Contains
// and regexp in pure Go, keeping the agent as a single static binary.

import "regexp"

// sigLevel controls how a single pattern match maps to event severity.
type sigLevel int

const (
	// sigDirect: one match alone → critical event.
	// Reserved for patterns that are unambiguously malicious.
	sigDirect sigLevel = iota

	// sigIndicator: 1-2 matches → warning; 3+ matches in the same file → critical.
	// Used for patterns that are suspicious but appear in legitimate code too.
	sigIndicator
)

// FileSig is a substring-based file signature.
type FileSig struct {
	Pattern string
	Level   sigLevel
	Label   string // human-readable tag included in event details
}

// ============================================================
// PHP signatures (php-malware-finder + Neo23x0/signature-base)
// ============================================================

var phpSigs = []FileSig{
	// --- Direct: RCE via PHP superglobals ---
	{"system($_GET", sigDirect, "rce_system_get"},
	{"system($_POST", sigDirect, "rce_system_post"},
	{"system($_REQUEST", sigDirect, "rce_system_request"},
	{"system($_COOKIE", sigDirect, "rce_system_cookie"},
	{"exec($_GET", sigDirect, "rce_exec_get"},
	{"exec($_POST", sigDirect, "rce_exec_post"},
	{"exec($_REQUEST", sigDirect, "rce_exec_request"},
	{"passthru($_GET", sigDirect, "rce_passthru_get"},
	{"passthru($_POST", sigDirect, "rce_passthru_post"},
	{"passthru($_REQUEST", sigDirect, "rce_passthru_request"},
	{"shell_exec($_GET", sigDirect, "rce_shell_exec_get"},
	{"shell_exec($_POST", sigDirect, "rce_shell_exec_post"},
	{"shell_exec($_REQUEST", sigDirect, "rce_shell_exec_request"},
	{"popen($_GET", sigDirect, "rce_popen_get"},
	{"popen($_POST", sigDirect, "rce_popen_post"},
	{"eval($_GET", sigDirect, "rce_eval_get"},
	{"eval($_POST", sigDirect, "rce_eval_post"},
	{"eval($_REQUEST", sigDirect, "rce_eval_request"},
	{"eval($_COOKIE", sigDirect, "rce_eval_cookie"},
	{"@eval($_GET", sigDirect, "rce_eval_get_hidden"},
	{"@eval($_POST", sigDirect, "rce_eval_post_hidden"},
	{"@eval($_REQUEST", sigDirect, "rce_eval_request_hidden"},
	{"assert($_GET", sigDirect, "rce_assert_get"},
	{"assert($_POST", sigDirect, "rce_assert_post"},
	{"assert($_REQUEST", sigDirect, "rce_assert_request"},

	// --- Direct: obfuscated eval chains ---
	{"eval(base64_decode(", sigDirect, "obf_eval_base64"},
	{"eval(str_rot13(", sigDirect, "obf_eval_rot13"},
	{"eval(gzinflate(", sigDirect, "obf_eval_gzinflate"},
	{"eval(gzuncompress(", sigDirect, "obf_eval_gzuncompress"},
	{"eval(gzdeflate(", sigDirect, "obf_eval_gzdeflate"},
	{"eval(str_replace(", sigDirect, "obf_eval_str_replace"},
	{"assert(base64_decode(", sigDirect, "obf_assert_base64"},
	{"assert(str_rot13(", sigDirect, "obf_assert_rot13"},
	{"assert(gzinflate(", sigDirect, "obf_assert_gzinflate"},

	// --- Direct: create_function with user input ---
	{"create_function($_", sigDirect, "create_function_userinput"},

	// --- Direct: known web shell signatures ---
	{"c99shell", sigDirect, "shell_c99"},
	{"r57shell", sigDirect, "shell_r57"},
	{"b374k", sigDirect, "shell_b374k"},
	{"FilesMan", sigDirect, "shell_filesmanager"},
	{"WSO shell", sigDirect, "shell_wso"},
	{"weevely3", sigDirect, "shell_weevely"},
	{"China Chopper", sigDirect, "shell_china_chopper"},
	{"safe_mode_bypass", sigDirect, "shell_safe_mode_bypass"},
	{"disable_functions_bypass", sigDirect, "shell_disable_functions"},

	// --- Indicators: obfuscation helpers ---
	// These appear in legitimate code (WordPress plugins, etc.) but 3+ together
	// is a strong signal of packed/obfuscated malware.
	{"base64_decode(", sigIndicator, "ind_base64_decode"},
	{"str_rot13(", sigIndicator, "ind_str_rot13"},
	{"gzinflate(", sigIndicator, "ind_gzinflate"},
	{"gzuncompress(", sigIndicator, "ind_gzuncompress"},
	{"gzdeflate(", sigIndicator, "ind_gzdeflate"},
	{"assert(", sigIndicator, "ind_assert"},
	{"create_function(", sigIndicator, "ind_create_function"},
	{"move_uploaded_file(", sigIndicator, "ind_move_uploaded_file"},
	{"@ini_set(\"display_errors\",0)", sigIndicator, "ind_hide_errors_dq"},
	{"@ini_set('display_errors',0)", sigIndicator, "ind_hide_errors_sq"},
}

// RegexSig is a regexp-based file signature. Each match is treated as sigDirect.
type RegexSig struct {
	Pattern *regexp.Regexp
	Label   string
}

// phpRegexSigs contains compiled regexp patterns for PHP that can't be
// expressed as simple substrings.
var phpRegexSigs = []RegexSig{
	{
		// preg_replace with /e modifier — executes matched string as PHP code.
		// Deprecated in PHP 5.5, removed in 7.0, but still found in old shells.
		regexp.MustCompile(`preg_replace\s*\(\s*['"][^'"]*\/e['"]`),
		"preg_replace_e_modifier",
	},
	{
		// High density of chr() calls concatenated — classic PHP obfuscation.
		regexp.MustCompile(`chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)\.chr\(\d+\)`),
		"chr_concatenation_obfuscation",
	},
}

// ============================================================
// Node.js signatures (Neo23x0/signature-base webshells.yar)
// ============================================================

var jsSigs = []FileSig{
	// --- Direct: RCE via request objects ---
	{"require('child_process').exec(req.", sigDirect, "rce_cp_exec_req_sq"},
	{"require(\"child_process\").exec(req.", sigDirect, "rce_cp_exec_req_dq"},
	{"require('child_process').execSync(req.", sigDirect, "rce_cp_execsync_req"},
	{"require('child_process').spawn(req.", sigDirect, "rce_cp_spawn_req"},

	// --- Direct: eval with decoded payload ---
	{"eval(Buffer.from(", sigDirect, "rce_eval_buffer_from"},
	{"eval(atob(", sigDirect, "rce_eval_atob"},

	// --- Direct: dynamic Function constructor from request ---
	{"new Function(req.body", sigDirect, "rce_new_function_body"},
	{"new Function(req.query", sigDirect, "rce_new_function_query"},
	{"new Function(req.params", sigDirect, "rce_new_function_params"},
	{"new Function(request.body", sigDirect, "rce_new_function_body2"},

	// --- Direct: VM sandbox escape ---
	{"vm.runInNewContext(req.", sigDirect, "rce_vm_new_context"},
	{"vm.runInThisContext(req.", sigDirect, "rce_vm_this_context"},

	// --- Indicators ---
	{"require('child_process')", sigIndicator, "ind_child_process_sq"},
	{"require(\"child_process\")", sigIndicator, "ind_child_process_dq"},
	{"process.binding(", sigIndicator, "ind_process_binding"},
}

// ============================================================
// Python signatures (Neo23x0/signature-base)
// ============================================================

var pythonSigs = []FileSig{
	// --- Direct: RCE via web framework request objects ---
	{"exec(request.args", sigDirect, "rce_exec_flask_args"},
	{"exec(request.form", sigDirect, "rce_exec_flask_form"},
	{"eval(request.args", sigDirect, "rce_eval_flask_args"},
	{"eval(request.form", sigDirect, "rce_eval_flask_form"},
	{"exec(request.GET", sigDirect, "rce_exec_django_get"},
	{"exec(request.POST", sigDirect, "rce_exec_django_post"},
	{"eval(request.GET", sigDirect, "rce_eval_django_get"},
	{"eval(request.POST", sigDirect, "rce_eval_django_post"},
	{"os.system(request.", sigDirect, "rce_os_system_request"},
	{"subprocess.call(request.", sigDirect, "rce_subprocess_request"},
	{"subprocess.Popen(request.", sigDirect, "rce_popen_request"},

	// --- Direct: eval with decoded payload ---
	{"exec(base64.b64decode(", sigDirect, "rce_exec_base64"},
	{"eval(base64.b64decode(", sigDirect, "rce_eval_base64"},
	{"exec(compile(base64.b64decode(", sigDirect, "rce_exec_compile_base64"},

	// --- Indicators ---
	{"base64.b64decode(", sigIndicator, "ind_base64_decode"},
	{"__import__('os').", sigIndicator, "ind_import_os"},
	{"__import__(\"os\").", sigIndicator, "ind_import_os_dq"},
}

// ============================================================
// Perl signatures (common CGI backdoors)
// ============================================================

var perlSigs = []FileSig{
	// --- Direct: RCE via CGI params ---
	{"system(param('", sigDirect, "rce_system_param"},
	{"exec(param('", sigDirect, "rce_exec_param"},
	{"system($q->param(", sigDirect, "rce_system_cgi_param"},
	{"system($ENV{'QUERY_STRING'})", sigDirect, "rce_system_query_string"},
	{"eval decode_base64(", sigDirect, "rce_eval_decode_base64"},

	// --- Indicators ---
	{"decode_base64(", sigIndicator, "ind_decode_base64"},
	{"$ENV{'HTTP_", sigIndicator, "ind_http_env_var"},
}

// ============================================================
// Universal signatures (applied to all scanned files)
// ============================================================

var universalSigs = []FileSig{
	// Reverse shell one-liners dropped as files (rare but definitive)
	{"bash -i >& /dev/tcp/", sigDirect, "reverse_shell_bash"},
	{"bash -c 'bash -i", sigDirect, "reverse_shell_bash2"},
	{"/bin/sh -i >& /dev/tcp/", sigDirect, "reverse_shell_sh"},
}

// sigsByExt maps file extension → slice of signatures to apply.
// Universal sigs are appended at match time.
var sigsByExt = map[string][]FileSig{
	".php":   phpSigs,
	".phtml": phpSigs,
	".php5":  phpSigs,
	".php7":  phpSigs,
	".phar":  phpSigs,
	".js":    jsSigs,
	".py":    pythonSigs,
	".pl":    perlSigs,
	".cgi":   perlSigs,
	".rb":    nil, // universal sigs only for now
}

// scanExts is the full set of extensions the web shell scanner processes.
var scanExts = func() map[string]bool {
	m := make(map[string]bool, len(sigsByExt))
	for ext := range sigsByExt {
		m[ext] = true
	}
	m[".rb"] = true
	return m
}()

// ============================================================
// Expanded crypto-miner patterns
// ============================================================

// expandedMinerNames contains process names (comm / cmdline) associated with
// known miners or malware that disguises itself as system processes.
var expandedMinerNames = []string{
	// Known miner binaries
	"xmrig", "minerd", "cpuminer", "ccminer", "cgminer", "bfgminer",
	"ethminer", "nbminer", "t-rex", "lolminer", "teamredminer",
	// Known malware process names (disguised as kernel threads)
	"kdevtmpfsi", "kworkerds", "kthreaddi", "kinsing",
	// Known disguise names used by post-exploitation frameworks
	"sysupdate", "networkservice", "systemd-network", "pamdicks",
}

// expandedMinerArgs contains strings found in process arguments that
// strongly indicate miner activity.
var expandedMinerArgs = []string{
	"stratum+tcp://",
	"stratum+ssl://",
	"stratum2+tcp://",
	"--donate-level",
	"--algo ",
	"-o stratum",
	"pool.minexmr.com",
	"supportxmr.com",
	"xmrpool.eu",
	"hashvault.pro",
	"moneroocean.stream",
	"gulf.moneroocean.stream",
}

// ============================================================
// Expanded cron suspicious patterns
// ============================================================

var expandedCronPatterns = []*regexp.Regexp{
	// Download and pipe to shell
	regexp.MustCompile(`curl\s+.*\|\s*.*sh`),
	regexp.MustCompile(`wget\s+.*\|\s*.*sh`),
	// Download to /tmp and execute
	regexp.MustCompile(`curl\s+.*-[oO]\s+/tmp/`),
	regexp.MustCompile(`wget\s+.*-[oO]\s+/tmp/`),
	regexp.MustCompile(`curl\s+.*-[oO]\s+/var/tmp/`),
	// Base64 decode and execute
	regexp.MustCompile(`base64\s+-d`),
	regexp.MustCompile(`base64\s+--decode`),
	// Executing files from temp dirs
	regexp.MustCompile(`/dev/shm/`),
	regexp.MustCompile(`/tmp/[^\s]*\.sh`),
	regexp.MustCompile(`/var/tmp/[^\s]*\.sh`),
	// Reverse shell patterns
	regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/tcp/`),
	regexp.MustCompile(`/bin/bash\s+-c\s+['"]bash\s+-i`),
	// Python reverse shell
	regexp.MustCompile(`python\s+-c\s+['"]import socket`),
	// chmod + execute from temp
	regexp.MustCompile(`chmod\s+\+x\s+/tmp/`),
	regexp.MustCompile(`chmod\s+\+x\s+/var/tmp/`),
}
