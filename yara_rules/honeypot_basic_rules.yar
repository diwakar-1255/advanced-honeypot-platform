rule Suspicious_Shell_Downloader
{
    meta:
        description = "Detects shell downloader behavior"
        author = "Advanced Honeypot Platform"
    strings:
        $wget = "wget "
        $curl = "curl "
        $chmod = "chmod +x"
        $bash = "/bin/bash"
        $sh = "/bin/sh"
    condition:
        any of them
}

rule Possible_Reverse_Shell
{
    meta:
        description = "Detects common reverse shell indicators"
        author = "Advanced Honeypot Platform"
    strings:
        $nc1 = "nc -e"
        $nc2 = "netcat"
        $bash_tcp = "/dev/tcp/"
        $python_socket = "socket.socket"
        $perl_socket = "IO::Socket"
    condition:
        any of them
}

rule Suspicious_Encoded_Payload
{
    meta:
        description = "Detects encoded payload patterns"
        author = "Advanced Honeypot Platform"
    strings:
        $b64_1 = "base64 -d"
        $b64_2 = "base64 --decode"
        $eval = "eval("
        $frombase64 = "FromBase64String"
    condition:
        any of them
}

rule Suspicious_Webshell
{
    meta:
        description = "Detects simple PHP webshell patterns"
        author = "Advanced Honeypot Platform"
    strings:
        $php = "<?php"
        $system = "system("
        $shell_exec = "shell_exec("
        $passthru = "passthru("
        $cmd = "$_GET['cmd']"
    condition:
        $php and any of ($system, $shell_exec, $passthru, $cmd)
}
