# Copyright 2012 Dominik Ruf <dominikruf@gmail.com>
# Copyright 2020 - 2023 Geert Lorang
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#
# Version history:
#
# 2012-01-01 - v1.0 - Dominik Ruf - Initial version
# 2020-06-15 - v1.1 - glorang - Add support for Python 3 / Mercurial 5
# 2022-04-08 - v1.2 - glorang - Add support for keytabs on Linux and macOS
# 2022-10-11 - v1.6 - glorang - Add support for ToroiseHG >= 6.2 (Windows, Python 3)
#

''' Automatically authenticate to servers protected with Kerberos/NTLM/SSPI (e.g. Active Directory)
'''

import os, sys

# Import platform independent modules
try:
	import mercurial.url

	# Python 2.7
	if(sys.version_info.major < 3):
		import urllib2 as urllib
		import ConfigParser as configparser
		from base64 import encodestring as encodebytes
	# Python 3 
	else:
		import urllib.request as urllib
		import configparser
		from base64 import encodebytes

except ImportError as e:
	print("Could not import all required modules, error was: %s" % str(e))
	sys.exit(1)

# Import Windows or Linux/macOS specific module
try:
	from sspi import ClientAuth # requires pywin32 extension
	import socket

except ImportError as e:
	try:
		# Linux/macOS
		import kerberos
	except ImportError as e:
		print("pywin32 (Windows) or python(3)-kerberos (Linux/macOS) module not found, error was: %s" % str(e))
		sys.exit(1)

# Windows
class SSPIAuthHandler(urllib.BaseHandler):
	"""auth handler for urllib2 that does Kerberos/NTLM/SSPI HTTP Negotiate Authentication
	"""
	handler_order = 480  # TODO: test this by enabling basic auth
    
	def __init__(self, ui=None, passmgr=None):
		pass
    
	def http_error_401(self, req, fp, code, msg, headers):
		supported_schemes = [s.strip() for s in headers.get("WWW-Authenticate", "").split(",")]

		# Fall back to user/password auth if server does not support Negotiate
		if('Negotiate' not in supported_schemes):
			print("Server does not support Kerberos authentication")
			return None

		# Try Kerberos authentication
		try:
			ca = ClientAuth("Kerberos", targetspn='HTTP/%s@%s' % (socket.gethostbyname_ex(req.host.split(':')[0])[0], os.environ['USERDNSDOMAIN']), auth_info=None)
			out_buf = ca.authorize(None)[1]
			data = out_buf[0].Buffer
			auth = encodebytes(data).decode('utf-8').replace("\012", "")
			req.add_header('Authorization', 'Negotiate' + ' ' + auth)
			return self.parent.open(req)
		except Exception as e:
			print("Kerberos error: %s" % str(e))

			# temporary workaround for https://bz.mercurial-scm.org/show_bug.cgi?id=6343
			if(sys.version_info.major == 3):
				sys.exit(1)
			else:
				return None

# Linux / macOS
class KerberosAuthHandler(urllib.BaseHandler):
	"""auth handler for urllib2 that does Kerberos HTTP Negotiate Authentication
	"""

	handler_order = 480

	def __init__(self, ui, passmgr):

		# Get a Kerberos ticket from a keytab if specified in .hgrc
		# If the ticket is still valid we will not init a new one

		import subprocess
		from os.path import isfile, expanduser
		from os import geteuid

		hgrcpath = "%s/.hgrc" % expanduser("~")

		if isfile(hgrcpath):
			hgrc = configparser.ConfigParser()
			hgrc.read(hgrcpath)

			keytab = None
			if hgrc.has_option("krb", "keytab"):
				keytab = expanduser(hgrc.get("krb", "keytab"))

			principal = None
			if hgrc.has_option("krb", "principal"):
				principal = hgrc.get("krb", "principal")

			if keytab and isfile(keytab) and principal:

				# Always use a fixed Kerberos cache on disk if keytab is specified in .hgrc
				krb5ccname = "/tmp/krb5cc_%s" % geteuid()
				os.environ['KRB5CCNAME'] = krb5ccname # Works around some weird issues on macOS with their API caches

				klist = subprocess.run(["/usr/bin/klist", "-c", krb5ccname, "-s"])

				if klist.returncode != 0:

					print("No valid kerberos ticket found, trying keytab")

					kinit = subprocess.run(["/usr/bin/kinit", "-k", "-c", krb5ccname, "-t", keytab, principal])
					if kinit.returncode == 0:
						print("Succesfully obtained Kerberos ticket from keytab")

	def http_error_401(self, req, fp, code, msg, headers):
		supported_schemes = [s.strip() for s in headers.get("WWW-Authenticate", "").split(",")]

		# Fall back to user/password auth if server does not support Negotiate
		if('Negotiate' not in supported_schemes):
			print("Server does not support Kerberos authentication")
			return None

		# Python 2 vs 3 foo
		if(sys.version_info.major < 3):
			r = req.get_host()
		else:
			r = req.host

		# Try Kerberos authentication
		context = kerberos.authGSSClientInit("HTTP@%s" % r.split(':')[0])[1]
		try:
			kerberos.authGSSClientStep(context, supported_schemes[0])
		except kerberos.GSSError as e:
			print("Kerberos GSS Error: %s" % str(e))

			# temporary workaround for https://bz.mercurial-scm.org/show_bug.cgi?id=6343
			if(sys.version_info.major == 3):
				sys.exit(1)
			else:
				return None

		response = kerberos.authGSSClientResponse(context)
		req.add_unredirected_header('Authorization', "Negotiate %s" % response)
		resp = self.parent.open(req)
		# make sure the response came from the correct server
		server_token = resp.info().get("WWW-Authenticate", "").split(",")[0].split()[1]
		server_auth_result = kerberos.authGSSClientStep(context, server_token)
		if(server_auth_result < 1):
			raise Exception("Server authentication error: %s" % str(server_auth_result))
		return resp
		
def uisetup(ui):
	if('ClientAuth' in globals()):
		mercurial.url.handlerfuncs.append(SSPIAuthHandler)
	if('kerberos' in globals()):
		mercurial.url.handlerfuncs.append(KerberosAuthHandler)
