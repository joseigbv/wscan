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
	'http_pass': '12345',

	# configuracion via proxy
	'proxies': {},

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
}


# variables runtime
RUN = \
{
	'index': '',
	'scope': '',
	'server_version': '',
	'server_timestamp': '',
	'exts_excl': CFG['exts_excl'],
	'dir': {},
}


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

#	valid_urls = [ 
#	]

	# por defecto busca "404 not found" en el contenido
	#return 404 if code in [ 400, 403, 500, 501 ] else code
	#return 404 if re.search('404.*not found', content) else code

#	if url in valid_urls: return 200 

	return 404 if \
		(code == 400) \
		else code
#		(code == 400 and re.search('gina no ha sido encontrada', content)) or \
#		(code == 200 and re.search('gina no encontrada', content)) or \
#		(code == 302 and re.search('aspxerrorpath', '%s\n' % headers)) or \


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

	lck_crawled = None
	lck_links = None
	lck_urls_base = None
	lck_urls_fake = None
	lck_dirs = None
	lck_files = None
	lck_exts = None


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

		# candados threads
		self.lck_crawled = thread.allocate_lock()
		self.lck_links  = thread.allocate_lock()
		self.lck_urls_base = thread.allocate_lock()
		self.lck_urls_fake = thread.allocate_lock()
		self.lck_dirs = thread.allocate_lock()
		self.lck_files = thread.allocate_lock()
		self.lck_exts = thread.allocate_lock()


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


	# salvamos estado para posterior resume
	def save_state(self): 
	
		save_var(self.links, 'crawler_links')
		save_var(self.crawled, 'crawler_crawled')
		save_var(self.urls_base, 'crawler_urls_base')
		save_var(self.urls_fake, 'crawler_urls_fake')
		save_var(self.dirs, 'crawler_dirs')
		save_var(self.files, 'crawler_files')
		save_var(self.exts, 'crawler_exts')


	# restauramos estado para resume
	def load_state(self): 
	
		self.links = load_var('crawler_links')
		self.crawled = load_var('crawler_crawled')
		self.urls_base = load_var('crawler_urls_base')
		self.urls_fake = load_var('crawler_urls_fake')
		self.dirs = load_var('crawler_dirs')
		self.files = load_var('crawler_files')
		self.exts = load_var('crawler_exts')

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

	# variables globales
	save_var(RUN, 'run')
	save_var(CFG, 'cfg')


""" cargamos resultados de ficheros """
def load_state():

	global RUN
	global CFG

	# crawler y navegacion
	CRAWLER.load_state()
	NAV.load_state()

	# variables globales
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


""" genera fichero a partir de url """
def url2fname(url):
	return CFG['dir'] + url.replace(
		RUN['scope'], '/').replace('/', ':')
	

""" calcula el directorio a partir de url """
def urldir(url): 
	return url if url[-1] == '/' \
		else '/'.join(url.split('/')[:-1]) + '/'


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
	return url[0:len(RUN['scope'])] == RUN['scope'] and url[len(RUN['scope'])] == '/'


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

	# probamos cada expresion regular
	for regexp in regexps:

		# registramos link
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

				# si existe, mime valido y es accesible navegamos
				if not code in [ 400, 401, 403, 404 ]:

					# crawling solo si mimetype texto
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

	# estadisticas crawler 
	pout("\n* Crawler:\n")
	CRAWLER.report()

	# estadisticas navegacion
	pout("\n* Estadisticas Navegacion:\n")
	NAV.report()

	pout("\n(fin report)\n")


""" imprimimos banner de uso """
def usage(): 

	# mostramos banner
	print "\n(w) 'Crawler v0.4' - (c) 2012 Jose Ignacio Bravo\n"
	print "usa: python crawler.py <url>\n"


""" inicializa scan """
def init(): 

	global NAV
	global CRAWLER
	global RUN

	# nivel de recursion
	MAX_RECURSION = 10000

	# maxima recursion
	sys.setrecursionlimit(MAX_RECURSION)

	# no buffering
	sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

	# inicializamos crawler
	RUN['index'] = norm_url(CFG['index'])

	# saneamos url y generams url base 
	scheme, netloc, path, query = parse_url(RUN['index'])
	path = re.sub('/[^/]*$', '', path)

	# designamos alcance del crawling
	RUN['scope'] = scheme + '://' +  netloc +  path

	# directorio de salida ? 
	CFG['dir'] = CFG['dir'] + '/' + netloc + '/'

	# si no existe, creamos
	if not os.access(CFG['dir'], os.F_OK): 
		os.makedirs(CFG['dir'])

	# inicializamos navegador
	NAV = Navigator()

	# inicializamos crawler
	CRAWLER = Crawler()


""" scan index """
def scan(index): 

	# comenzamos a navegar
	pinfo("* Crawling...")
	chk_url(index)


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


""" funcion principal """
def main(argv): 

	global CFG

	# banner
	usage()

	# paramoetros de entrada ?
	if len(argv) < 2: 

		# indicar url, please 
		pabort('Parametros incorrectos')

	# empieza por http ?
	if not re.match('^https?://.*$', argv[1]):

		# por defecto http
		argv[1] = 'http://' + argv[1]
		
	# url de inicio
	CFG['index'] = argv[1] 

	# inicializa
	pinfo("* Inicializando...")
	init()

	# comprobamos servidor
	pinfo("* Comprobando servidor...")
	check_server()

	# resume
	pinfo("* Buscando ejecuciones anteriores...")
	resume()

	try:
		# crawling 
		scan(RUN['index'])

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

