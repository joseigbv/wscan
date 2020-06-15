# wscan

Web scanner and crawler in python (work in progress).

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Python interpreter.

### Installing

Download a copy of the project from github:

```
$ git clone https://github.com/joseigbv/wscan.git
```

Edit configuration: 

```
...
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
        'db_tests': '/opt/nikto-2.1.5/databases/db_tests',

        # lista de plugins activos
        'plugins': \
        {
                1001: True,     # search robots
                1002: True,     # search in google
                1004: True,     # search forms
                1005: True,     # search web server
                1006: True,     # directory listing
                1007: True,     # search default page
                1008: True,     # search backups
                1009: True,     # search logs
                1010: True,     # known pages and directories
                1011: True,     # fuzzing general
                1012: True,     # search mails
                1013: True,     # search comments
                1014: True,     # search info leaks
                1015: True,     # search errors
                1016: True,     # check auth
                1017: True,     # testing http methods
                1018: True,     # testing arbitrary http methods
                1019: True,     # head acces control bypass
                1020: True,     # testing xst
                1021: True,     # file extensions handling
...
               1029: True,     # xss
                1030: True,     # nikto tests
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
                '^.*www.perusabe.com.pe\/wp-content\/themes\/perusabe\/js\/$',
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
...
```


### Usage

```
usa: python wscan.py [url]
```

For example:

```
$ python wscan.py http://testasp.vulnweb.com
```

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details


