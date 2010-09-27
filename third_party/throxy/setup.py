"""Throttling HTTP proxy in one Python file

* Simulate a slow connection (like dial-up).
* Adjustable bandwidth limit for download and upload.
* Optionally dump HTTP headers and content for debugging.
* Decompress gzip content encoding for debugging.
* Multiple connections, without threads (uses asyncore).
* Only one source file, written in pure Python.
"""

from distutils.core import setup

doc_lines = __doc__.split('\n')
description = doc_lines[0]
long_description = '\n'.join(doc_lines[1:]).rstrip()

classifiers = filter(None, map(str.strip, """
Development Status :: 4 - Beta
License :: OSI Approved :: MIT License
Programming Language :: Python

Intended Audience :: Information Technology
Intended Audience :: System Administrators
Intended Audience :: Developers

Topic :: Internet :: WWW/HTTP
Topic :: Internet :: WWW/HTTP :: Browsers
Topic :: Internet :: WWW/HTTP :: HTTP Servers
Topic :: Internet :: WWW/HTTP :: Dynamic Content
""".split('\n')))

setup(
    name='throxy.py',
    version='0.1',
    description=description,
    long_description=long_description,
    license='http://www.opensource.org/licenses/mit-license.php',
    author='Johann C. Rocholl',
    author_email='johann@rocholl.net',
    url='http://github.com/jcrocholl/throxy/raw/master/throxy.py',
    classifiers=classifiers,
    platforms=['any'],
    scripts=['throxy.py'],
    )
