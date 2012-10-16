# yarad
## yara daemon

yarad deploys a server that can be used to scan files and streams centrally with yara and your own ruleset.

Requirements:

	- yara-python
	- python-daemon (if you want to daemonize it)

See yarad.cfg for configuration options.

# pyarad
## python library to interact with yarad

pyarad allows you to interact with yarad server from your python scripts.

It implements this functions:

y = init\_network\_socket(host, port=3369)

y = init\_unix\_socket(socket\_file="/tmp/yarad.ctl")

y.close()

y.scan\_file(filename)

y.scan\_stream(filebuffer)

See examples for more information.
