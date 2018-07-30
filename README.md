# Disposable

![Logo](https://git.jlxip.net/jlxip/Disposable-Client/raw/2b131144d2a31c8a72e41fae89f567ebe87855d4/UI/MainImage/256x256.png)

## The basics
**Disposable is an anonymous, cryptographically secure, semi-decentralized and multiplatform instant messaging program written in Python.**

It's based on nodes, which act as intermediaries between clients. These nodes are in charge of delievering the encrypted messages, [and anyone can run one](https://git.jlxip.net/jlxip/Disposable-Node). The clients and the nodes share a common protocol, specifically designed for keeping the transmission anonymous and encrypted, with some clever security protections that make Man In The Middle attacks and malicious nodes impossible to run. If you are interested in the protocol, have a look at the node README.

To connect to a node, you have to get its `node.dat` file via a secure channel (such as HTTPS), which contains the IP of the node, the port, and a public key for making the secure transmission of messages.

There are no users in Disposable, but **identities**. These are shared via a 32-bytes long string, known as _client identity hash_ (CID). To exchange messages with a person, you have to exchange first your CIDs via a secure channel as well. Even though only one person needs the other one's CID to establish a chat, if they send theirs as well, both of them can be sure that no one is impersonating them.

## Installation
First, you need to have installed Python 2.7 (Click [here](https://www.python.org/downloads/) for Windows, in GNU/Linux is installed by default), as well as some dependencies: PyCrypto, PyQt4 and PyGame.

### GNU/Linux
In Debian-based GNU/Linux distributions, you can install them easily with the following commands:
```
sudo apt install python-crypto python-qt4
sudo pip install pygame
```

### Windows
If you are on Windows, first you have to install PyCrypto.

If you have a full C/C++ development environment installed, you can install it with pip as well.

If you don't, you can try the following for x86_64:

```
C:\Python27\Scripts\easy_install.exe http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win-amd64-py2.7.exe
```

Or this if you have x86:

```
C:\Python27\Scripts\easy_install.exe http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win32-py2.7.exe
```

Alternatively, if you encounter any error during installation, you can try installing the MSI files. [This one](http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win-amd64-py2.7.msi) for x86_64, or [this one](http://www.voidspace.org.uk/python/pycrypto-2.6.1/pycrypto-2.6.1.win32-py2.7.msi) for x86.

Then, you have to install PyQt4. You can try [going here](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyqt4), and downloading either _PyQt4‑4.11.4‑cp27‑cp27m‑win\_amd64.whl_ (x86_64) or _PyQt4‑4.11.4‑cp27‑cp27m‑win32.whl_ (x86), depending on your architecture. However, that website is terribly slow, so I've updated them to my server, so you can have a decent download speed. [This one](https://jlxip.net/mirror/PyQt4-4.11.4-cp27-cp27m-win_amd64.whl) for x86_64 and [this one](https://jlxip.net/mirror/PyQt4-4.11.4-cp27-cp27m-win32.whl) for x86.

Finally, in the directory of the download, run:

```
C:\Python27\Scripts\pip.exe install PyQt4[Tab]
```

And install PyGame as well:

```
C:\Python27\Scripts\pip.exe install pygame
```

## Running
In order to run it, you just have to do:

```
python disposable.py
```

And you should be done. Alternatively, you can set files with `.py` extension to be opened with python, and just double click. However, it's recommended running in a terminal so that if any error is printed out, the user can report it.

SIGO LUEGO JEJEJE