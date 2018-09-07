# Disposable

![Logo](https://raw.githubusercontent.com/jlxip/Disposable-Client/master/UI/MainImage/MainImage.png)

## The basics
**Disposable is an anonymous, cryptographically secure, semi-decentralized and multiplatform instant messaging program written in Python.**

It's based on nodes, which act as intermediaries between clients. These nodes are in charge of delievering the encrypted messages, [and can run one if you want](https://github.com/jlxip/Disposable-Node), that's what makes Disposable semi-decentralized. The clients and the nodes share a common protocol, specifically designed for keeping the transmission anonymous and encrypted, with some clever security protections that make Man In The Middle attacks and malicious nodes impossible to run. If you are interested in the protocol, have a look at the node README. You should have a VPN running in order to keep your IP safe from the node you're connecting to, in case it has been _hacked_ to keep logs.

To connect to a node, you have to get its node connection file via a secure channel (such as HTTPS). It will be required when creating a new identity. There's an official Disposable node, whose file you can download [here](https://jlxip.net/node.dat).

There are no users in Disposable, but **identities**. These are shared via a 32-bytes long string, known as _client identity hash_ (CID). To exchange messages with a person, you have to exchange first your CIDs via a secure channel as well. Even though only one person needs the other one's CID to establish a chat, if they send theirs as well, both of them can be sure that no one is impersonating them.

An identity in the node A cannot connect to another one in the node B. But you can have as many identities as you want from any of the nodes.

## Installation
First, you need to have installed Python 2.7 (Click [here](https://www.python.org/downloads/) for Windows, in GNU/Linux is installed by default), as well as some dependencies: PyCrypto, PyQt4, PyGame, Numpy and qdarkstyle.

### GNU/Linux
In Debian-based GNU/Linux distributions, you can install them easily with the following commands:
```
sudo apt install python-crypto python-qt4
sudo pip install pygame numpy qdarkstyle
```

### Windows
In Windows you have two options.

You can run an installer (which is in the "releases" tab of this very page), with which you won't have to configure anything and it will be much easier to set up. However, the installer is really heavy (~200MB).

Or you can run the program directly with python and all the dependences satisfied, but this will be harder to set up. If you are a developer or you know enough about computers, I'd recommend this option.

In both cases, make sure to install the certificate of Let's Encrypt (explained at the end of the manual tutorial).

#### Manual installation
First you have to install PyCrypto.

If you have a full C/C++ development environment installed (such as Visual Studio), you can install it with pip as well.

If you don't, or you really don't want to have any problems at all, run the following for x86_64:

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

And install PyGame, Numpy and qdarkstyle as well:

```
C:\Python27\Scripts\pip.exe install pygame numpy qdarkstyle
```

If you run Disposable now, there might be an issue with file transfers in Windows. This is because Windows lacks the Let's Encrypt certificate in its certificate store. You can fix this by installing the Let's Encrypt certificate. Go [here](https://transfer.sh), and follow these instructions:

If you use Firefox, click at the green lock at the left of the URL, click the arrow and "More information". Then, hit "View certificate", "Details", "Let's Encrypt Authority X3" and save it with "Export". Then, open the file, and install the certificate.

If you use Chrome, it's pretty much the same deal.

## Running
In order to run it, if you are on GNU/Linux or you have installed it in Windows by the manual method, then you just have to do:

```
python disposable.py
```

If you have installed it by the installer, just run the shortcut to the program.

You should be done. Disposable will open.

## Quick start
First of all, you have to add a node to Disposable. In the menu, enter "Identities" and click "Nodes". Then, hit the "+" button and select a node file connection (you have the official one at the top of this file).

Once you are done, close the window, and it's time to create an identity. Go to "Identities" and click "New identity". Select a node from the list, and click "CREATE".

A new tab should appear in the program, with an alphanumeric name. Change it in "Identities"->"Rename". Set a name that you will be able to recognise. For instance, "Friends". As it has been said before, you can have as many identities as you want. They will be kept isolated from each other in order for you to remain anonymous.

In "Identities"->"Show hash" you can see your CID, as well as export the node connection file of the node related to the current identity. You can send both to anyone, while it's through a secure channel (in the best case scenario, by hand; in the worst case scenario, through Facebook).

If you want to chat with someone, click the button "+", and enter the CID of the other person. It should be added to your chats list with a name representing a shortened version of the CID. Right click it, and "Rename". Double click it, and start messaging.

In the menu "Preferences", you can both increase and decrease the font size of the messages box, as well as disable the notification sound.

If you wish to transfer a file, click the "FILE" button in a chat, select it, and hit "UPLOAD". The file will be encrypted with the same method as your messages, and will be uploaded to [transfer.sh](https://transfer.sh), where it will be kept for 14 days. There's a limit of 10GB. When the other person clicks "Download", it will be inserted into their database. Then, the "download" link will change to "copy" and "delete". If you click "copy", you will be able to save the file anywhere you want. If you click "delete", it will be deleted from the database, in case you need to free space.

That's everything you should know. Good luck with secure and anonymous messaging.
