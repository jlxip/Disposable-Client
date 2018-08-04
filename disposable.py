#!/usr/bin/env python2.7
# -*- encoding: utf-8 -*-

import socket, os, data, cryptic, sys, base64, hashlib, sqlite3, time, datetime, json, unzalgo, unicodedata, urllib2, struct
from PyQt4 import QtCore, QtGui, uic
from pygame import mixer
from threading import Thread
from StringIO import StringIO

UIdirectory = 'UI'+os.sep
mainwindow_fc = uic.loadUiType(UIdirectory+'mainwindow.ui')[0]
identity_ui = uic.loadUiType(UIdirectory+'identity.ui')[0]
invalid_ui = uic.loadUiType(UIdirectory+'invalid.ui')[0]
identityhash_ui = uic.loadUiType(UIdirectory+'identityhash.ui')[0]
sendfile_ui = uic.loadUiType(UIdirectory+'sendfile.ui')[0]
downloadingdialog_ui = uic.loadUiType(UIdirectory+'downloading.ui')[0]

messagesFontFamily = 'Monospace'

def connectToNode():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((NODE[0], NODE[1]))
	except:
		msg = QtGui.QMessageBox()
		msg.setIcon(QtGui.QMessageBox.Critical)
		msg.setText('Disposable could not connect to the node.')
		msg.setInformativeText('Check if your \'node.dat\' file is correct.')
		msg.exec_()
		exit()
	return s

def keyExchange():
	s = connectToNode()
	pub = cryptic.getRSACipher(NODE[2])
	thisAES = cryptic.genRandomAESKey()
	thisIV = cryptic.genIV()
	data.send_msg(s, pub.encrypt(thisAES+thisIV))

	if cryptic.decrypt(thisAES, thisIV, data.recv_msg(s)) == 'OK':
		return s, thisAES, thisIV
	else:
		return False

def authenticate(CID, priv):
	try:
		s, thisAES, thisIV = keyExchange()
	except:
		print 'Something went horribly wrong (AUTH).'
		exit()
	data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x01'+CID))
	random = cryptic.decrypt(thisAES, thisIV, data.recv_msg(s))
	if random == '\x01':
		return (None, False, None, None)
	if priv == '':	# Just checking if the user exists in the node
		data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x00'))
		s.close()
		return (False, False, None, None)
	tmpcipher = cryptic.getRSACipher(priv)
	random = tmpcipher.decrypt(random)
	data.send_msg(s, cryptic.encrypt(thisAES, thisIV, random))
	return (s, cryptic.decrypt(thisAES, thisIV, data.recv_msg(s)) == '\x00', thisAES, thisIV)

class downloadingdialog(QtGui.QDialog, downloadingdialog_ui):
	def __init__(self, parent):
		super(downloadingdialog, self).__init__(parent)
		self.setupUi(self)

def escapeHTMLString(s):
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

sizeToStringAppends = [' bytes', 'kB', 'MB', 'GB']
def sizeToString(size_):
	try:
		size = float(size_)
		ret = ''
		k = 0
		while not int(size) == 0:
			size /= 1000	# I just learned that 1kB=1000 bytes. I always thought it was 1024 bytes. Weird.
			k += 1
		size *= 1000; k -= 1
		if not k < len(sizeToStringAppends):
			return 'more that 1TB'
		size = str(size)
		return size[:size.index('.')+3]+sizeToStringAppends[k]
	except:
		return False

class BufferReader(StringIO):
	# Note: this class was stolen from http://foobarnbaz.com/2012/12/31/file-upload-progressbar-in-pyqt/

    def __init__(self, buf='', callback=None, cb_args=(), cb_kwargs={}):
        self._callback = callback
        self._cb_args = cb_args
        self._cb_kwargs = cb_kwargs
        self._progress = 0
        StringIO.__init__(self, buf)

    def read(self, n=-1):
        chunk = StringIO.read(self, n)
        self._progress += int(len(chunk))
        self._cb_kwargs.update({'progress': self._progress})
        try:
        	self._callback(*self._cb_args, **self._cb_kwargs)
        except:
            raise
        return chunk

def update_progress(progressbar, size, progress=None):
	if progressbar.wasCanceled():
		raise
	progressbar.setValue(progress)

class sendfile(QtGui.QDialog, sendfile_ui):
	def __init__(self, parent, ALIAS, PUB):
		super(sendfile, self).__init__(parent)
		self.setupUi(self)
		self.parent = parent
		self.PUB = PUB
		self.hint.setText('Send a file to %s.' % ALIAS)
		self.selectfile_btn.clicked.connect(self.selectfile)
		self.uploadfile_btn.clicked.connect(self.uploadfile)

	def selectfile(self):
		f = QtGui.QFileDialog.getOpenFileName()
		if f == '':
			return
		self.selectedfile.setText(f)
		self.uploadfile_btn.setEnabled(True)

	def uploadfile(self):
		f = str(self.selectedfile.text().toUtf8())
		if not os.path.isfile(f):
			msg = QtGui.QMessageBox()
			msg.setIcon(QtGui.QMessageBox.Critical)
			msg.setText('File not found.')
			msg.exec_()
			return
		_FILENAME = f.split(os.sep)[-1]
		FILENAME = urllib2.quote(_FILENAME)
		with open(f, 'rb') as f:
			data = f.read()

		# Insert into my files
		global DB
		cursor = DB.cursor()
		cursor.execute(
			"INSERT INTO FILES (NAME, SIZE, CONTENT) VALUES (?, ?, ?)",
			(_FILENAME, len(data), base64.b64encode(data))
		)
		for i in cursor.execute("SELECT ID FROM FILES ORDER BY ID DESC LIMIT 1"):
			fileID = i[0]

		# Encrypt file (same procedure as sendMessage)
		thisFileAES = cryptic.genRandomAESKey()	# First, generate a random AES key
		data = cryptic.encrypt(thisFileAES, chr(0)*16, data)	# Encrypt 'data' with the AES key
		thisFileAES = self.PUB.encrypt(thisFileAES)	# Encrypt the AES key with their public key
		data = struct.pack('>I', len(thisFileAES)) + thisFileAES + data

		SIZE = len(data)

		progressDialog = QtGui.QProgressDialog('Uploading %s...' % FILENAME, QtCore.QString('Cancel'), 0, SIZE)
		progressDialog.setWindowTitle('Upload status')
		progressDialog.setWindowModality(QtCore.Qt.WindowModal);
		databuf = BufferReader(buf=data, callback=update_progress, cb_args=(progressDialog, SIZE))

		# Upload the actual file
		req = urllib2.Request('https://transfer.sh/'+FILENAME, databuf, {'Content-Length': SIZE})
		req.get_method = lambda: 'PUT'
		try:
			urlobj = urllib2.urlopen(req)
		except:
			return
		result = urlobj.read()	# Get the URL of the file

		self.parent.writemsg.setText('[_F_]!'+str(SIZE)+'|'+result)
		self.parent.sendMessage()

		# Update my messages
		for i in cursor.execute(
			"SELECT ID FROM MESSAGES WHERE ME=? AND THEY=? ORDER BY ID DESC LIMIT 1",
			(self.parent.ME, self.parent.chats[self.parent.chatslist.selectedIndexes()[0].row()][0])
		):
			messageID = i[0]
		cursor.execute("UPDATE MESSAGES SET CONTENT=? WHERE ID=?", ('[_FR_]!'+str(fileID), messageID))
		DB.commit()

		self.parent.updateMessages()

		self.close()

class invalidtab(QtGui.QWidget, invalid_ui):
	def __init__(self):
		super(invalidtab, self).__init__(None)
		self.setupUi(self)

class listenThread(QtCore.QThread):
	def __init__(self, parent):
		QtCore.QThread.__init__(self, parent)
		self.signal = QtCore.SIGNAL('signal')
		self.parent = parent
	def run(self):
		s, result, thisAES, thisIV = authenticate(self.parent.ME, self.parent.PRIV)
		if not result:
			print 'Something went horribly wrong (LISTEN).'
			exit()
		data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x00'))

		while True:
			try:
				r = cryptic.decrypt(thisAES, thisIV, data.recv_msg(s))
			except:
				s.close()
				break
			self.emit(self.signal, r)

class identitytab(QtGui.QWidget, identity_ui):
	def __init__(self, ME, PRIV, ALIAS, tabIndex, parent):
		super(identitytab, self).__init__(None)
		self.setupUi(self)
		self.newchat_btn.clicked.connect(self.newchat)
		self.ME = ME
		self.PRIV = PRIV
		self.ALIAS = ALIAS
		self.tabs = parent.identitiestab
		self.tabIndex = tabIndex
		self.writingtimers = []
		self.parent = parent
		self.chats = []
		self.chatslist.doubleClicked.connect(self.chatsListClicked)
		self.chatslist.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
		self.chatslist.customContextMenuRequested.connect(self.chatOptions)
		self.writemsg.textEdited.connect(self.sendWritingSignal)
		self.writemsg.returnPressed.connect(self.sendMessage)
		self.sendfile_btn.clicked.connect(self.sendfileclicked)
		self.messages.anchorClicked.connect(self.anchorclicked)
		self.writemsg.setFont(QtGui.QFont(messagesFontFamily))

		global PREFERENCES
		self.messages.setFont(QtGui.QFont(messagesFontFamily, PREFERENCES['font-size']))

		self.SEND, _result, self.thisAES, self.thisIV = authenticate(self.ME, self.PRIV)
		if not _result:
			print 'Something went horribly wrong (NOT-AUTHENTICATE).'
			exit()
		data.send_msg(self.SEND, cryptic.encrypt(self.thisAES, self.thisIV, '\x01'))

		self.updateChatsList()

		thread = listenThread(self)
		self.connect(thread, thread.signal, self.messageReceived)
		thread.start()

	def anchorclicked(self, url_):
		global DB
		cursor = DB.cursor()
		url = str(url_.toString())

		if url[:6] == '[_F_]!':
			url = url[6:].split('|')
			size = int(url[0])
			id = url[2]
			url = url[1]
			filename = url.split('/')[-1]
			# The url was decoded when it passed through the anchor. Now, encode it again.
			url = url[:url.index(filename)] + urllib2.quote(filename)

			# Download
			downloading = downloadingdialog(self)
			downloading.show()
			response = urllib2.urlopen(url)
			data = response.read()
			downloading.close()

			# Decrypt (same procedure as in messageReceived)
			keylength = struct.unpack('>I', data[:4])[0]
			data = data[4:]
			msg_key = cryptic.getRSACipher(self.PRIV).decrypt(data[:keylength])
			msg_content = cryptic.decrypt(msg_key, chr(0)*16, data[keylength:])

			msg_content = base64.b64encode(msg_content)

			# Insert into database
			THEY = self.chats[self.chatslist.selectedIndexes()[0].row()][0]
			cursor.execute(
				"INSERT INTO FILES (NAME, SIZE, CONTENT) VALUES (?, ?, ?)",
				(filename, str(size), msg_content)
			)

			# Get the ID of the inserted file
			for i in cursor.execute("SELECT ID FROM FILES ORDER BY ID DESC LIMIT 1"):
				insertedID = i[0]

			# Update database
			cursor.execute("UPDATE MESSAGES SET CONTENT=? WHERE ID=?", ('[_FR_]!'+str(insertedID), id))

			DB.commit()

			# Update messages
			self.updateMessages()
		elif url[:4] == 'COPY':
			for i in cursor.execute("SELECT NAME, CONTENT FROM FILES WHERE ID=?", (url[4:],)):
				filename = i[0]
				content = base64.b64decode(i[1])
			f = QtGui.QFileDialog.getSaveFileName(self, "Save file", filename)
			if f == '':
				return

			with open(f, 'wb') as file:
				file.write(content)

		elif url[:6] == 'DELETE':
			ID = url[6:]
			# First, get the name of the file.
			for i in cursor.execute("SELECT NAME FROM FILES WHERE ID=?", (ID,)):
				filename = i[0]
			# Then, remove the file.
			cursor.execute("DELETE FROM FILES WHERE ID=?", (ID,))
			# Finally, update the message.
			cursor.execute(
				"UPDATE MESSAGES SET CONTENT=? WHERE CONTENT=?",
				('_You removed this file (%s)._' % filename, '[_FR_]!'+ID)
			)
			DB.commit()
			cursor.execute("VACUUM")

			# Update messages
			self.updateMessages()

	def sendfileclicked(self):
		selected = self.chats[self.chatslist.selectedIndexes()[0].row()]
		sendfile(self, selected[1], selected[2]).show()
		return

	def sendWritingSignal(self):
		CID = self.chats[self.chatslist.selectedIndexes()[0].row()][0]
		data.send_msg(self.SEND, cryptic.encrypt(self.thisAES, self.thisIV, '\x00'+CID))

	def chatsListClicked(self):
		self.writemsg.setText('')
		selected = self.chatslist.selectedIndexes()[0].row()

		self.messages.setEnabled(True)
		self.writemsg.setEnabled(True)
		self.writemsg.setPlaceholderText('Write something to '+self.chats[selected][1])
		self.sendfile_btn.setEnabled(True)

		if self.chats[selected][0] in UNREAD_CHATS:
			UNREAD_CHATS.pop(selected)
			self.updateChatsList()

		areAllChatsRead = True
		for i in range(len(self.chats)):
			if self.chats[i][0] in UNREAD_CHATS:
				areAllChatsRead = False
				break
		if areAllChatsRead:
			self.tabs.setTabText(self.tabIndex, self.ALIAS)
			self.parent.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(':/Icons/256x256.png')))

		self.updateMessages()

	def updateMessages(self):
		selected = self.chats[self.chatslist.selectedIndexes()[0].row()]
		chat = selected[0]

		# Get messages from the database
		global DB
		cursor = DB.cursor()
		messages = []
		# WARNING: IT NEEDS A FUCKING LIMIT
		for i in cursor.execute("SELECT TIMESTAMP, WHO, CONTENT, ID FROM MESSAGES WHERE ME=? AND THEY=? ORDER BY TIMESTAMP ASC", (self.ME, chat)):
			messages.append(i)

		html = '<style>* { font-family: monospace; }</style>\n'	# This makes monospaced font work in Windows
		show = []
		for i in messages:
			# Before 'You' was self.ALIAS, but that might be confusing to the user.
			who = 'You' if i[1] == 0 else escapeHTMLString(selected[1])
			content = i[2]
			if content[:6] == '[_F_]!':
				# It's a file to download.
				try:
					SIZE = sizeToString(int(content[6:].split('|')[0]))
					URL = content[6:].split('|')[1]
					FILENAME = escapeHTMLString(urllib2.unquote(URL.split('/')[-1]))
					content = '<a href=\''+content+'|'+str(i[3])+'\'>Download "'+FILENAME+'" ('+SIZE+')</a>'
				except:
					content = '<i>This message is poorly formatted. Maybe you are using an old version of Disposable.</i>'
			elif content[:7] == '[_FR_]!':
				# It's a downloaded file.
				try:
					ID = content[7:]
					for j in cursor.execute("SELECT NAME, SIZE FROM FILES WHERE ID=?", (ID,)):
						FILENAME = j[0]
						SIZE = j[1]
					content = '<a href=\'COPY'+ID+'\'>Copy "'+FILENAME+'"</a> <a href=\'DELETE'+ID+'\'>Delete</a>'
				except:
					content = '<i>This message is poorly formatted. Maybe you are using an old version of Disposable.</i>'
			else:
				# It's not.
				content = escapeHTMLString(content)
				content = content.replace('****', '')
				content = content.replace('__', '')
				bolds = content.split('**')
				if not len(bolds) % 2 == 0:
					content = ''
					for j in range(len(bolds)):
						if j % 2 == 0:
							content += bolds[j]
						else:
							content += '<b>'
							content += bolds[j]
							content += '</b>'
				content = content.replace('\\*', '*')
				content = content.replace('\\_', '\x00')
				italics = content.split('_')
				if not len(italics) % 2 == 0:
					content = ''
					for j in range(len(italics)):
						if j % 2 == 0:
							content += italics[j]
						else:
							content += '<i>'
							content += italics[j]
							content += '</i>'
				content = content.replace('\x00', '_')

			shown = '[%s] &lt;%s&gt; %s' % (datetime.datetime.fromtimestamp(i[0]).strftime('%H:%M'), who, content)
			show.append(shown)
		html += '<br>'.join(show)
		self.messages.setHtml(html)

		# Scroll to the bottom
		self.messages.moveCursor(QtGui.QTextCursor.End)
		self.messages.ensureCursorVisible()

	def updateChatsList(self):
		# Get the currently selected chat, so that it can be kept
		try:
			currentlyselected = self.chats[self.chatslist.selectedIndexes()[0].row()][0]
		except:
			currentlyselected = None

		self.chats = []

		# Load chats from database
		global DB
		cursor = DB.cursor()
		for i in cursor.execute("SELECT THEY, ALIAS FROM CHATS WHERE ME=? ORDER BY LAST DESC", (self.ME,)):
			self.chats.append([i[0], i[1]])
		for i in range(len(self.chats)):
			# Get the public key of this chat
			PUB = False
			for j in cursor.execute("SELECT PUB FROM PUBS WHERE CID=?", (self.chats[i][0],)):
				PUB = j[0]
			if not PUB:
				# Request it from the node
				s, result, thisAES, thisIV = authenticate(self.ME, self.PRIV)
				if not result:
					print 'Something went horribly wrong (UPDATE-CHATS).'
					exit()
				data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x03'+self.chats[i][0]))
				PUB = cryptic.decrypt(thisAES, thisIV, data.recv_msg(s))
				s.close()

				if PUB == '\x01':
					self.chats[i].append('')
					continue

				# Check if the CID is the MD5 hash of the public key.
				if not hashlib.md5(PUB).hexdigest() == self.chats[i][0]:
					print 'Something went horribly wrong (MALICIOUS-NODE).'
					exit()

				# Store it in the database for the next time
				cursor.execute("INSERT INTO PUBS (CID, PUB) VALUES (?, ?)", (self.chats[i][0], PUB))
				DB.commit()

			PUB = cryptic.getRSACipher(PUB)

			# Append to the list
			self.chats[i].append(PUB)

		model = QtGui.QStandardItemModel()
		for i in self.chats:
			name = '*'+i[1] if i[0] in UNREAD_CHATS else i[1]
			bold = 75 if i[0] in UNREAD_CHATS else 50

			item = QtGui.QStandardItem(name)
			item.setEditable(False)
			item.setFont(QtGui.QFont('Sans', 15, bold))
			model.appendRow(item)
		self.chatslist.setModel(model)

		# The code below is really messy. It just tries to select the item that was selected before.
		if currentlyselected:
			index = -1
			for i in range(len(self.chats)):
				if self.chats[i][0] == currentlyselected:
					index = i
					break
			if not index == -1:
				self.chatslist.selectionModel().select(model.createIndex(index, 0), QtGui.QItemSelectionModel.Select)
				self.writemsg.setPlaceholderText('Write something to '+self.chats[i][1])	# This has to be reset in case the alias has been changed.

	def chatOptions(self, pos):
		selected_CID = self.chats[self.chatslist.selectedIndexes()[0].row()][0]
		menu = QtGui.QMenu()
		menu.addAction('Show hash', lambda:self.showhash(selected_CID))
		menu.addAction('Rename', lambda:self.renamechat(selected_CID))
		menu.addAction('Delete', lambda:self.deleteChat(selected_CID))
		menu.exec_(QtGui.QCursor.pos())

	def showhash(self, selected_CID):
		identityhash(self, selected_CID).show()

	def renamechat(self, selected_CID):
		ALIAS = unicode(QtGui.QInputDialog.getText(self, 'Rename chat', 'Enter the new name:')[0].toUtf8(), encoding='utf-8')
		if ALIAS == '':
			return

		# Update the row in the database
		global DB
		cursor = DB.cursor()
		cursor.execute("UPDATE CHATS SET ALIAS=? WHERE ME=? AND THEY=?", (ALIAS, self.ME, selected_CID))
		DB.commit()

		self.updateChatsList()	# Update the chats list
		self.updateMessages()	# Update messages, in order to change the name in desplay

	def deleteChat(self, selected_CID):
		# Sure?
		sure = QtGui.QMessageBox(self)
		sure.setIcon(QtGui.QMessageBox.Information)
		sure.setText('Are you sure you want to delete this chat?')
		sure.setInformativeText('You will lose all the messages.')
		sure.addButton(QtGui.QMessageBox.Yes)
		sure.addButton(QtGui.QMessageBox.No)
		sure.setDefaultButton(QtGui.QMessageBox.No)
		ret = sure.exec_()
		if ret == QtGui.QMessageBox.Yes:
			global DB
			cursor = DB.cursor()

			cursor.execute("DELETE FROM CHATS WHERE ME=? AND THEY=?", (self.ME, selected_CID))	# First, remove the row in CHATS
			cursor.execute("DELETE FROM MESSAGES WHERE ME=? AND THEY=?", (self.ME, selected_CID))	# Then, remove the messages
			DB.commit()

			self.updateChatsList()	# Finally, update the chats list

	def newchat(self):
		THEY = str(QtGui.QInputDialog.getText(self, 'New chat', 'Enter the identity:')[0])
		if THEY == '':
			return

		global DB
		cursor = DB.cursor()

		# Check if it's already in chats
		isInChats = False
		for i in cursor.execute("SELECT 1 FROM CHATS WHERE ME=? AND THEY=?", (self.ME, THEY)):
			isInChats = True
		if isInChats:
			msg = QtGui.QMessageBox()
			msg.setIcon(QtGui.QMessageBox.Warning)
			msg.setText('The given identity hash is already in your chats.')
			msg.exec_()
			self.close()
			return

		# Check if the identity exists in the node
		result = authenticate(THEY, '')
		if result[0] == None:
			# It doesn't exist
			msg = QtGui.QMessageBox()
			msg.setIcon(QtGui.QMessageBox.Critical)
			msg.setText('The given identity hash doesn\'t exist in the node.')
			msg.exec_()
			self.close()
			return

		cursor.execute("INSERT INTO CHATS (ME, THEY, ALIAS, LAST) VALUES (?, ?, ?, ?)", (self.ME, THEY, THEY.upper()[:8], time.time()))
		DB.commit()
		self.updateChatsList()

	def deletedIdentity(self):
		msg = QtGui.QMessageBox()
		msg.setIcon(QtGui.QMessageBox.Critical)
		msg.setText('This identity has been deleted.')
		msg.exec_()

	def sendMessage(self):
		msg_content = str(self.writemsg.text().toUtf8())	# As a string, to encrypt it
		if msg_content == '':
			return

		# Fix text
		msg_content = msg_content.strip()	# Remove leading spaces
		msg_content = unzalgo.fixZalgo(unicodedata.normalize('NFD', unicode(msg_content, encoding='utf-8')))
		msg_content = str(msg_content.encode('utf-8'))

		_ = self.chats[self.chatslist.selectedIndexes()[0].row()]
		msg_to = _[0]
		PUB = _[2]

		if PUB == '':
			self.deletedIdentity()
			return

		_ = unicode(msg_content, encoding='utf-8')	# As unicode, to store it in the database

		thisMessageAES = cryptic.genRandomAESKey()	# First, generate a random AES key
		msg_content = cryptic.encrypt(thisMessageAES, chr(0)*16, msg_content)	# Encrypt 'msg_content' with the AES key
		thisMessageAES = PUB.encrypt(thisMessageAES)	# Encrypt the AES key with their public key

		# Send the message
		tosend = msg_to+'|'+base64.b64encode(thisMessageAES)+'|'+base64.b64encode(msg_content)
		data.send_msg(self.SEND, cryptic.encrypt(self.thisAES, self.thisIV, tosend))

		if not cryptic.decrypt(self.thisAES, self.thisIV, data.recv_msg(self.SEND)) == '\x00':
			self.deletedIdentity()
			return

		# Insert the message into the database
		global DB
		cursor = DB.cursor()
		cursor.execute("INSERT INTO MESSAGES (ME, THEY, TIMESTAMP, WHO, CONTENT) VALUES (?, ?, ?, ?, ?)", (self.ME, msg_to, int(time.time()), 0, _))

		# Update LAST in CHATS
		cursor.execute("UPDATE CHATS SET LAST=? WHERE ME=? AND THEY=?", (time.time(), self.ME, msg_to))

		DB.commit()

		self.writemsg.setText('')

		self.updateMessages()	# Update the chat
		self.updateChatsList()

	def tickWriting(self):
		try:
			self.writingtimers.pop(0)
		except:
			pass
		if len(self.writingtimers) == 0:
			self.writing.setText('')

	def messageReceived(self, r):
		global DB
		cursor = DB.cursor()

		if r[0] == '\x00':
			r = r[1:].split('|')
			try:
				selected = self.chats[self.chatslist.selectedIndexes()[0].row()]
			except:
				return
			if self.ME == r[0] and selected[0] == r[1]:
				self.writing.setText('%s is writing...' % selected[1])
				writingTimer = QtCore.QTimer()
				writingTimer.setSingleShot(True)
				writingTimer.timeout.connect(self.tickWriting)
				writingTimer.start(1000)
				self.writingtimers.append(writingTimer)
			return
		self.writingtimers = []
		self.tickWriting()

		r = r.split('|')
		msg_from, msg_time, msg_key, msg_content = r[0], int(r[1]), base64.b64decode(r[2]), base64.b64decode(r[3])

		# 'msg_key' is encrypted with our public key. So, decrypt it with our private key.
		msg_key = cryptic.getRSACipher(self.PRIV).decrypt(msg_key)

		# 'msg_content' is encrypted with 'msg_key'.
		# As we're using a random symmetric key for each message, there's no need to use a random IV.
		msg_content = cryptic.decrypt(msg_key, chr(0)*16, msg_content)

		# Fix text
		msg_content = msg_content.strip()	# Remove leading spaces
		msg_content = unzalgo.fixZalgo(unicodedata.normalize('NFD', unicode(msg_content, encoding='utf-8')))
		msg_content = str(msg_content.encode('utf-8'))

		# It's converted into unicode, so that it can be inserted into the database
		msg_content = unicode(msg_content, encoding='utf-8')

		# Insert into the database
		cursor.execute("INSERT INTO MESSAGES (ME, THEY, TIMESTAMP, WHO, CONTENT) VALUES (?, ?, ?, ?, ?)", (self.ME, msg_from, msg_time, 1, msg_content))

		# If the identity who sent the message is not in CHATS, insert it.
		isInChats = False
		for i in cursor.execute("SELECT 1 FROM CHATS WHERE ME=? AND THEY=?", (self.ME, msg_from)):
			isInChats = True
		if not isInChats:
			cursor.execute("INSERT INTO CHATS (ME, THEY, ALIAS, LAST) VALUES (?, ?, ?, ?)", (self.ME, msg_from, msg_from.upper()[:8], msg_time))

		# Update LAST in CHATS
		cursor.execute("UPDATE CHATS SET LAST=? WHERE ME=? AND THEY=?", (time.time(), self.ME, msg_from))

		DB.commit()

		notified = False
		# If the chat is open, update it
		try:
			if self.chats[self.chatslist.selectedIndexes()[0].row()][0] == msg_from:
				self.updateMessages()
		except:
			# If not, add its CID to UNREAD_CHATS
			if not msg_from in UNREAD_CHATS:
				UNREAD_CHATS.append(msg_from)
			# And also, notify
			if PREFERENCES['notification']:
				mixer.music.play()
			notified = True
			# Finally set the new window icon
			self.parent.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(':/Icons/newmessages.png')))

		# If the tab is not selected, notify
		if not notified:
			if not self.tabs.currentIndex() == self.tabIndex:
				self.tabs.setTabText(self.tabIndex, '*'+self.ALIAS)
				# And play the sound
				if PREFERENCES['notification']:
					mixer.music.play()
				notified = True
				# And set the new window icon
				self.parent.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(':/Icons/newmessages.png')))

		# If the window is not focused, notify
		if not notified:
			if not self.parent.isFocused:
				if PREFERENCES['notification']:
					mixer.music.play()
				# And set the new window icon
				self.parent.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(':/Icons/newmessages.png')))
				# And let the window know that the icon has been changed because of this
				self.parent.iconChangedBecauseOfFocus = True

		self.updateChatsList()

class identityhash(QtGui.QDialog, identityhash_ui):
	def __init__(self, parent, CID):
		super(identityhash, self).__init__(parent)
		self.setupUi(self)
		self.address_field.setText(CID)

class mainwindow(QtGui.QMainWindow, mainwindow_fc):
	def __init__(self):
		super(mainwindow, self).__init__(None)
		self.setupUi(self)
		self.center()
		self.installEventFilter(self)
		self.isFocused = True
		self.iconChangedBecauseOfFocus = False

		self.loadIdentities()

		self.newidentity_btn.triggered.connect(self.newidentity)
		self.identitiestab.currentChanged.connect(self.tabChanged)
		self.showhash_btn.triggered.connect(self.showhash)
		self.renameidentity_btn.triggered.connect(self.renameidentity)
		self.deleteidentity_btn.triggered.connect(self.deleteidentity)

		self.increasefontsize.triggered.connect(self.fontsizeplus)
		self.decreasefontsize.triggered.connect(self.fontsizeminus)
		self.notificationsound.triggered.connect(self.switchnotification)

	def eventFilter(self, obj, evt):
		if evt.type() == QtCore.QEvent.WindowDeactivate:
			self.isFocused = False
		elif evt.type() == QtCore.QEvent.WindowActivate:
			self.isFocused = True
			if self.iconChangedBecauseOfFocus:
				self.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(':/Icons/256x256.png')))
				self.iconChangedBecauseOfFocus = False
		return False

	def center(self):
		frameGm = self.frameGeometry()
		screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
		centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
		frameGm.moveCenter(centerPoint)
		self.move(frameGm.topLeft())

	def writePreferences(self):
		global PREFERENCES
		with open('preferences.dat', 'w') as f:
			f.write(json.dumps(PREFERENCES))

	def fontsizeplus(self):
		PREFERENCES['font-size'] += 1
		self.writePreferences()
		for i in range(1, self.identitiestab.count()):
			self.identitiestab.widget(i).messages.setFont(QtGui.QFont(messagesFontFamily, PREFERENCES['font-size']))

	def fontsizeminus(self):
		PREFERENCES['font-size'] -= 1
		self.writePreferences()
		for i in range(1, self.identitiestab.count()):
			self.identitiestab.widget(i).messages.setFont(QtGui.QFont(messagesFontFamily, PREFERENCES['font-size']))

	def switchnotification(self):
		PREFERENCES['notification'] = not PREFERENCES['notification']
		self.writePreferences()

	def loadIdentities(self):
		# Read the CIDs from database
		self.identities = []
		global DB
		cursor = DB.cursor()
		for i in cursor.execute("SELECT CID, PRIV, ALIAS FROM IDENTITIES"):
			CID = i[0]
			PRIV = i[1]
			ALIAS = i[2]

			# Check if it's possible to authenticate
			s, result, thisAES, thisIV = authenticate(CID, PRIV)
			if s:
				s.close()
			self.identities.append([CID, PRIV, ALIAS, result])

		# Add the tabs that are not already there (weird)
		for i in range(self.identitiestab.count()-1, len(self.identities)):	# This might cause troubles in the future.
			if self.identities[i][3]:
				ALIAS = self.identities[i][2]
				tab = identitytab(self.identities[i][0], self.identities[i][1], ALIAS, i+1, self)
			else:
				ALIAS = '[INVALID] '+self.identities[i][2]
				tab = invalidtab()
			self.identitiestab.addTab(tab, ALIAS)

	def newidentity(self):
		try:
			s, thisAES, thisIV = keyExchange()
		except:
			print 'Something went horribly wrong (NO-KEY-EXCHANGE).'
			exit()

		data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x00'))
		if not cryptic.decrypt(thisAES, thisIV, data.recv_msg(s)) == '\x00':
			print 'Something went horribly wrong (BAD-PROTOCOL).'
			exit()
		while True:
			priv, pub = cryptic.genPairOfKeys()
			data.send_msg(s, cryptic.encrypt(thisAES, thisIV, pub))
			response = cryptic.decrypt(thisAES, thisIV, data.recv_msg(s))
			if response == '\x00':
				CID = hashlib.md5(pub).hexdigest()
				break
		s.close()

		# Insert into database
		global DB
		cursor = DB.cursor()
		cursor.execute("INSERT INTO IDENTITIES (CID, PRIV, ALIAS) VALUES (?, ?, ?)", (CID, priv, CID.upper()[:8]))
		DB.commit()

		# Everything went fine. Update the identities and close the window.
		self.loadIdentities()

	def tabChanged(self):
		i = self.identitiestab.currentIndex()
		self.showhash_btn.setEnabled(not i == 0)
		self.renameidentity_btn.setEnabled(not i == 0)
		self.deleteidentity_btn.setEnabled(not i == 0)
		if not i == 0:
			areAllChatsRead = True
			for j in range(len(self.identitiestab.widget(i).chats)):
				if self.identitiestab.widget(i).chats[j][0] in UNREAD_CHATS:
					areAllChatsRead = False
					break
			if areAllChatsRead:
				self.identitiestab.setTabText(i, self.identities[i-1][2])	# Set the ALIAS as the tab text, in case it has a '*'.
				self.setWindowIcon(QtGui.QIcon(QtGui.QPixmap(':/Icons/256x256.png')))	# Set the window icon to "no messages"

	def showhash(self):
		CID = self.identities[self.identitiestab.currentIndex()-1][0]
		identityhash(self, CID).show()

	def renameidentity(self):
		k = self.identitiestab.currentIndex()-1
		ALIAS = unicode(QtGui.QInputDialog.getText(self, 'Rename identity', 'Enter the new name:')[0].toUtf8(), encoding='utf-8')
		if ALIAS == '':
			return
		self.identities[k][2] = ALIAS
		self.identitiestab.setTabText(k+1, ALIAS)	# Rename the tab.

		# Update the row in the database
		CID = self.identities[k][0]
		global DB
		cursor = DB.cursor()
		cursor.execute("UPDATE IDENTITIES SET ALIAS=? WHERE CID=?", (ALIAS, CID))
		DB.commit()

	def deleteidentity(self):
		# Sure?
		sure = QtGui.QMessageBox(self)
		sure.setIcon(QtGui.QMessageBox.Information)
		sure.setText('Are you sure you want to delete this identity?')
		sure.setInformativeText('There\'s no going back.')
		sure.addButton(QtGui.QMessageBox.Yes)
		sure.addButton(QtGui.QMessageBox.No)
		sure.setDefaultButton(QtGui.QMessageBox.No)
		ret = sure.exec_()
		if ret == QtGui.QMessageBox.Yes:
			# Authenticate
			k = self.identitiestab.currentIndex()-1
			s, result, thisAES, thisIV = authenticate(self.identities[k][0], self.identities[k][1])

			if s and result:
				# Send delete signal
				data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x02'))
				s.close()
			# Otherwise, it's already deleted in the node

			self.identitiestab.removeTab(k+1)	# Remove tab
			CID = self.identities[k][0]
			self.identities.pop(k)	# Remove from identities

			# Remove from database
			global DB
			cursor = DB.cursor()

			cursor.execute("DELETE FROM IDENTITIES WHERE CID=?", (CID,))
			cursor.execute("DELETE FROM CHATS WHERE ME=?", (CID,))
			cursor.execute("DELETE FROM MESSAGES WHERE ME=?", (CID,))

			DB.commit()

if __name__ == '__main__':
	# Load the node data
	if not os.path.isfile('node.dat'):
		print '\'node.dat\' could not be found.'
		exit()
	global NODE
	with open('node.dat', 'r') as f:
		NODE = f.read()
	NODE_CONNECTION = NODE[:NODE.find('\n')].split(':')
	NODE_PUB = NODE[NODE.find('\n')+1:]
	NODE = [NODE_CONNECTION[0], int(NODE_CONNECTION[1]), NODE_PUB]

	# Connect to database
	global DB
	DB = sqlite3.connect('database')

	# Initialize database
	cursor = DB.cursor()
	areTablesThere = False
	for i in cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='IDENTITIES'"):
		areTablesThere = True	# The tables already exist
	if not areTablesThere:
		# If the tables do not exist, create them
		cursor.execute("CREATE TABLE 'IDENTITIES' ('CID' TEXT PRIMARY KEY, 'PRIV' TEXT, 'ALIAS' TEXT)")
		cursor.execute("CREATE TABLE 'CHATS' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'ME' TEXT, 'THEY' TEXT, 'ALIAS' TEXT, 'LAST' INTEGER)")
		cursor.execute("CREATE TABLE 'PUBS' ('CID' TEXT PRIMARY KEY, 'PUB' TEXT)")
		cursor.execute("CREATE TABLE 'MESSAGES' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'ME' TEXT, 'THEY' TEXT, 'TIMESTAMP' INTEGER, 'WHO' INTEGER, 'CONTENT' TEXT)")
		cursor.execute("CREATE TABLE 'FILES' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'NAME' TEXT, 'SIZE' TEXT, 'CONTENT' TEXT)")
		DB.commit()

	# Load preferences
	global PREFERENCES
	PREFERENCES = {
		'font-size': 11,
		'notification': True
	}
	if os.path.isfile('preferences.dat'):
		with open('preferences.dat', 'r') as f:
			PREFERENCES = f.read()
			PREFERENCES = json.JSONDecoder().decode(PREFERENCES)

	mixer.init()
	mixer.music.load('sounds'+os.sep+'stairs.mp3')

	# These are for showing unread chats in bold
	global UNREAD_CHATS
	UNREAD_CHATS = []

	# Start the application
	app = QtGui.QApplication(sys.argv)
	w = mainwindow()

	# Check connection.
	tmp = connectToNode()
	data.send_msg(tmp, '\x00')
	tmp.close()

	# Show the window
	w.show()
	app.exec_()
