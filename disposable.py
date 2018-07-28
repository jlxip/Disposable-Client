#!/usr/bin/env python2.7
# -*- encoding: utf-8 -*-

import socket, os, data, cryptic, sys, base64, hashlib, sqlite3, time, datetime
from PyQt4 import QtCore, QtGui, uic
from threading import Thread

UIdirectory = 'UI'+os.sep
mainwindow_fc = uic.loadUiType(UIdirectory+'mainwindow.ui')[0]
identity_ui = uic.loadUiType(UIdirectory+'identity.ui')[0]
invalid_ui = uic.loadUiType(UIdirectory+'invalid.ui')[0]
identityhash_ui = uic.loadUiType(UIdirectory+'identityhash.ui')[0]

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
		print 'Something went horribly wrong.'
		exit()
	data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x01'))
	if not cryptic.decrypt(thisAES, thisIV, data.recv_msg(s)) == 'OK':
		return (None, False, None, None)
	data.send_msg(s, cryptic.encrypt(thisAES, thisIV, CID))
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
			print 'Something went horribly wrong.'
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
	def __init__(self, CID, PRIV):
		super(identitytab, self).__init__(None)
		self.setupUi(self)
		self.newchat_btn.clicked.connect(self.newchat)
		self.ME = CID
		self.PRIV = PRIV
		self.chatslist.doubleClicked.connect(self.chatsListClicked)
		self.chatslist.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
		self.chatslist.customContextMenuRequested.connect(self.chatOptions)
		self.writemsg.returnPressed.connect(self.sendMessage)

		self.SEND, _result, self.thisAES, self.thisIV = authenticate(self.ME, self.PRIV)
		if not _result:
			print 'Something went horribly wrong.'
			exit()
		data.send_msg(self.SEND, cryptic.encrypt(self.thisAES, self.thisIV, '\x01'))

		self.updateChatsList()

		#Thread(target=self.listen, args=(self.ME, self.PRIV)).start()
		thread = listenThread(self)
		self.connect(thread, thread.signal, self.messageReceived)
		thread.start()

	def chatsListClicked(self):
		self.messages.setEnabled(True)
		self.writemsg.setEnabled(True)

		self.updateMessages()

	def updateMessages(self):
		selected = self.chats[self.chatslist.selectedIndexes()[0].row()][0]

		# Get messages from the database
		global DB
		cursor = DB.cursor()
		messages = []
		# WARNING: IT NEEDS A FUCKING LIMIT
		for i in cursor.execute("SELECT CONTENT, TIMESTAMP FROM MESSAGES WHERE ME=? AND THEY=? ORDER BY TIMESTAMP ASC", (self.ME, selected)):
			messages.append([i[0], i[1]])

		# Show messages in 'messages' (QListView)
		model = QtGui.QStandardItemModel()
		for i in messages:
			shown = '[%i] %s' % (i[1], i[0])
			item = QtGui.QStandardItem(shown)
			item.setEditable(False)
			model.appendRow(item)
		self.messages.setModel(model)

	def updateChatsList(self, thisDB=None):
		self.chats = []

		# Load chats from database
		if thisDB == None:
			global DB
		else:
			DB = thisDB
		cursor = DB.cursor()
		for i in cursor.execute("SELECT THEY, ALIAS FROM CHATS WHERE ME=? ORDER BY LAST DESC", (self.ME,)):
			# Get the public key of this chat
			s, result, thisAES, thisIV = authenticate(self.ME, self.PRIV)
			if not result:
				print 'Something went horribly wrong.'
				exit()
			data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x03'+i[0]))
			PUB = cryptic.getRSACipher(cryptic.decrypt(thisAES, thisIV, data.recv_msg(s)))
			s.close()

			# Append to the list
			self.chats.append([i[0], i[1], PUB])

		model = QtGui.QStandardItemModel()
		for i in self.chats:
			item = QtGui.QStandardItem(i[1])
			item.setEditable(False)
			item.setFont(QtGui.QFont('Sans', 15))
			model.appendRow(item)
		self.chatslist.setModel(model)

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
		ALIAS = str(QtGui.QInputDialog.getText(self, 'Rename chat', 'Enter the new name:')[0])
		if ALIAS == '':
			return

		# Update the row in the database
		global DB
		cursor = DB.cursor()
		cursor.execute("UPDATE CHATS SET ALIAS=? WHERE ME=? AND THEY=?", (ALIAS, self.ME, selected_CID))
		DB.commit()

		self.updateChatsList()	# Update the chats list

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

	def sendMessage(self):
		_ = self.chats[self.chatslist.selectedIndexes()[0].row()]
		msg_to = _[0]
		PUB = _[2]
		msg_content = str(self.writemsg.text())
		_ = msg_content

		thisMessageAES = cryptic.genRandomAESKey()	# First, generate a random AES key
		msg_content = cryptic.encrypt(thisMessageAES, chr(0)*16, msg_content)	# Encrypt 'msg_content' with the AES key
		thisMessageAES = PUB.encrypt(thisMessageAES)	# Encrypt the AES key with their public key

		# Send the message
		tosend = msg_to+'|'+base64.b64encode(thisMessageAES)+'|'+base64.b64encode(msg_content)
		data.send_msg(self.SEND, cryptic.encrypt(self.thisAES, self.thisIV, tosend))

		# Insert the message into the database
		global DB
		cursor = DB.cursor()
		cursor.execute("INSERT INTO MESSAGES (ME, THEY, TIMESTAMP, CONTENT) VALUES (?, ?, ?, ?)", (self.ME, msg_to, time.time(), _))
		DB.commit()

		self.updateMessages()	# Update the chat

	def messageReceived(self, r):
		global DB
		cursor = DB.cursor()
		r = r.split('|')
		msg_from, msg_time, msg_key, msg_content = r[0], int(r[1]), base64.b64decode(r[2]), base64.b64decode(r[3])

		# First of all, msg_time is in UTC.
		# Calculate the difference from UTC and apply it to the received time.
		UTC_diff = int(time.time()) - int(datetime.datetime.utcnow().strftime('%s'))
		msg_time += UTC_diff

		# 'msg_key' is encrypted with our public key. So, decrypt it with our private key.
		msg_key = cryptic.getRSACipher(self.PRIV).decrypt(msg_key)

		# 'msg_content' is encrypted with 'msg_key'.
		# As we're using a random symmetric key for each message, there's no need to use a random IV.
		msg_content = cryptic.decrypt(msg_key, chr(0)*16, msg_content)

		# Insert into the database
		cursor.execute("INSERT INTO MESSAGES (ME, THEY, TIMESTAMP, CONTENT) VALUES (?, ?, ?, ?)", (self.ME, msg_from, msg_time, msg_content))

		# If the identity who sent the message is not in CHATS, insert it.
		isInChats = False
		for i in cursor.execute("SELECT 1 FROM CHATS WHERE ME=? AND THEY=?", (self.ME, msg_from)):
			isInChats = True
		if not isInChats:
			cursor.execute("INSERT INTO CHATS (ME, THEY, ALIAS, LAST) VALUES (?, ?, ?, ?)", (self.ME, msg_from, msg_from.upper()[:8], msg_time))

		DB.commit()
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

		self.loadIdentities()

		self.newidentity_btn.triggered.connect(self.newidentity)
		self.identitiestab.currentChanged.connect(self.tabChanged)
		self.showhash_btn.triggered.connect(self.showhash)
		self.renameidentity_btn.triggered.connect(self.renameidentity)
		self.deleteidentity_btn.triggered.connect(self.deleteidentity)

	def center(self):
		frameGm = self.frameGeometry()
		screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
		centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
		frameGm.moveCenter(centerPoint)
		self.move(frameGm.topLeft())

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
				tab = identitytab(self.identities[i][0], self.identities[i][1])
			else:
				ALIAS = '[INVALID] '+self.identities[i][2]
				tab = invalidtab()
			self.identitiestab.addTab(tab, ALIAS)

	def newidentity(self):
		try:
			s, thisAES, thisIV = keyExchange()
		except:
			print 'Something went horribly wrong.'
			exit()

		data.send_msg(s, cryptic.encrypt(thisAES, thisIV, '\x00'))
		if not cryptic.decrypt(thisAES, thisIV, data.recv_msg(s)) == '\x00':
			print 'Something went horribly wrong.'
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

	def showhash(self):
		CID = self.identities[self.identitiestab.currentIndex()-1][0]
		identityhash(self, CID).show()

	def renameidentity(self):
		k = self.identitiestab.currentIndex()-1
		ALIAS = str(QtGui.QInputDialog.getText(self, 'Rename identity', 'Enter the new name:')[0])
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
		cursor.execute("CREATE TABLE 'IDENTITIES' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'CID' TEXT, 'PRIV' TEXT, 'ALIAS' TEXT)")
		cursor.execute("CREATE TABLE 'CHATS' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'ME' TEXT, 'THEY' TEXT, 'ALIAS' TEXT, 'LAST' INTEGER)")
		cursor.execute("CREATE TABLE 'MESSAGES' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'ME' TEXT, 'THEY' TEXT, 'TIMESTAMP' INTEGER, 'CONTENT' TEXT)")
		DB.commit()

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
