#!/usr/bin/env python2.7

import socket, os, data, cryptic, sys, base64, hashlib, sqlite3
from PyQt4 import QtCore, QtGui, uic

UIdirectory = 'UI'+os.sep
mainwindow_fc = uic.loadUiType(UIdirectory+'mainwindow.ui')[0]
identity_ui = uic.loadUiType(UIdirectory+'identity.ui')[0]
invalid_ui = uic.loadUiType(UIdirectory+'invalid.ui')[0]
identityaddress_ui = uic.loadUiType(UIdirectory+'identityaddress.ui')[0]

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

class identitytab(QtGui.QWidget, identity_ui):
	def __init__(self):
		super(identitytab, self).__init__(None)
		self.setupUi(self)
		self.newchat_btn.clicked.connect(self.newchat)
	def newchat(self):
		CID = str(QtGui.QInputDialog.getText(self, 'New chat', 'Enter the identity:')[0])
		# Check if the identity exists in the node
		result = authenticate(CID, '')
		if result[0] == None:
			# It doesn't exist
			msg = QtGui.QMessageBox()
			msg.setIcon(QtGui.QMessageBox.Critical)
			msg.setText('The identity doesn\'t exist in the node.')
			msg.exec_()
			self.close()
			return
		# It does exist


class identityaddress(QtGui.QDialog, identityaddress_ui):
	def __init__(self, parent, CID):
		super(identityaddress, self).__init__(parent)
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
		self.showaddress_btn.triggered.connect(self.showaddress)
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
				tab = identitytab()
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
		self.showaddress_btn.setEnabled(not i == 0)
		self.renameidentity_btn.setEnabled(not i == 0)
		self.deleteidentity_btn.setEnabled(not i == 0)

	def showaddress(self):
		CID = self.identities[self.identitiestab.currentIndex()-1][0]
		identityaddress(self, CID).show()

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
		cursor.execute("CREATE TABLE 'CHATS' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'ME' TEXT, 'THEY' TEXT)")
		cursor.execute("CREATE TABLE 'MESSAGES' ('ID' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'ME' TEXT, 'THEY' TEXT, 'TIMESTAMP' TEXT, 'CONTENT' TEXT)")
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
