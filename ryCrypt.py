'''
	File: ryCrypt.py
	Purpose: Various encryption methods using Blowfish encryption
	Author: Ryan Blakely
	Date: June 25, 2013
'''


import sys, os
from Crypto.Cipher import Blowfish

DEFAULT_EXT = ".ssf" #super secret file

#writes to a file with binary data
def writeFile(fname,fdata):
	outfile = open(fname, 'wb')
	outfile.write(fdata)
	outfile.close()

#reads in a given file as binary data
def getFile(fname):
	filedata=None
	if os.path.exists(fname):
		infile = open(fname, 'rb')
		filedata = infile.read()
		infile.close()
	else:
		print("File doesn't exist! filename = " + fname)
		sys.exit()
	
	return filedata

#pads file data so that its length is divisible by the blocksize
#pads anywhere from 1 to blocksize bytes, where the last byte is always the # of padded bytes added (inclusive)
def padFile(filedata,blocksize=8):
	pad = blocksize - (len(filedata) % blocksize)
	
	#if padding isn't needed, pad anyways so we can store the pad-size byte
	if (pad==0):
		pad=8
		
	#pads with all spaces, except the last byte which is the amount of padding added (for decrypting)
	padstr = ' ' * (pad - 1) + str(pad)
	filedata = filedata + padstr.encode()
	
	return filedata

#trims excess file data from a padded file of a particular block size
#expects the last byte in the file to the the # of padded bytes total (including the last byte)
def trimFile(filedata,blocksize=8):
	pad = chr(filedata[-1]) # number of padded bytes
	filedata = filedata[:-int(pad)] #get the trimmed filedata
	
	return filedata

#encrypts a file w/ a given password and either writes it to an output file or returns the encrypted data
def encryptFile(fname,pw,efname=None):
	cipher = Blowfish.new(pw)
	file = padFile(getFile(fname))
	crypted = cipher.encrypt(file)
	
	if(not efname):
		return crypted
	else:
		writeFile(efname,crypted)
		return None

#decrypts a file using a given password and either writes it to an output file or returns the decrypted data
def decryptFile(fname,pw,dfname=None):
	cipher = Blowfish.new(pw)
	file = getFile(fname)
	decrypted = trimFile(cipher.decrypt(file))
	
	if(not dfname):
		return decrypted
	else:
		writeFile(dfname,decrypted)
		return None

#test function
def test2():
	pw="cool"
	f1 = "test.txt"
	f2 = "test.enc"
	f3 = "test2.txt"
	
	encryptFile(f1,pw,f2)
	decryptFile(f2,pw,f3)

#test function
def test():
	cipher=Blowfish.new("testing")
	print("Testing block encrypt:")
	text = padFile(getFile('test.txt'))
	crypted = cipher.encrypt (text)
	writeFile('test.enc',crypted)
	detext = getFile('test.enc')
	decrypted = cipher.decrypt (crypted)
	writeFile('test2.txt',trimFile(decrypted))
	
test2()