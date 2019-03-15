import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot
from Crypto.Cipher import Blowfish
import binascii
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
unpad = lambda s: s[:-ord(s[len(s)-1:])]

def iv():
    return chr(0) * 16

#***AES STARTS***

class AESCipher(object):
    def __init__(self, key):
        self.key = key
        #self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, message):
        message = message.encode()
        raw = pad(message)
        cipher = AES.new(self.key, AES.MODE_CBC, iv())
        enc = cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, iv())
        dec = cipher.decrypt(enc)
        return unpad(dec).decode('utf-8')

#***AES ENDS***

#***OTHERS START***

class encryptions:

    def __init__(self):
        self=self

    def modlensq(self):
        s=self
        t = ""
        l = len(s)
        s = s.lower()
        for i in range(0, l):
            n = ord(s[i])
            if (i % 2 == 0):
                n = n + 2 * (n % l)
            else:
                n = n + (n % l)
            t = t + str(chr(n))
        return t


    def fishcrypt(self):
        s = self
        s = list(s)
        l = len(s)
        s1 = list(map(ord, s[0:len(s):2]))
        s2 = list(map(ord, s[1:len(s):2]))
        s1 = sum(s1)
        s2 = sum(s2)
        return str(complex(s1, s2))

    def bitman(self):
        s = self
        t = ''.join(format(ord(x), 'b') for x in s)
        l = len(s)
        m = ""
        for i in range(0, len(str(t))):
            p = t[i]
            if (p == "1" and (i + 1) % 3 == 0 and (i + 1) % l != 0):
                p = "0"
            if (p == "0" and (i + 1) % l == 0):
                p = "1"
            m = m + p
        m = m[::-1]
        return m

    def caesarcipher(self):
        s=self
        k=len(s)**0.5
        m=""
        for i in s:
            m=m+chr(int(ord(i)+k))
        return m


    def encryptcipher2(self):
        lookup = {'A': 'aaaaa', 'B': 'aabaab', 'C': 'bbaaaba', 'D': 'aaabab', 'E': 'aaaabaa', 'F': 'aaabab', 'G': 'aabaabba', 'H': 'aabbb', 'I': 'abaaaaab', 'J': 'abaabb', 'K': 'ababbba', 'L': 'ababaaab', 'M': 'abbaabbbb', 'N': 'abbbbbbab', 'O': 'abaaaaabba', 'P': 'abbbaaaaab', 'Q': 'baaaaa', 'R': 'abaaab', 'S': 'bbbaaba', 'T': 'aabaabb', 'U': 'bbbabaa', 'V': 'aaababab', 'W': 'ababba', 'X': 'baabbb', 'Y': 'bbaaa', 'Z': 'bbaab'}
        message=self
        m=""
        for i in message:
            i=chr(65+ord(i)%26)
            m+=i
        message=m
        cipher = ''
        for i in m:
            cipher+=lookup[i][::-1]
        return cipher

    def blowfishencryption(self, key_str):
            encr_str=self
            #Key str to be entered by the company
            cipher = Blowfish.new(key_str, Blowfish.MODE_ECB)
            return binascii.hexlify(cipher.encrypt(encr_str)).decode('utf-8')


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.title = 'Password encryption'
        self.left = 10
        self.top = 10
        self.width = 600
        self.height = 200
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # Create textbox
        self.textbox = QLineEdit(self)
        self.textbox.move(30, 35)
        self.textbox.resize(450, 30)

        lvl1 = QLabel(self)
        lvl1.setText("Level 1:")
        lvl1.move(45, 75)

        # Create a button in the window
        drop1 = QComboBox(self)
        drop1.addItem("None")
        drop1.addItem("modlensq")
        drop1.addItem("fishcrypt")
        drop1.addItem("bitman")
        drop1.addItem("caesarcipher")
        drop1.addItem("encryptcipher2")
        drop1.addItem("blowfishencryption")
        drop1.addItem("AES")
        drop1.move(45, 100)
        drop1.activated[str].connect(self.onActivated)

        lvl2 = QLabel(self)
        lvl2.setText("Level 2:")
        lvl2.move(200, 75)

        drop2 = QComboBox(self)
        drop2.addItem("None")
        drop2.addItem("modlensq")
        drop2.addItem("fishcrypt")
        drop2.addItem("bitman")
        drop2.addItem("caesarcipher")
        drop2.addItem("encryptcipher2")
        drop2.addItem("AES")
        drop2.move(200, 100)
        drop2.activated[str].connect(self.onActivated)

        lvl3 = QLabel(self)
        lvl3.setText("Level 3:")
        lvl3.move(355, 75)

        drop3 = QComboBox(self)
        drop3.addItem("None")
        drop3.addItem("modlensq")
        drop3.addItem("fishcrypt")
        drop3.addItem("bitman")
        drop3.addItem("caesarcipher")
        drop3.addItem("encryptcipher2")
        drop3.addItem("AES")
        drop3.move(355, 100)
        drop3.activated[str].connect(self.onActivated)

        self.combotext = []


        inp = QLabel(self)
        inp.setText("Enter password:")
        inp.move(5, 5)

        # Create a drop down list to select in the window
        self.button = QPushButton('Encrypt', self)
        self.button.move(200, 150)

        # connect button to function on_click
        self.button.clicked.connect(self.on_click)
        self.show()


    @pyqtSlot()



    def on_click(self):
        textboxValue = self.textbox.text()

        print("Password entered: ",textboxValue)

        if self.combotext[0]=="None":
            textboxValue = textboxValue
        elif self.combotext[0]=="modlensq":
            textboxValue = encryptions.modlensq(textboxValue)
        elif self.combotext[0]=="fishcrypt":
            textboxValue = encryptions.fishcrypt(textboxValue)
        elif self.combotext[0]=="bitman":
            textboxValue = encryptions.bitman(textboxValue)
        elif self.combotext[0]=="caesarcipher":
            textboxValue = encryptions.caesarcipher(textboxValue)
        elif self.combotext[0]=="encryptcipher2":
            textboxValue = encryptions.encryptcipher2(textboxValue)
        elif self.combotext[0]=="blowfishencryption":
            if(len(textboxValue)==8 or len(textboxValue)==16):
                textboxValue = encryptions.blowfishencryption(textboxValue, "Key")
            else:
                textboxValue = "Enter a 8/16 character password only"
        else:
           textboxValue = AESCipher("2777Key3456789876545678987654561").encrypt(textboxValue)

        print("After Level #1:   ", textboxValue)

        if self.combotext[1]=="None":
            textboxValue = textboxValue
        elif self.combotext[1]=="modlensq":
            textboxValue = encryptions.modlensq(textboxValue)
        elif self.combotext[1]=="fishcrypt":
            textboxValue = encryptions.fishcrypt(textboxValue)
        elif self.combotext[1]=="bitman":
            textboxValue = encryptions.bitman(textboxValue)
        elif self.combotext[1]=="caesarcipher":
            textboxValue = encryptions.caesarcipher(textboxValue)
        elif self.combotext[1]=="encryptcipher2":
            textboxValue = encryptions.encryptcipher2(textboxValue)
        else:
           textboxValue = AESCipher("987654567892777Key34567887654561").encrypt(textboxValue)

        print("After Level #2:   " ,textboxValue)

        if self.combotext[2]=="None":
            textboxValue = textboxValue
        elif self.combotext[2]=="modlensq":
            textboxValue = encryptions.modlensq(textboxValue)
        elif self.combotext[2]=="fishcrypt":
            textboxValue = encryptions.fishcrypt(textboxValue)
        elif self.combotext[2]=="bitman":
            textboxValue = encryptions.bitman(textboxValue)
        elif self.combotext[2]=="caesarcipher":
            textboxValue = encryptions.caesarcipher(textboxValue)
        elif self.combotext[2]=="encryptcipher2":
            textboxValue = encryptions.encryptcipher2(textboxValue)
        else:
           textboxValue = AESCipher("87654567892777yki345678987654561").encrypt(textboxValue)

        print("After Level #3:   ", textboxValue)
        self.combotext=[]

        QMessageBox.question(self, 'password after encryption', "encrypted form: " + textboxValue , QMessageBox.Ok,
                             QMessageBox.Ok)
        self.textbox.setText("")

    def onActivated(self,text):
        self.combotext.append(text)




if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
