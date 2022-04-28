# BEGIN LICENSE #
#
# CERT Tapioca
#
# Copyright 2018 Carnegie Mellon University. All Rights Reserved.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
# ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS.
# CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED
# TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY,
# OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON
# UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO
# FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a BSD (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for
# public release and unlimited distribution.  Please see Copyright
# notice for non-US Government use and distribution.
# CERT(R) is registered in the U.S. Patent and Trademark Office by
# Carnegie Mellon University.
#
# DM18-0637
#
# END LICENSE #
try:
    from PyQt4.QtGui import QApplication, QWidget, QPushButton, QMessageBox, QInputDialog
    from PyQt4.QtCore import pyqtSlot
except ImportError:
    from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QMessageBox, QInputDialog
    from PyQt5.QtCore import pyqtSlot


app = QApplication([])
win = QWidget()
msgBox = QMessageBox()

def YesNo(question='', caption='Tapioca'):
    msgBox.setIcon(QMessageBox.Question)
    msgBox.setText(question)
    msgBox.setWindowTitle(caption)
    msgBox.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
    ret = msgBox.exec()
    if ret == QMessageBox.Yes:
        return True
    else:
        return False


def Info(message='', caption='Tapioca'):
    msgBox.setIcon(QMessageBox.Information)
    msgBox.setText(message)
    msgBox.setWindowTitle(caption)
    msgBox.setStandardButtons(QMessageBox.Ok)
    msgBox.exec()


def Warn(message='', caption='Warning!'):
    msgBox.setIcon(QMessageBox.Warning)
    msgBox.setText(message)
    msgBox.setWindowTitle(caption)
    msgBox.setStandardButtons(QMessageBox.Ok)
    msgBox.exec()


def Ask(message='', caption='Tapioca', default_value=''):
    text, ok = QInputDialog.getText(win, caption, message, text=default_value)
    return text
