#!/usr/bin/python
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

import sys
try:
    from PyQt4 import QtGui, QtCore
except ImportError:
    print(
        'Be sure to run ./install_tapioca.sh before attempting to run %s' % __file__)
    sys.exit(1)
from PyQt4.QtNetwork import QLocalSocket, QLocalServer, QAbstractSocket
import subprocess
import re
import os
import tcpdump
import ssltest
import proxy
import allreports
import json
import time


class Example(QtCore.QObject):
    '''
    This is the main object to set up the app
    '''

    workersignal = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super(self.__class__, self).__init__(parent)

        # Create a gui object.
        self.gui = Window()

        if os.path.isfile('.lastapp'):
            with open('.lastapp', 'r') as lastfile:
                self.appname = lastfile.read()
        else:
            self.appname = ''

        if os.path.isfile('.lastsearch'):
            with open('.lastsearch', 'r') as lastfile:
                self.searchterm = lastfile.read()
        else:
            self.searchterm = ''

        #print('self.appname: %s' % self.appname)

        # Setup the worker object and the worker_thread.
        self.worker = WorkerObject(appname=self.appname)
        self.worker_thread = QtCore.QThread()
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.start()

        # Make any cross object connections.
        self._connectSignals()

        self.cboPopulated = False
        if os.path.isdir('results'):
            appnames = self.getappnames('results')
        else:
            QtGui.QMessageBox.critical(
                self.gui, 'Tapioca', 'You must run install_tapioca.sh before you can use Tapioca.')
            sys.exit(1)
        if appnames:
            appnames.sort()
            self.gui.cboapp.addItems(appnames)
            self.gui.cboapp.setCurrentIndex(
                self.gui.cboapp.findText(self.appname))
        self.cboPopulated = True

        self.gui.searchbox.setText(self.searchterm)

        self.gui.show()
        if not self.gui.unconfigured:
            self.appname = self.gui.getapp(self.appname)
        self.gui.appname = self.appname
        self.getinitialstatus()

    def _connectSignals(self):
        self.gui.btntcpdump.clicked.connect(self.captcpdump)
        self.gui.btnssl.clicked.connect(self.capssltest)
        self.gui.btnfull.clicked.connect(self.capproxy)
        self.gui.btnstop.clicked.connect(self.stopcap)
        self.gui.allreports.clicked.connect(self.allreports)
        self.gui.btnsearch.clicked.connect(self.search)

        self.gui.chksearch.stateChanged.connect(self.multitoggle)
        self.gui.chkrewrite.stateChanged.connect(self.rewritetoggle)
        self.gui.btnrewrite.clicked.connect(self.editrewrite)

        self.worker.signalStatus.connect(self.gui.updateStatus)
        self.worker.signalStatus.connect(self.updateStatus)

        self.workersignal.connect(self.worker.receivework)
        # self.gui.leapp.editingFinished.connect(self.updateapp)
        self.gui.cboapp.editTextChanged.connect(self.updateapp)
        self.gui.searchbox.editingFinished.connect(self.updatesearch)

        self.gui.lblsearchfound.mousePressEvent = self.opentcpdump
        self.gui.lblsearchunprotfound.mousePressEvent = self.openssltest
        self.gui.lblsearchprotfound.mousePressEvent = self.openfulltest
        self.gui.lblsslresultsval.mousePressEvent = self.opensslreport
        self.gui.lblcryptoresultsval.mousePressEvent = self.opencryptoreport
        self.gui.lblnetresultsval.mousePressEvent = self.opennetreport

        self.gui.lbltcpdump.mousePressEvent = self.opentcpdumpcap
        self.gui.lblssltest.mousePressEvent = self.openssltestcap
        self.gui.lblfull.mousePressEvent = self.openfulltestcap

        self.parent().aboutToQuit.connect(self.forceWorkerQuit)

    def forceWorkerQuit(self):
        self.savelastapp()
        if self.worker_thread.isRunning():
            self.worker_thread.terminate()
            self.worker_thread.wait(5)

    def clearteststatus(self, test):
        #print('Getting initial test states')
        if test == 'tcpdump':
            self.gui.lbltcpdump.setText('')
        elif test == 'ssltest':
            self.gui.lblssltest.setText('')
        elif test == 'full':
            self.gui.lblfull.setText('')

    def getinitialstatus(self):
        #print('Getting initial test states')
        if self.testdone('tcpdump'):
            self.gui.lbltcpdump.setText('COMPLETE')
            self.gui.lbltcpdump.setToolTip(
                'Open tcpdump capture for %s' % self.appname)
            self.gui.lbltcpdump.setCursor(
                QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        else:
            self.gui.lbltcpdump.setText('')
            self.gui.lbltcpdump.setToolTip('')
            self.gui.lbltcpdump.setCursor(QtGui.QCursor())
        if self.testdone('ssltest'):
            self.gui.lblssltest.setText('COMPLETE')
            self.gui.lblssltest.setToolTip(
                'Open mitmproxy SSL test capture for %s' % self.appname)
            self.gui.lblssltest.setCursor(
                QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        else:
            self.gui.lblssltest.setText('')
            self.gui.lblssltest.setToolTip('')
            self.gui.lblssltest.setCursor(QtGui.QCursor())
        if self.testdone('full'):
            self.gui.lblfull.setText('COMPLETE')
            self.gui.lblfull.setToolTip(
                'Open mitmproxy full inspection capture for %s' % self.appname)
            self.gui.lblfull.setCursor(
                QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        else:
            self.gui.lblfull.setText('')
            self.gui.lblfull.setToolTip('')
            self.gui.lblfull.setCursor(QtGui.QCursor())
        #print('Getting report states')
        self.gui.updateStatus('report COMPLETE')

    def savelastapp(self):
        #print('Saving .lastapp to %s' % self.appname)
        with open('.lastapp', 'w+') as lastfile:
            lastfile.write(self.appname)
        #print('Saving .lastsearch to %s' % self.searchterm)
        with open('.lastsearch', 'w+') as lastfile:
            lastfile.write(self.searchterm)

    def stopcap(self):
        self.gui.enabletests()
        #print('Stopping capture!')
        subprocess.Popen(['./noproxy.py'])

    def updatesearch(self):
        self.searchterm = self.gui.searchbox.text()
        #print('updating self.searchterm to %s' % self.searchterm)
        self.gui.clearsearchresults()

    def updateapp(self):
        #print('updateapp: self.appname: "%s"' % self.appname)
        if self.cboPopulated:
            # Don't trigger while combobox is being populated
            self.appname = str(self.gui.cboapp.currentText())
            #print('Read %s from combobox' % self.appname)
            self.appname = re.sub(r'\W+', '', str(self.appname)).lower()
            # self.gui.cboapp.setText(self.appname)
            # self.gui.cboapp.setCurrentIndex(self.gui.cboapp.findText(self.appname))
            # if self.appname != '':
            self.worker.appname = self.appname
            self.gui.appname = self.appname
            #print('Updated self.appname to %s' % self.appname)
            self.getinitialstatus()
            self.gui.clearsearchresults()

    def disabletests(self):
        self.gui.disabletests()

    @QtCore.pyqtSlot(str)
    def updateStatus(self, test):
        '''
        Main app module Status update.
        This hooks into the self.worker.signalStatus event
        '''
        #print('*** Main updateStatus : %s ***' % test)
        test = str(test)
        if test.endswith('COMPLETE') or test.endswith('ERROR'):
            if test.startswith('search '):
                # Search results needs to pass data from worker object to GUI
                # object
                #print('Setting search result values in GUI object')
                self.gui.searchfound = self.worker.searchfound
                self.gui.foundunenc = self.worker.foundunenc
                self.gui.foundunprot = self.worker.foundunprot
                self.gui.foundprot = self.worker.foundprot
                self.gui.updatesearchresults()
            else:
                # This is something handled only by the GUI part
                pass
        else:
            # We need a prompt
            prompt_msg = test
            #print('We need a prompt!')
            reply = QtGui.QMessageBox.question(self.gui, 'Tapioca',
                                               prompt_msg, QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                pass
            else:
                pass

    @QtCore.pyqtSlot()
    def captcpdump(self):
        test = 'tcpdump'
        if not self.testdone(test):
            self.disabletests()
            self.workersignal.emit(test)
        else:
            print('%s has already has output for the %s test' %
                  (self.appname, test))
            prompt_msg = '%s has already has output for the %s test. Continue?' % (
                self.appname, test)
            #print('We need a prompt!')
            reply = QtGui.QMessageBox.question(self.gui, 'Tapioca',
                                               prompt_msg, QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                self.clearteststatus(test)
                self.disabletests()
                self.workersignal.emit(test)

    @QtCore.pyqtSlot()
    def capssltest(self):
        test = 'ssltest'
        if not self.testdone(test):
            self.disabletests()
            self.workersignal.emit(test)
            # ltest.testapp(self.appname)
            # elf._sendstatus(test)
        else:
            print('%s has already has output for the %s test' %
                  (self.appname, test))
            prompt_msg = '%s has already has output for the %s test. Continue?' % (
                self.appname, test)
            #print('We need a prompt!')
            reply = QtGui.QMessageBox.question(self.gui, 'Tapioca',
                                               prompt_msg, QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                self.clearteststatus(test)
                self.disabletests()
                self.workersignal.emit(test)

    def _prompt_certinstall(self):
        if os.path.isfile('.certinstall'):
            return

        # Bring dialog to foreground
        time.sleep(3)
        self.gui.activateWindow()

        QtGui.QMessageBox.information(
            self.gui, 'Tapioca', 'Be sure to install the mitmproxy certificate on each device!'
            +
            '\n\nTo start the certificate installation, visit mitm.it on your device and follow instructions.'
            + '\nOnce this is complete, you should perform the Full HTTPS inspection test again.')

        with open('.certinstall', 'w+') as certinstall:
            certinstall.write('')

    @QtCore.pyqtSlot()
    def capproxy(self):
        test = 'full'
        if not self.testdone(test):
            self.disabletests()
            self.workersignal.emit(test)
            self._prompt_certinstall()
        else:
            print('%s has already has output for the %s test' %
                  (self.appname, test))
            prompt_msg = '%s has already has output for the %s test. Continue?' % (
                self.appname, test)
            #print('We need a prompt!')
            reply = QtGui.QMessageBox.question(self.gui, 'Tapioca',
                                               prompt_msg, QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
            if reply == QtGui.QMessageBox.Yes:
                self.clearteststatus(test)
                self.disabletests()
                self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def testdone(self, test):
        #print('Checking if %s is already done for %s' % (test, self.appname))
        capfile = self._getlogfilename(test)
        if capfile:
            if self.appname:
                outdir = './results/%s' % self.appname
            else:
                outdir = './logs'
            flowsfile = '%s/%s' % (outdir, capfile)
            #print('Checking if %s exits...' % flowsfile)
            if os.path.isfile(flowsfile):
                return True
        else:
            return False

    def _getlogfilename(self, test):
        capfile = ''

        if test == 'tcpdump':
            capfile = 'tcpdump.pcap'
        elif test == 'ssltest':
            capfile = 'ssltest.log'
        elif test == 'full':
            capfile = 'flows.log'

        return capfile

    @QtCore.pyqtSlot()
    def restore(self):
        self.gui.setWindowFlags(
            self.gui.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        self.gui.showNormal()
        self.gui.setWindowFlags(
            self.gui.windowFlags() & ~QtCore.Qt.WindowStaysOnTopHint)
        self.gui.showNormal()
        self.gui.activateWindow()

    @QtCore.pyqtSlot()
    def multitoggle(self):
        if self.gui.chksearch.checkState():
            # print('Checked!')
            self.worker.searchmulti = True
        else:
            #print('Not checked')
            self.worker.searchmulti = False

    @QtCore.pyqtSlot()
    def editrewrite(self):
        subprocess.call(['exo-open rewrite.py'], shell=True)

    @QtCore.pyqtSlot()
    def rewritetoggle(self):
        if self.gui.chkrewrite.checkState():
            # print('Checked!')
            self.worker.rewrite = True
            self.gui.btnrewrite.setEnabled(True)
        else:
            # print('Not checked')
            self.worker.rewrite = False
            self.gui.btnrewrite.setEnabled(False)


    @QtCore.pyqtSlot()
    def allreports(self):
        test = 'report'
        self.workersignal.emit(test)

    @QtCore.pyqtSlot()
    def search(self):
        test = 'search'
        self.worker.searchterm = self.gui.searchbox.text()
        self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def opentcpdump(self, event):
        if self.gui.lblsearchfound.text():
            test = 'opentcpdump'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def opentcpdumpcap(self, event):
        if self.gui.lbltcpdump.text() == 'COMPLETE':
            test = 'opentcpdump'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def openssltest(self, event):
        if self.gui.lblsearchunprotfound.text():
            test = 'openssltest'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def openssltestcap(self, event):
        if self.gui.lblssltest.text() == 'COMPLETE':
            test = 'openssltest'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def openfulltest(self, event):
        if self.gui.lblsearchprotfound.text():
            test = 'openfulltest'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def openfulltestcap(self, event):
        if self.gui.lblfull.text() == 'COMPLETE':
            test = 'openfulltest'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def opensslreport(self, event):
        if self.gui.lblsslresultsval.text():
            test = 'opensslreport'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def opencryptoreport(self, event):
        if self.gui.lblcryptoresultsval.text():
            test = 'opencryptoreport'
            self.workersignal.emit(test)

    @QtCore.pyqtSlot(str)
    def opennetreport(self, event):
        if self.gui.lblnetresultsval.text():
            test = 'opennetreport'
            self.workersignal.emit(test)

    def getappnames(self, a_dir):
        return [name.lower() for name in os.listdir(a_dir)
                if os.path.isdir(os.path.join(a_dir, name))]


class WorkerObject(QtCore.QObject):
    '''
    This is the worker object.  Any long-running processes are spawned here
    in a separate thread to retain GUI responsiveness.
    '''

    signalStatus = QtCore.pyqtSignal(str)

    def __init__(self, parent=None, appname=''):
        super(self.__class__, self).__init__(parent)

        #print('=== appname inside of worker: %s' % appname)
        self.appname = appname
        self.searchterm = ''
        self.searchmulti = False
        self.searchfound = False
        self.foundunenc = False
        self.foundunprot = False
        self.foundprot = False
        self.rewrite = False

    @QtCore.pyqtSlot(str)
    def receivework(self, message):
        if message == 'tcpdump':
            #print('** running %s for %s' % (message, self.appname))
            tcpdump.testapp(self.appname)
        elif message == 'ssltest':
            #print('** running %s for %s' % (message, self.appname))
            ssltest.testapp(self.appname, rewrite=self.rewrite)
        elif message == 'full':
            #print('** running %s for %s' % (message, self.appname))
            proxy.testapp(self.appname, rewrite=self.rewrite)
        elif message == 'report':
            #print('** running %s for %s' % (message, self.appname))
            subprocess.call(
                ['xfce4-terminal --disable-server -H -T "Tapioca" -e "./allreports.py %s"' % self.appname], shell=True)
            # allreports.runreports(self.appname)
        elif message == 'opensslreport':
            #print('** received message to open report: %s' % message)
            reportfile = os.path.join('results', self.appname, 'ssltest.txt')
            #print('** Opening report: %s' % reportfile)
            subprocess.call(['exo-open %s' % reportfile], shell=True)
        elif message == 'opennetreport':
            #print('** received message to open report: %s' % message)
            reportfile = os.path.join('results', self.appname, 'net.txt')
            #print('** Opening report: %s' % reportfile)
            subprocess.call(['exo-open %s' % reportfile], shell=True)
        elif message == 'opencryptoreport':
            #print('** received message to open report: %s' % message)
            reportfile = os.path.join('results', self.appname, 'crypto.txt')
            #print('** Opening report: %s' % reportfile)
            subprocess.call(['exo-open %s' % reportfile], shell=True)
        elif message == 'opentcpdump':
            logfile = self._getlogfilename('tcpdump')
            #print('** received message to open tcpdump: %s' % message)
            reportfile = os.path.join('results', self.appname, logfile)
            #print('** Opening report: %s' % reportfile)
            subprocess.call(['exo-open %s' % reportfile], shell=True)
        elif message == 'openssltest':
            logfile = self._getlogfilename('ssltest')
            #print('** received message to open ssltest: %s' % message)
            reportfile = os.path.join('results', self.appname, logfile)
            #print('** Opening report: %s' % reportfile)
            subprocess.call(['exo-open %s' % reportfile], shell=True)
        elif message == 'openfulltest':
            logfile = self._getlogfilename('full')
            #print('** received message to open fulltest: %s' % message)
            reportfile = os.path.join('results', self.appname, logfile)
            #print('** Opening report: %s' % reportfile)
            subprocess.call(['exo-open %s' % reportfile], shell=True)
        elif message == 'search':
            # print('** received message to search %s for %s' %
            #      (self.appname, self.searchterm))
            # search script requires python3, so we can't just load it as a
            # module
            multiflag = ''
            if self.searchmulti:
                multiflag = '-m'
            subprocess.call(
                ['xfce4-terminal --disable-server -H -T "Tapioca" -e "./search.py %s \'%s\' %s"' % (self.appname, self.searchterm, multiflag)], shell=True)
            appdir = os.path.join('results', self.appname)
            jsonfile = os.path.join(appdir, 'search.json')
            txtfile = os.path.join(appdir, 'search.txt')
            subprocess.call(['exo-open', txtfile])
            if os.path.exists(jsonfile):
                reportdict = {}
                try:
                    with open(jsonfile) as jsonhandle:
                        reportdict = json.load(jsonhandle)
                        if reportdict['found']:
                            #print('Search found!')
                            self.searchfound = True
                            if reportdict['foundunenc']:
                                self.foundunenc = True
                                print('Found %s in unencrypted data' %
                                      self.searchterm)
                            if reportdict['foundunprot']:
                                self.foundunprot = True
                                print('Found %s in unprotected HTTPS data' %
                                      self.searchterm)
                            if reportdict['foundprot']:
                                self.foundprot = True
                                print('Found %s in protected HTTPS data' %
                                      self.searchterm)
                        else:
                            self.searchfound = False
                except:
                    print('Problem reading %s' % jsonfile)
            #search.check_app(self.appname, self.searchterm)
        self._sendstatus(message)

    @QtCore.pyqtSlot(str)
    def testdone(self, test):
        #print('Checking if %s is already done for %s' % (test, self.appname))
        capfile = self._getlogfilename(test)
        if capfile:
            if self.appname:
                outdir = './results/%s' % self.appname
            else:
                outdir = './logs'
            flowsfile = '%s/%s' % (outdir, capfile)
            #print('Checking if %s exits...' % flowsfile)
            if os.path.isfile(flowsfile):
                return True
        else:
            return False

    def _getlogfilename(self, test):
        capfile = ''

        if test == 'tcpdump':
            capfile = 'tcpdump.pcap'
        elif test == 'ssltest':
            capfile = 'ssltest.log'
        elif test == 'full':
            capfile = 'flows.log'

        return capfile

    def _sendstatus(self, test, prompt=None):
        if test == 'report':
            self.signalStatus.emit('%s COMPLETE' % test)
        elif test == 'search':
            self.signalStatus.emit('%s COMPLETE' % test)
        elif not prompt:
            if self.testdone(test):
                self.signalStatus.emit('%s COMPLETE' % test)
            else:
                self.signalStatus.emit('%s ERROR' % test)
        else:
            #print('Emitting %s' % prompt)
            self.signalStatus.emit(prompt)


class Window(QtGui.QWidget):
    '''
    This is the GUI object.  Any gui-related operations happen here
    '''

    def __init__(self):

        self.internal_net = ''
        self.external_net = ''
        self.unconfigured = True

        self.searchfound = False
        self.foundunenc = False
        self.foundunprot = False
        self.foundprot = False

        if os.path.exists('tapioca.cfg'):
            with open('tapioca.cfg') as f:
                configlines = f.readlines()
            for line in configlines:
                if line.startswith('external_net'):
                    line = line.rstrip()
                    self.external_net = line.split('=')[1]
                if line.startswith('internal_net'):
                    line = line.rstrip()
                    self.internal_net = line.split('=')[1]

        if self.external_net != 'WAN_DEVICE' and self.internal_net != 'LAN_DEVICE':
            self.unconfigured = False

        QtGui.QWidget.__init__(self)

        self.setWindowTitle('Tapioca')
        app_icon = QtGui.QIcon()
        app_icon.addFile('cert.ico', QtCore.QSize(32, 32))
        self.setWindowIcon(app_icon)

        self.lblupstream = QtGui.QLabel('<b>Upstream-network device:</b>')
        self.lblupstreamval = QtGui.QLabel(self.external_net)
        self.lblupstreamval.setToolTip(
            'Ethernet device used for internet connectivity')
        self.lbllocal = QtGui.QLabel('<b>Locally-provided-network device:</b>')
        self.lbllocalval = QtGui.QLabel(self.internal_net)
        self.lbllocalval.setToolTip(
            'Ethernet device used for connectivity to device under test')
        self.spacer = QtGui.QLabel()
        self.net_status = QtGui.QLabel()
        self.appname = ''
        self.lblapp = QtGui.QLabel('<b>Capture session:</b>')
        self.cboapp = QtGui.QComboBox()
        self.cboapp.setEditable(True)
        self.cboapp.setToolTip(
            'Select an existing session from the dropdown or type a new one')
        #self.leapp = QtGui.QLineEdit()
        self.btntcpdump = QtGui.QPushButton(
            'Capture - All traffic with tcpdump')
        self.btntcpdump.setToolTip(
            'Launch tcpdump to capture all traffic without interception')
        self.lbltcpdump = QtGui.QLabel()
        self.chkrewrite = QtGui.QCheckBox('Modify mitmproxy traffic')
        self.chkrewrite.setToolTip(
            'Edit mitmproxy rules for traffic modification.\nOnly affects "Verify SSL Validation" and "Full HTTPS inspection" tests')
        self.btnrewrite = QtGui.QPushButton('Edit modification rules')
        self.btnrewrite.setToolTip(
            'Modify mitmproxy traffic rewriting rules')
        self.btnrewrite.setEnabled(False)
        self.btnssl = QtGui.QPushButton('Capture - Verify SSL validation')
        self.btnssl.setToolTip(
            'Launch mitmproxy to capture HTTP(S) traffic with an invalid certificate')
        self.lblssltest = QtGui.QLabel()
        self.btnfull = QtGui.QPushButton('Capture - Full HTTPS inspection')
        self.btnfull.setToolTip(
            'Launch mitmproxy to capture HTTP(S) traffic with an installed certificate')
        self.lblfull = QtGui.QLabel()
        self.btnstop = QtGui.QPushButton('Stop current capture')
        self.allreports = QtGui.QPushButton('Generate reports')
        self.allreports.setToolTip(
            'Generate reports for all tests performed for this capture')
        self.lblsslresults = QtGui.QLabel('<b>SSL test results:</b>')
        self.lblsslresultsval = QtGui.QLabel()
        self.lblcryptoresults = QtGui.QLabel('<b>Crypto test results:</b>')
        self.lblcryptoresultsval = QtGui.QLabel()
        self.lblnetresults = QtGui.QLabel(
            '<b>Network connectivity test results:</b>')
        self.lblnetresultsval = QtGui.QLabel()

        self.lblsearch = QtGui.QLabel('<b>Search term:</b>')
        self.searchbox = QtGui.QLineEdit()
        self.searchbox.setToolTip(
            'Case-insensitive perl-compatible regex pattern')
        self.chksearch = QtGui.QCheckBox('Search multiple encodings')
        self.chksearch.setToolTip(
            'Search for base64, md5, and sha1 encodings as well - INCOMPATIBLE with Regex')
        self.btnsearch = QtGui.QPushButton('Search')
        self.btnsearch.setToolTip(
            'Search for term (perl-compatible regex) in all captures')
        self.lblsearchresults = QtGui.QLabel()
        self.lblsearchfound = QtGui.QLabel()
        self.lblsearchunprotfound = QtGui.QLabel()
        self.lblsearchprotfound = QtGui.QLabel()

        #layout = QtGui.QVBoxLayout(self)
        layout = QtGui.QFormLayout(self)
        layout.addRow(self.lblupstream, self.lblupstreamval)
        layout.addRow(self.lbllocal, self.lbllocalval)
        layout.addRow(self.net_status)
        #layout.addRow(self.lblapp, self.leapp)
        layout.addRow(self.lblapp, self.cboapp)
        layout.addRow(self.btntcpdump, self.lbltcpdump)
        layout.addRow(self.btnssl, self.lblssltest)
        layout.addRow(self.btnfull, self.lblfull)
        layout.addRow(self.chkrewrite, self.btnrewrite)
        layout.addRow(self.btnstop)
        layout.addRow(self.spacer)
        layout.addRow(self.spacer)
        layout.addRow(self.lblsearch, self.searchbox)
        layout.addRow(self.chksearch, self.btnsearch)
        layout.addRow(self.lblsearchresults, self.lblsearchfound)
        layout.addRow(self.spacer, self.lblsearchunprotfound)
        layout.addRow(self.spacer, self.lblsearchprotfound)
        layout.addRow(self.allreports)
        layout.addRow(self.lblsslresults, self.lblsslresultsval)
        layout.addRow(self.lblcryptoresults, self.lblcryptoresultsval)
        layout.addRow(self.lblnetresults, self.lblnetresultsval)

        self.setFixedSize(480, 420)
        self.center()

        if self.unconfigured:
            self.net_status.setText(
                '<font color="red"><b>Please enable soft AP or configure networks</b></font>')
            self.disabletests()
            self.disablestop()

        if not self.checklan():
            self.net_status.setText(
                '<font color="red"><b>LAN device %s not found</b></font>' % self.internal_net)
            self.disabletests()
            self.disablestop()

    def checklan(self):
        landevice = subprocess.check_output(
            ["nmcli device status | grep %s | awk '{print $1}'" % self.internal_net], shell=True)
        if not landevice:
            return False
        else:
            return True

    @QtCore.pyqtSlot()
    def clearsearchresults(self):
        #print('Clearing search results...')
        self.lblsearchresults.setText('')
        self.lblsearchfound.setText('')
        self.lblsearchfound.setCursor(QtGui.QCursor())
        self.lblsearchfound.setToolTip('')
        self.lblsearchunprotfound.setText('')
        self.lblsearchunprotfound.setCursor(QtGui.QCursor())
        self.lblsearchunprotfound.setToolTip('')
        self.lblsearchprotfound.setText('')
        self.lblsearchprotfound.setCursor(QtGui.QCursor())
        self.lblsearchprotfound.setToolTip('')

    @QtCore.pyqtSlot()
    def updatesearchresults(self):
        #print('Updating GUI search results...')
        #print('searchfound: %s' % self.searchfound)
        searchresults = ''
        if self.searchfound:
            self.lblsearchresults.setText('<b>Matches:</b>')
            if self.foundunenc:
                searchresults = 'Unencrypted traffic'
                self.lblsearchfound.setText(searchresults)
                self.lblsearchfound.setCursor(
                    QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                self.lblsearchfound.setToolTip('Open raw tcpdump capture')
            else:
                self.lblsearchfound.setText('')
                self.lblsearchfound.setCursor(QtGui.QCursor())
                self.lblsearchfound.setToolTip('')

            if self.foundunprot:
                if searchresults != '':
                    searchresults = searchresults + ', '
                searchresults = 'Unprotected HTTPS traffic'
                self.lblsearchunprotfound.setText(searchresults)
                self.lblsearchunprotfound.setCursor(
                    QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                self.lblsearchunprotfound.setToolTip(
                    'Open SSL test mitmproxy capture')
            else:
                self.lblsearchunprotfound.setText('')
                self.lblsearchunprotfound.setCursor(QtGui.QCursor())
                self.lblsearchunprotfound.setToolTip('')

            if self.foundprot:
                if searchresults != '':
                    searchresults = searchresults + ', '
                searchresults = 'Protected HTTPS traffic'
                self.lblsearchprotfound.setText(searchresults)
                self.lblsearchprotfound.setCursor(
                    QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                self.lblsearchprotfound.setToolTip(
                    'Open full HTTPS inspection mitmproxy capture')
            else:
                self.lblsearchprotfound.setText('')
                self.lblsearchprotfound.setCursor(QtGui.QCursor())
                self.lblsearchprotfound.setToolTip('')

        else:
            self.lblsearchresults.setText('<b>No match</b>')
            self._clearsearchresult()

        # self.lblsearchfound.setText(searchresults)

    def _clearsearchresult(self):
        self.lblsearchprotfound.setText('')
        self.lblsearchprotfound.setCursor(QtGui.QCursor())
        self.lblsearchprotfound.setToolTip('')
        self.lblsearchunprotfound.setText('')
        self.lblsearchunprotfound.setCursor(QtGui.QCursor())
        self.lblsearchunprotfound.setToolTip('')
        self.lblsearchfound.setText('')
        self.lblsearchfound.setCursor(QtGui.QCursor())
        self.lblsearchfound.setToolTip('')

    @QtCore.pyqtSlot(str)
    def check_addapp(self, appname):
        #print('Checking if %s is already there...') % appname
        appindex = self.cboapp.findText(appname)
        if appindex == -1:
            # Current app hasn't been added to combobox
            #print('Adding app %s' % appname)
            self.cboapp.addItem(appname)

    @QtCore.pyqtSlot()
    def disabletests(self):
        #print('Disabling test buttons')
        self.btntcpdump.setEnabled(False)
        self.btnssl.setEnabled(False)
        self.btnfull.setEnabled(False)

    @QtCore.pyqtSlot()
    def disablestop(self):
        #print('Disabling test buttons')
        self.btnstop.setEnabled(False)

    @QtCore.pyqtSlot()
    def enabletests(self):
        #print('Enabling test buttons again!')
        self.btntcpdump.setEnabled(True)
        self.btnssl.setEnabled(True)
        self.btnfull.setEnabled(True)

    @QtCore.pyqtSlot()
    def center(self):
        frameGm = self.frameGeometry()
        screen = QtGui.QApplication.desktop().screenNumber(
            QtGui.QApplication.desktop().cursor().pos())
        centerPoint = QtGui.QApplication.desktop().screenGeometry(
            screen).center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    @QtCore.pyqtSlot(str)
    def getapp(self, appname):
        text, ok = QtGui.QInputDialog.getText(
            self, 'Tapioca', 'Enter capture session name:', QtGui.QLineEdit.Normal,
            appname)
        appname = re.sub(r'\W+', '', str(text)).lower()

        if ok:
            appindex = self.cboapp.findText(appname)
            if appindex == -1:
                # New app
                # Create and select item in combobox
                self.cboapp.addItem(appname)
                self.cboapp.setCurrentIndex(
                    self.cboapp.findText(appname))
            else:
                # existing app
                # Just select item in combobox
                self.cboapp.setCurrentIndex(
                    self.cboapp.findText(appname))

        return appname

    def _reset_resultslinks(self):
        self.lblsslresultsval.setText('')
        self.lblsslresultsval.setToolTip('')
        self.lblsslresultsval.setCursor(
            QtGui.QCursor())
        self.lblcryptoresultsval.setText('')
        self.lblcryptoresultsval.setToolTip('')
        self.lblcryptoresultsval.setCursor(
            QtGui.QCursor())
        self.lblnetresultsval.setText('')
        self.lblnetresultsval.setToolTip('')
        self.lblnetresultsval.setCursor(
            QtGui.QCursor())

    @QtCore.pyqtSlot(str)
    def updateStatus(self, test):
        '''
        GUI module updateStatus
        '''
        failures = {}
        #print('--- gui object updateStatus. test: %s' % test)
        test = str(test)
        if test.endswith('COMPLETE') or test.endswith('ERROR'):
            testname, status = str(test).split()
            #print('testname: %s' % testname)
            if testname == 'report':
                #print('*** %s Report done ***' % self.appname)
                failures = allreports.getfailures(self.appname)
                self._reset_resultslinks()
                #print('=== failures: %s ===' % failures)
                for test in failures:
                    #print('- Checking %s' % test)
                    if test == 'ssltest':
                        self.lblsslresultsval.setToolTip(
                            'Open SSL test report')
                        self.lblsslresultsval.setCursor(
                            QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                        if failures[test] is True:
                            #print('failed ssl!')
                            self.lblsslresultsval.setText(
                                '<font color="red">FAILED</font>')
                        elif failures[test] is False:
                            #print('passed ssl')
                            self.lblsslresultsval.setText(
                                '<font color="green">PASSED</font>')
                    elif test == 'crypto':
                        self.lblcryptoresultsval.setToolTip(
                            'Open SSL test report')
                        self.lblcryptoresultsval.setCursor(
                            QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                        if failures[test] is True:
                            self.lblcryptoresultsval.setText(
                                '<font color="red">FAILED</font>')
                        elif failures[test] is False:
                            self.lblcryptoresultsval.setText(
                                '<font color="green">PASSED</font>')
                    elif test == 'net':
                        self.lblnetresultsval.setToolTip(
                            'Open SSL test report')
                        self.lblnetresultsval.setCursor(
                            QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                        if test in failures:
                            self.lblnetresultsval.setText('VIEW')
                        else:
                            self.lblnetresultsval.setText('')

            elif testname == 'search':
                # Let main app object handle this to allow for value passing
                pass
                # self.lblsearchfound.setText(status)
                #print('*** Search complete! ***')
            elif testname == 'openssltest' or testname == 'openfulltest' \
                    or testname == 'opentcpdump' or testname == 'opensslreport' \
                    or testname == 'opencryptoreport' or testname == \
                    'opennetreport':
                # NO need to enable test buttons or so anything else
                pass
            else:
                # Test capture complete
                # Updating individual test status
                #print('gui.updatestatus() re-enabling test buttons')
                self.enabletests()
                #print('*** GUI updateStatus : %s' % test)

                if status == 'COMPLETE':
                    # A test has completed.  Add appname to combobox
                    #print('Finished a test... adding to combobox')
                    self.check_addapp(self.appname)

                if testname == 'tcpdump':
                    self.lbltcpdump.setText(status)
                    if status == 'COMPLETE':
                        self.lbltcpdump.setToolTip(
                            'Open tcpdump capture for %s' % self.appname)
                        self.lbltcpdump.setCursor(
                            QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                    else:
                        self.lbltcpdump.setToolTip('')
                        self.lbltcpdump.setCursor(QtGui.QCursor())
                elif testname == 'ssltest':
                    self.lblssltest.setText(status)
                    if status == 'COMPLETE':
                        self.lblssltest.setToolTip(
                            'Open mitmproxy SSL test capture for %s' % self.appname)
                        self.lblssltest.setCursor(
                            QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                    else:
                        self.lblssltest.setToolTip('')
                        self.lblssltest.setCursor(QtGui.QCursor())
                elif testname == 'full':
                    self.lblfull.setText(status)
                    if status == 'COMPLETE':
                        self.lblfull.setToolTip(
                            'Open mitmproxy full inspection capture for %s' % self.appname)
                        self.lblfull.setCursor(
                            QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                    else:
                        self.lblfull.setToolTip('')
                        self.lblfull.setCursor(QtGui.QCursor())


if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)

    # self.qtappname = 'Tapioca'
    socket = QLocalSocket()
    socket.connectToServer('Tapioca')
    if socket.isOpen():
        socket.close
        socket.deleteLater()
        sys.exit(0)

    example = Example(app)

    socket.deleteLater()
    server = QLocalServer()
    server.newConnection.connect(example.restore)
    ok = server.listen('Tapioca')
    if not ok:
        if server.serverError() == QAbstractSocket.AddressInUseError:
             #print('Socket in use!')
            server.removeServer('Tapioca')
            ok = server.listen('Tapioca')
            if not ok:
                print('Socket trouble!')

    try:
        sys.exit(app.exec_())
    except:
        pass
