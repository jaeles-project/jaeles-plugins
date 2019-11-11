from burp import IBurpExtender
from burp import ITab
from burp import IMessageEditorController
from burp import IContextMenuFactory
from burp import IHttpRequestResponse
from burp import IHttpListener
from burp import IParameter
from burp import IBurpCollaboratorInteraction
from burp import IBurpCollaboratorClientContext

from java.awt import Component
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt import Dimension
from java.util import ArrayList
from java.lang import Boolean
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JTable
from javax.swing import JTree
from javax.swing import JOptionPane
from javax.swing import JMenuItem
from javax.swing import JCheckBox
from javax.swing import JComboBox
from javax.swing import JTextArea
from javax.swing import DefaultCellEditor
from javax.swing import JLabel
from javax.swing import JFrame
from javax.swing import JFileChooser
from javax.swing import JPopupMenu
from javax.swing import JTextField
from javax.swing import TransferHandler
from javax.swing import DropMode
from javax.swing import JSeparator
from javax.swing import SwingConstants
from javax.swing import JList
from javax.swing import AbstractCellEditor
from javax.swing import Timer
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import DataFlavor
from javax.swing.table import AbstractTableModel
from javax.swing.table import TableCellRenderer
from javax.swing.table import JTableHeader
from javax.swing.table import TableCellEditor
from java.awt import Color
from java.awt import Font
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.event import ItemListener
from java.awt.event import ItemEvent
from javax.swing.event import DocumentListener
from javax.swing.event import ChangeListener
import java.lang
from threading import Lock
from java.util import LinkedList
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Integer
from java.lang import String
from java.lang import Math
from thread import start_new_thread
from java.util import LinkedList
from javax.swing.tree import DefaultMutableTreeNode
from java.awt import GridLayout
from javax.swing.table import DefaultTableModel

import os
import time
import getpass

from pprint import pprint
import base64
import urllib2
import json

SPECIAL_CHAR = '$$'


# Console colors
W = '\033[1;0m'   # white
R = '\033[1;31m'  # red
G = '\033[1;32m'  # green
O = '\033[1;33m'  # orange
B = '\033[1;34m'  # blue
Y = '\033[1;93m'  # yellow
P = '\033[1;35m'  # purple
C = '\033[1;36m'  # cyan
GR = '\033[1;37m'  # gray
colors = [G, R, B, P, C, O, GR]


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController, AbstractTableModel):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Jaeles")

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        # logTable = Table(self)
        # scrollPane = JScrollPane(logTable)

        # _toppane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        _mainpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        _mainpane.setResizeWeight(0.5)
        # _mainpane = JPanel()

        _toppane = JPanel()

        # top pane
        self.banner = JLabel("Jaeles Scanner ")
        self.banner.setBounds(50, 30, 200, 400)
        _toppane.add(self.banner)

        # _botpane = JPanel()
        _botpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # bot pane
        self.HostLabel = JLabel("Jaeles Endpoint: ")
        self.HostLabel.setBounds(100, 150, 200, 400)

        endpoint_pane = JPanel()
        # end point to submit request
        self.Jaeles_endpoint = 'http://127.0.0.1:5000/api/parse'
        self.HostText = JTextArea(self.Jaeles_endpoint, 3, 100)

        # JWT token
        self.blankLabel = JLabel("\n")
        self.blankLabel.setBounds(80, 120, 200, 400)

        self.jwtLabel = JLabel("Jaeles JWT token: ")
        self.jwtLabel.setBounds(100, 150, 200, 400)

        jwt = self.get_config()
        if jwt:
            self.jwt = jwt
        else:
            self.jwt = 'Jaeles token_here'

        self.jwtText = JTextArea(self.jwt, 3, 100, lineWrap=True)

        buttons = JPanel()
        self.buttonLabel = JLabel("Actions: ")
        self.buttonLabel.setBounds(150, 200, 200, 400)
        self._saveButton = JButton("Save", actionPerformed=self.saveToken)
        self._loadButton = JButton(
            "Test Connection", actionPerformed=self.butClick)
        self._clearButton = JButton("Clear", actionPerformed=self.butClick)

        oob_control = JPanel()
        self.oobLabel = JLabel("OOB: ")
        self.oobLabel.setBounds(150, 200, 200, 400)
        self._saveoob = JButton("Save OOB", actionPerformed=self.saveToken)
        self._pollingBox = JCheckBox("Polling")
        self._pollingBox.setBounds(290, 25, 300, 30)
        oob_control.add(self.oobLabel)
        oob_control.add(self._saveoob)
        oob_control.add(self._pollingBox)

        # _botpane.add(self.banner)
        endpoint_pane.add(self.blankLabel)
        endpoint_pane.add(self.HostLabel)
        endpoint_pane.add(self.HostText)
        endpoint_pane.add(self.jwtLabel)
        endpoint_pane.add(self.jwtText)

        buttons.add(self.buttonLabel)
        buttons.add(self._saveButton)
        buttons.add(self._loadButton)
        buttons.add(self._clearButton)

        _botpane.setLeftComponent(oob_control)
        _botpane.setLeftComponent(endpoint_pane)
        _botpane.setRightComponent(buttons)
        _botpane.setResizeWeight(0.7)

        # set
        _mainpane.setLeftComponent(_toppane)
        _mainpane.setRightComponent(_botpane)

        self._splitpane.setLeftComponent(_mainpane)

        ###########
        # tabs with request/response viewers
        tabs = JTabbedPane()

        self.log_area = JTextArea("", 5, 30)
        # self._requestViewer = callbacks.createMessageEditor(self, False)

        tabs.addTab("Log", self.log_area)
        # tabs.addTab("Config", self._requestViewer.getComponent())

        self._splitpane.setRightComponent(tabs)
        self._splitpane.setResizeWeight(0.5)

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(tabs)

        callbacks.registerContextMenuFactory(self)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # register ourselves as an HTTP listener
        # callbacks.registerHttpListener(self)
        self.print_log("Jaeles Loaded ...")

        # collab = callbacks.createBurpCollaboratorClientContext()
        # self.jaeles_collab(collab)

        return

    #
    # implement ITab
    #

    ##
    def saveToken(self, e):
        self.set_config(self.jwtText.getText().strip())

    def butClick(self, e):
        # print(e.getActionCommand())
        button_name = e.getActionCommand()
        print("{0} Clicked !!!".format(button_name))

        if button_name == 'Reload':
            self.Jaeles_endpoint = self.HostText.getText()
            print("[+] Reload endpoint to {0}".format(self.Jaeles_endpoint))

        elif button_name == 'Test Connection':
            print(self.Jaeles_endpoint)
            req = urllib2.Request(self.Jaeles_endpoint)
            # req.add_header('Content-Type', 'application/json')
            # print()
            response = urllib2.urlopen(req)
            print(response)

            # pass

        # String s = textArea.getText();

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            requestMenuItem = JMenuItem("[*] Send request to Jaeles Endpoint")
            requestMenuItem.addActionListener(
                handleMenuItems(self, responses, "request"))
            ret.add(requestMenuItem)
            return ret
        return None

    def highlightTab(self):
        currentPane = self._splitpane
        previousPane = currentPane
        while currentPane and not isinstance(currentPane, JTabbedPane):
            previousPane = currentPane
            currentPane = currentPane.getParent()
        if currentPane:
            index = currentPane.indexOfComponent(previousPane)
            currentPane.setBackgroundAt(index, Color(0xff6633))

            class setColorBackActionListener(ActionListener):
                def actionPerformed(self, e):
                    currentPane.setBackgroundAt(index, Color.BLACK)

            timer = Timer(5000, setColorBackActionListener())
            timer.setRepeats(False)
            timer.start()

    def getTabCaption(self):
        return "Jaeles"

    def getUiComponent(self):
        return self._splitpane

    #
    # implement Polling Collaborator
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    # def jaeles_collab(self, collab):
    #     oob = collab.generatePayload(True)

    #     # oob2 = collab.generatePayload(True)
    #     # print(oob2)
    #     self.print_log("[+] Gen oob host: {0}".format(oob))
    #     # print(oob)
    #     # os.system('curl {0}'.format(oob))

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    def sendRequestToJaeles(self, messageInfos):
        # just for debug
        for messageInfo in messageInfos:
            data_json = self.req_parsing(messageInfo)

            if data_json:
                self.print_log("Import to external Jaeles ...")
                self.import_to_Jaeles(data_json)
            else:
                self.print_log("No response on selected request")
            self.print_log("-"*30)

    # start of my function

    def req_parsing(self, messageInfo):
        data_json = {}
        # request part
        # requestInfo = self._helpers.analyzeRequest(messageInfo)
        # print(requestInfo.toString())
        data_json['req_scheme'] = str(messageInfo.getProtocol())  # return http
        data_json['req_host'] = str(messageInfo.getHost())
        data_json['req_port'] = str(messageInfo.getPort())
        data_json['url'] = str(messageInfo.getUrl())
        # {'req_scheme': 'http', 'req_host': 'testphp.vulnweb.com', 'req_port': '80'}

        # full request
        full_req = self._helpers.bytesToString(messageInfo.getRequest())
        full_res = self._helpers.bytesToString(messageInfo.getResponse())

        data_json['req'] = self.just_base64(str(full_req))
        data_json['res'] = self.just_base64(str(full_res))
        return data_json

    def import_to_Jaeles(self, data_json):
        # hardcode for now
        # jurl = 'http://127.0.0.1:8000/Jaeles/api/analyzed/create'
        # print(self.jwt)
        req = urllib2.Request(self.Jaeles_endpoint)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', self.jwt)
        self.print_log(req)
        response = urllib2.urlopen(req, json.dumps(data_json))
        # print(response.read())
        self.print_log(response.read())

    def just_base64(self, text):
        return str(base64.b64encode(str(text)))

    def just_wrap_char(self, string_in):
        string_in = self.insert_char(string_in, SPECIAL_CHAR, 0)
        string_in = self.insert_char(
            string_in, SPECIAL_CHAR, len(string_in) + 1)
        return string_in

    def insert_char(self, string_in, insert_char, index):
        return string_in[:index] + insert_char + string_in[index:]

    def get_config_path(self):
        home = os.path.expanduser('~{0}'.format(getpass.getuser()))
        jaeles_path = os.path.join(home, '.jaeles-burp')
        config_path = os.path.join(jaeles_path, 'config.json')
        return config_path

    def get_config(self):
        config_path = self.get_config_path()

        if os.path.isfile(config_path):
            with open(config_path, 'r') as f:
                data = json.load(f)
            print('[+] Load JWT from {0}'.format(config_path))
            return data.get('JWT', False)

        else:
            print('[-] No config file to load.')
            return False

    # save jwt token to ~/'jaeles-burp/config.json
    def set_config(self, jwt):
        data = {
            'JWT': jwt,
            'endpoint': self.Jaeles_endpoint
        }
        config_path = self.get_config_path()
        jaeles_path = os.path.dirname(config_path)

        if jaeles_path and not os.path.exists(jaeles_path):
            os.makedirs(jaeles_path)

        with open(config_path, 'w+') as f:
            json.dump(data, f)

        self.print_log('[+] Store JWT in {0}'.format(config_path))
        return True

    def print_log(self, text):
        # JTextArea.append(String text).
        print(text)
        if type(text) != str:
            text = str(text)
        self.log_area.append(text)
        self.log_area.append("\n")

    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


#
# class to hold details of each log entry
#
class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        if self._menuName == "request":
            start_new_thread(self._extender.sendRequestToJaeles,
                             (self._messageInfo,))

        if self._menuName == "cookie":
            self._extender.replaceString.setText(
                self._extender.getCookieFromMessage(self._messageInfo))

        self._extender.highlightTab()
