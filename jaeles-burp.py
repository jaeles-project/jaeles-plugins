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


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController, AbstractTableModel):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        print("[*] Loading Jaeles beta v0.1")
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
        self.banner = JLabel("Jaeles - The Swiss Army knife for automated Web Application Testing. ")
        self.banner.setBounds(50, 30, 200, 400)

        self.banner2 = JLabel("Official Documentation: https://jaeles-project.github.io/")
        self.banner2.setBounds(100, 50, 200, 400)
        _toppane.add(self.banner)
        _toppane.add(self.banner2)

        # _botpane = JPanel()
        _botpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # bot pane
        self.HostLabel = JLabel("Jaeles Endpoint: ")
        self.HostLabel.setBounds(100, 150, 200, 400)

        self.Jaeles_endpoint = 'http://127.0.0.1:5000/api/parse'
        self.jwt = 'Jaeles token_here'
        self.initial()
        jwt, endpoint = self.get_config()

        if endpoint:
            self.Jaeles_endpoint = endpoint        
        if jwt:
            self.jwt = jwt

        endpoint_pane = JPanel()

        # end point to submit request
        self.EndpointText = JTextArea(self.Jaeles_endpoint, 3, 100)

        self.jwtLabel = JLabel("Jaeles JWT token: ")
        self.jwtLabel.setBounds(100, 300, 250, 450)

        self.jwtText = JTextArea(self.jwt, 3, 100, lineWrap=True)

        buttons = JPanel()
        self.buttonLabel = JLabel("Actions: ")
        self.buttonLabel.setBounds(150, 200, 200, 400)
        self._saveButton = JButton("Save", actionPerformed=self.saveToken)
        self._loadButton = JButton(
            "Test Connection", actionPerformed=self.butClick)
        self._reloadButton = JButton("Reload", actionPerformed=self.butClick)

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
        # endpoint_pane.add(self.blankLabel)
        endpoint_pane.add(self.HostLabel)
        endpoint_pane.add(self.EndpointText)
        endpoint_pane.add(self.jwtLabel)
        endpoint_pane.add(self.jwtText)

        buttons.add(self.buttonLabel)
        buttons.add(self._saveButton)
        buttons.add(self._loadButton)
        buttons.add(self._reloadButton)

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
        return

    #
    # implement ITab
    #

    ##
    def saveToken(self, e):
        token = self.jwtText.getText().strip()
        endpoint = self.EndpointText.getText().strip()
        self.Jaeles_endpoint = endpoint
        self.jwt = token
        self.set_config(token, endpoint)

    def butClick(self, e):
        button_name = e.getActionCommand()

        if button_name == 'Reload':
            # self.initial()
            username, password = self.get_cred()
            valid_cred = self.login(username, password)
            jwt, endpoint = self.get_config()
            self.Jaeles_endpoint = endpoint
            self.jwt = jwt
            self.print_log("[+] Reload Config")

        elif button_name == 'Test Connection':
            connection = self.test_connection()
            if connection:
                self.print_log("[+] Ready to send request to {0}".format(self.Jaeles_endpoint))
            else:
                self.print_log("[-] Fail to authen with API server at {0}".format(self.Jaeles_endpoint))

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
        data_json['req_scheme'] = str(messageInfo.getProtocol())  # return http
        data_json['req_host'] = str(messageInfo.getHost())
        data_json['req_port'] = str(messageInfo.getPort())
        data_json['url'] = str(messageInfo.getUrl())

        # full request
        full_req = self._helpers.bytesToString(messageInfo.getRequest())
        data_json['req'] = self.just_base64(str(full_req))

        if messageInfo.getResponse():
            full_res = self._helpers.bytesToString(messageInfo.getResponse())
        else:
            full_res = None
        if not full_res:
            data_json['res'] = ""
            return data_json

        data_json['res'] = self.just_base64(str(full_res.encode('utf-8')))
        return data_json

    # send data to Jaeles API Endpoint
    def import_to_Jaeles(self, data_json):
        req = urllib2.Request(self.Jaeles_endpoint)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', self.jwt)
        self.print_log(req)
        response = urllib2.urlopen(req, json.dumps(data_json))
        if str(response.code) == "200":
            self.print_log("[+] Send request to {0}".format(self.Jaeles_endpoint))
        else:
            self.print_log("[-] Fail Send request to {0}".format(self.Jaeles_endpoint))

    # check if token is available or not
    def initial(self):
        connection = self.test_connection()
        if connection:
            return True
        username, password = self.get_cred()
        valid_cred = self.login(username, password)
        if valid_cred:
            return True
        return False

    # do login
    def login(self, username, password):
        req = urllib2.Request(self.Jaeles_endpoint.replace("/api/parse","/auth/login"))
        req.add_header('Content-Type', 'application/json')
        response = urllib2.urlopen(req, json.dumps({"username": username, "password": password}))

        if str(response.code) == "200":
            data = json.loads(response.read())
            token = "Jaeles " + data.get("token")
            self.set_config(token, self.Jaeles_endpoint, username, password)
            print("[+] Authentication success on {0}".format(self.Jaeles_endpoint))
            return True
        else:
            print("[-] Can't authen on {0}".format(self.Jaeles_endpoint))
            return False

    # check connection
    def test_connection(self):
        req = urllib2.Request(self.Jaeles_endpoint.replace("/parse", "/ping"))
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', self.jwt)
        try:
            response = urllib2.urlopen(req)
            if str(response.code) == "200":
                return True
        except:
            pass
        return False

    # get default credentials
    def get_cred(self):
        config_path = self.get_config_path()
        if os.path.isfile(config_path):
            with open(config_path, 'r') as f:
                data = json.load(f)
            print('[+] Load credentials from {0}'.format(config_path))
            return data.get('username', False), data.get('password', False)
        else:
            print('[-] No config file to load.')
            return False, False

    # get token and endpoint
    def get_config(self):
        config_path = self.get_config_path()
        if os.path.isfile(config_path):
            with open(config_path, 'r') as f:
                data = json.load(f)
            print('[+] Load JWT from {0}'.format(config_path))
            return data.get('JWT', False), data.get('endpoint', False)
        else:
            print('[-] No config file to load.')
            return False, False

    # save jwt token and endpoint to ~/.jaeles/burp.json
    def set_config(self, token, endpoint, username='', password=''):
        data = {
            'JWT': token,
            'endpoint': endpoint,
            'username': username,
            'password': password,
        }
        config_path = self.get_config_path()
        jaeles_path = os.path.dirname(config_path)

        if jaeles_path and not os.path.exists(jaeles_path):
            os.makedirs(jaeles_path)
        with open(config_path, 'w+') as f:
            json.dump(data, f)

        print('[+] Store JWT in {0}'.format(config_path))
        return True
    
    def just_base64(self, text):
        if not text:
            return ""
        return str(base64.b64encode(str(text)))

    def get_config_path(self):
        home = os.path.expanduser('~{0}'.format(getpass.getuser()))
        jaeles_path = os.path.join(home, '.jaeles')

        config_path = os.path.join(jaeles_path, 'burp.json')
        return config_path

    def print_log(self, text):
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
