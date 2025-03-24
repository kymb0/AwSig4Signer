from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from javax.swing import JPanel, JLabel, JTextField, JButton, JCheckBox, JMenuItem, JTabbedPane, JTextArea, JScrollPane, BorderFactory, UIManager, JComboBox
from java.awt import GridLayout, BorderLayout, Font, Color
from java.awt.event import ActionListener, ItemListener
import hmac
import hashlib
import xml.etree.ElementTree as ET
import json
import time
import threading
import re
import urllib

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    """
    AwSigV4Signer - AWS Signature V4 Signing Plugin for Burp Suite
    Author: kymb0 and grok
    Version: 2.1
    Description: Robust AWS SigV4 signing
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AwSigV4Signer")

        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # Config
        self.profiles = {"Default": {
            "access_key": "",
            "secret_key": "",
            "region": "us-east-1",
            "service": "iam",
            "endpoint": "",  # Optional
            "auth_endpoint": "/get-credentials",
            "access_key_path": "Credentials.AccessKeyId",
            "secret_key_path": "Credentials.SecretAccessKey"
        }}
        self.current_profile = "Default"
        self.signing_enabled = False
        self.auto_extract_enabled = False
        self.scope_only = False
        self.logging_enabled = True
        self.tool_settings = {"Proxy": False, "Repeater": True, "Scanner": False, "Spider": False, "Intruder": False, "Sequencer": False}
        self.signing_method = "Header"
        self.console_text = ""
        self.last_signed = "Never"
        self.url_filter = ""
        self.lock = threading.Lock()

        # GUI
        self.access_key_field = JTextField(20)
        self.secret_key_field = JTextField(20)
        self.region_field = JTextField(self.profiles["Default"]["region"], 20)
        self.service_field = JTextField(self.profiles["Default"]["service"], 20)
        self.endpoint_field = JTextField(self.profiles["Default"]["endpoint"], 20)
        self.auth_endpoint_field = JTextField(self.profiles["Default"]["auth_endpoint"], 20)
        self.access_key_path_field = JTextField(self.profiles["Default"]["access_key_path"], 20)
        self.secret_key_path_field = JTextField(self.profiles["Default"]["secret_key_path"], 20)
        self.profile_name_field = JTextField("NewProfile", 20)
        self.console_area = JTextArea(10, 50)
        self.console_area.setEditable(False)
        self.manual_request_area = JTextArea(10, 50)
        self.url_filter_field = JTextField("", 20)

        UIManager.put("Label.font", Font("Arial", Font.PLAIN, 12))
        UIManager.put("TextField.font", Font("Arial", Font.PLAIN, 12))
        UIManager.put("Button.font", Font("Arial", Font.BOLD, 12))

        saved_profiles = self._callbacks.loadExtensionSetting("sigv4_profiles")
        if saved_profiles:
            self.profiles = json.loads(saved_profiles)

        self._tab = self.createTabbedPane()
        callbacks.addSuiteTab(self)
        self.log("INFO", "AwSigV4Signer v2.1 loaded - Set it up in 'Config'.")

    def createTabbedPane(self):
        tabbed_pane = JTabbedPane()
        config_tab = self.createConfigTab()
        config_tab.setBorder(BorderFactory.createTitledBorder("Config"))
        tabbed_pane.addTab("Config", config_tab)

        console_panel = JPanel(BorderLayout(5, 5))
        console_panel.add(JScrollPane(self.console_area), BorderLayout.CENTER)
        self.toggle_logging = JCheckBox("Enable Logging", actionPerformed=self.toggleLogging)
        self.toggle_logging.setSelected(True)
        console_panel.add(self.toggle_logging, BorderLayout.SOUTH)
        console_panel.setBorder(BorderFactory.createTitledBorder("Logs"))
        tabbed_pane.addTab("Console", console_panel)

        manual_tab = self.createManualSignTab()
        manual_tab.setBorder(BorderFactory.createTitledBorder("Manual Sign"))
        tabbed_pane.addTab("Manual", manual_tab)
        return tabbed_pane

    def createConfigTab(self):
        panel = JPanel(GridLayout(0, 3, 5, 5))
        fields = [
            ("Access Key *", self.access_key_field, "e.g., AKIAIOSFODNN7EXAMPLE"),
            ("Secret Key *", self.secret_key_field, "e.g., wJalrXUtnFEMI/K7MDENG..."),
            ("Region", self.region_field, "e.g., us-east-1 (default if blank)"),
            ("Service", self.service_field, "e.g., iam (default: execute-api)"),
            ("Endpoint", self.endpoint_field, "e.g., https://iam.amazonaws.com/ (optional)"),
            ("Auth Endpoint", self.auth_endpoint_field, "e.g., /get-credentials (optional)"),
            ("Access Key Path", self.access_key_path_field, "e.g., Credentials.AccessKeyId (optional)"),
            ("Secret Key Path", self.secret_key_path_field, "e.g., Credentials.SecretAccessKey (optional)"),
        ]
        for label, field, tooltip in fields:
            lbl = JLabel(label)
            lbl.setToolTipText(tooltip)
            panel.add(lbl)
            panel.add(field)
            panel.add(JLabel(""))

        self.profile_combo = JComboBox(self.profiles.keys())
        self.profile_combo.addItemListener(ProfileSelector(self))
        panel.add(JLabel("Profile"))
        panel.add(self.profile_combo)
        save_button = JButton("Save", actionPerformed=SaveProfileAction(self))
        panel.add(save_button)

        self.toggle_signing = JCheckBox("Auto-Sign", actionPerformed=self.toggleSigning)
        self.signing_status = JLabel("Off", JLabel.CENTER)
        self.signing_status.setForeground(Color.RED)
        panel.add(self.toggle_signing)
        panel.add(self.signing_status)
        panel.add(JLabel(""))

        self.toggle_auto_extract = JCheckBox("Auto-Extract", actionPerformed=self.toggleAutoExtract)
        self.extract_status = JLabel("Off", JLabel.CENTER)
        self.extract_status.setForeground(Color.RED)
        panel.add(self.toggle_auto_extract)
        panel.add(self.extract_status)
        panel.add(JLabel(""))

        self.toggle_scope_only = JCheckBox("Scope Only", actionPerformed=self.toggleScopeOnly)
        self.scope_status = JLabel("All", JLabel.CENTER)
        self.scope_status.setForeground(Color.BLUE)
        panel.add(self.toggle_scope_only)
        panel.add(self.scope_status)
        panel.add(JLabel(""))

        panel.add(JLabel("URL Filter"))
        panel.add(self.url_filter_field)
        panel.add(JLabel("e.g., .*amazonaws.*"))

        self.signing_method_combo = JComboBox(["Header", "Presigned", "Chunked"])
        self.signing_method_combo.addItemListener(SigningMethodSelector(self))
        panel.add(JLabel("Method"))
        panel.add(self.signing_method_combo)
        panel.add(JLabel(""))

        tools = [
            ("Proxy", "Proxy requests", 16),
            ("Repeater", "Repeater requests", 64),
            ("Scanner", "Scanner requests", 4),
            ("Spider", "Spider requests", 32),
            ("Intruder", "Intruder requests", 128),
            ("Sequencer", "Sequencer requests", 256)
        ]
        self.tool_checkboxes = {}
        for tool, tooltip, _ in tools:
            checkbox = JCheckBox(tool, actionPerformed=self.toggleTool(tool))
            checkbox.setToolTipText(tooltip)
            checkbox.setSelected(self.tool_settings[tool])
            self.tool_checkboxes[tool] = checkbox
            panel.add(checkbox)
            panel.add(JLabel(""))
            panel.add(JLabel(""))

        self.last_signed_label = JLabel("Last Signed: Never")
        panel.add(JLabel("Last Signed"))
        panel.add(self.last_signed_label)
        panel.add(JLabel(""))

        return panel

    def createManualSignTab(self):
        panel = JPanel(BorderLayout(5, 5))
        panel.add(JScrollPane(self.manual_request_area), BorderLayout.CENTER)
        sign_button = JButton("Sign", actionPerformed=self.manualSignAction)
        panel.add(sign_button, BorderLayout.SOUTH)
        return panel

    def toggleSigning(self, event):
        self.signing_enabled = self.toggle_signing.isSelected()
        self.signing_status.setText("On" if self.signing_enabled else "Off")
        self.signing_status.setForeground(Color.GREEN if self.signing_enabled else Color.RED)
        self.log("INFO", "Auto-Signing: %s" % self.signing_enabled)

    def toggleScopeOnly(self, event):
        self.scope_only = self.toggle_scope_only.isSelected()
        self.scope_status.setText("Scope" if self.scope_only else "All")
        self.scope_status.setForeground(Color.GREEN if self.scope_only else Color.BLUE)
        self.log("INFO", "Scope-Only: %s" % self.scope_only)

    def toggleAutoExtract(self, event):
        self.auto_extract_enabled = self.toggle_auto_extract.isSelected()
        self.extract_status.setText("On" if self.auto_extract_enabled else "Off")
        self.extract_status.setForeground(Color.GREEN if self.auto_extract_enabled else Color.RED)
        self.log("INFO", "Auto-Extract: %s" % self.auto_extract_enabled)

    def toggleLogging(self, event):
        self.logging_enabled = self.toggle_logging.isSelected()
        self.log("INFO", "Logging: %s" % self.logging_enabled)

    def toggleTool(self, tool):
        def action(event):
            self.tool_settings[tool] = self.tool_checkboxes[tool].isSelected()
            self.log("INFO", "%s Signing: %s" % (tool, self.tool_settings[tool]))
        return action

    def loadProfile(self, profile_name):
        if profile_name in self.profiles:
            profile = self.profiles[profile_name]
            self.access_key_field.setText(profile["access_key"])
            self.secret_key_field.setText(profile["secret_key"])
            self.region_field.setText(profile["region"])
            self.service_field.setText(profile["service"])
            self.endpoint_field.setText(profile["endpoint"])
            self.auth_endpoint_field.setText(profile["auth_endpoint"])
            self.access_key_path_field.setText(profile["access_key_path"])
            self.secret_key_path_field.setText(profile["secret_key_path"])
            self.current_profile = profile_name
            self.log("INFO", "Loaded profile: %s" % profile_name)

    def saveProfile(self, profile_name):
        if not profile_name:
            self.log("WARN", "Profile name cannot be empty")
            return
        self.profiles[profile_name] = {
            "access_key": self.access_key_field.getText(),
            "secret_key": self.secret_key_field.getText(),
            "region": self.region_field.getText(),
            "service": self.service_field.getText(),
            "endpoint": self.endpoint_field.getText(),
            "auth_endpoint": self.auth_endpoint_field.getText(),
            "access_key_path": self.access_key_path_field.getText(),
            "secret_key_path": self.secret_key_path_field.getText()
        }
        self._callbacks.saveExtensionSetting("sigv4_profiles", json.dumps(self.profiles))
        if profile_name not in [self.profile_combo.getItemAt(i) for i in range(self.profile_combo.getItemCount())]:
            self.profile_combo.addItem(profile_name)
        self.current_profile = profile_name
        self.log("INFO", "Saved profile: %s" % profile_name)

    def getTabCaption(self):
        return "AwSigV4Signer"

    def getUiComponent(self):
        return self._tab

    def createMenuItems(self, invocation):
        return [JMenuItem("Sign Now", actionPerformed=self.signNowAction(invocation))]

    def signNowAction(self, invocation):
        def action(event):
            self.signNow(invocation)
        return action

    def signNow(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            self.log("WARN", "No request selected")
            return
        for message in messages:
            try:
                request = message.getRequest()
                http_service = message.getHttpService()
                request_info = self._helpers.analyzeRequest(http_service, request)
                headers = request_info.getHeaders()
                body = request[request_info.getBodyOffset():].tostring()
                url = request_info.getUrl()
                if self.scope_only and not self._callbacks.isInScope(url):
                    self.log("INFO", "Skipping out-of-scope: %s" % url)
                    continue
                host = self.getHostFromHeaders(headers)
                new_headers, new_body, query_string = self.signRequest(headers, body, host, request_info.getMethod(), str(url.getPath()))
                if query_string:
                    new_url = str(url) + ("?" + query_string if "?" not in str(url) else "&" + query_string)
                    new_request = self._helpers.buildHttpRequest(self._helpers.stringToBytes(new_url), new_body)
                else:
                    new_request = self._helpers.buildHttpMessage(new_headers, new_body)
                message.setRequest(new_request)
                self.log("INFO", "Signed request: %s" % url)
                self.updateLastSigned()
            except Exception, e:
                self.log("ERROR", "Sign Now failed: %s" % str(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        tool_map = {4: "Scanner", 16: "Proxy", 32: "Spider", 64: "Repeater", 128: "Intruder", 256: "Sequencer"}
        tool_name = tool_map.get(toolFlag, "Unknown")

        if not messageIsRequest and self.auto_extract_enabled:
            try:
                request = messageInfo.getRequest()
                http_service = messageInfo.getHttpService()
                request_info = self._helpers.analyzeRequest(http_service, request)
                url = request_info.getUrl()
                if self.auth_endpoint_field.getText() not in str(url) or request_info.getMethod() != "POST":
                    return
                response = messageInfo.getResponse()
                response_info = self._helpers.analyzeResponse(response)
                response_body = response[response_info.getBodyOffset():].tostring()
                self.extractCredentials(response_body)
            except ValueError, e:
                self.log("ERROR", "Extract failed: %s" % str(e))
            return

        if not messageIsRequest or not self.signing_enabled:
            return

        if tool_name not in self.tool_settings or not self.tool_settings[tool_name]:
            self.log("DEBUG", "Skipping tool: %s" % tool_name)
            return

        try:
            request = messageInfo.getRequest()
            http_service = messageInfo.getHttpService()
            request_info = self._helpers.analyzeRequest(http_service, request)
            url = request_info.getUrl()
            url_str = str(url)
            if self.scope_only and not self._callbacks.isInScope(url):
                return
            if self.url_filter and not re.search(self.url_filter, url_str):
                self.log("DEBUG", "URL %s skipped (filter: %s)" % (url_str, self.url_filter))
                return
            headers = request_info.getHeaders()
            body = request[request_info.getBodyOffset():].tostring()
            host = self.getHostFromHeaders(headers)
            new_headers, new_body, query_string = self.signRequest(headers, body, host, request_info.getMethod(), str(url.getPath()))
            if query_string:
                new_url = url_str + ("?" + query_string if "?" not in url_str else "&" + query_string)
                new_request = self._helpers.buildHttpRequest(self._helpers.stringToBytes(new_url), new_body)
            else:
                new_request = self._helpers.buildHttpMessage(new_headers, new_body)
            messageInfo.setRequest(new_request)
            self.log("INFO", "Signed %s (Tool: %s)" % (url, tool_name))
            self.updateLastSigned()
        except Exception, e:
            self.log("ERROR", "Auto-sign failed: %s" % str(e))

    def signRequest(self, headers, body, host, method, path):
        try:
            access_key = self.access_key_field.getText().strip()
            secret_key = self.secret_key_field.getText().strip()
            region = self.region_field.getText().strip() or "us-east-1"
            service = self.service_field.getText().strip() or "execute-api"
            endpoint = self.endpoint_field.getText().strip()

            if not access_key or not secret_key:
                raise ValueError("Access Key and Secret Key required")
            if not host and not endpoint:
                raise ValueError("Host or Endpoint required")
            host = host if not endpoint else (endpoint.split("://")[1].split("/")[0] if "://" in endpoint else endpoint)

            sign_body = body or ""
            amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            date_stamp = amz_date[:8]
            content_sha256 = hashlib.sha256(sign_body).hexdigest()

            canonical_headers = (
                "accept:application/json\n"
                "host:%s\n"
                "x-amz-content-sha256:%s\n"
                "x-amz-date:%s\n" % (host, content_sha256, amz_date)
            )
            signed_headers = "accept;host;x-amz-content-sha256;x-amz-date"
            canonical_request = "%s\n%s\n\n%s\n%s\n%s" % (
                method.upper(), path or "/", canonical_headers, signed_headers, content_sha256)
            canonical_hash = hashlib.sha256(canonical_request).hexdigest()

            credential_scope = "%s/%s/%s/aws4_request" % (date_stamp, region, service)
            string_to_sign = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (amz_date, credential_scope, canonical_hash)

            # Force bytes for HMAC
            k_date = hmac.new(("AWS4" + secret_key).encode('utf-8'), date_stamp.encode('utf-8'), hashlib.sha256).digest()
            k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
            k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
            k_signing = hmac.new(k_service, "aws4_request".encode('utf-8'), hashlib.sha256).digest()
            signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

            if self.signing_method == "Header":
                new_headers = list(headers)
                header_positions = {"X-Amz-Content-Sha256": None, "X-Amz-Date": None, "Authorization": None}
                for i, header in enumerate(new_headers):
                    for key in header_positions:
                        if header.startswith(key):
                            header_positions[key] = i
                            break
                sigv4_headers = {
                    "X-Amz-Content-Sha256": "X-Amz-Content-Sha256: %s" % content_sha256,
                    "X-Amz-Date": "X-Amz-Date: %s" % amz_date,
                    "Authorization": "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
                        access_key, credential_scope, signed_headers, signature)
                }
                for key, value in sigv4_headers.items():
                    if header_positions[key] is not None:
                        new_headers[header_positions[key]] = value
                    else:
                        new_headers.append(value)
                return new_headers, sign_body, None

            elif self.signing_method == "Presigned":
                query_params = {
                    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                    "X-Amz-Credential": "%s/%s" % (access_key, credential_scope),
                    "X-Amz-Date": amz_date,
                    "X-Amz-Expires": "3600",
                    "X-Amz-SignedHeaders": signed_headers,
                    "X-Amz-Signature": signature
                }
                if method.upper() in ["POST", "PUT"]:
                    query_params["X-Amz-Content-Sha256"] = content_sha256
                query_string = "&".join(["%s=%s" % (k, urllib.quote_plus(str(v))) for k, v in query_params.items()])
                return headers, sign_body, query_string

            elif self.signing_method == "Chunked":
                new_headers = list(headers)
                header_positions = {"X-Amz-Content-Sha256": None, "X-Amz-Date": None, "Authorization": None}
                for i, header in enumerate(new_headers):
                    for key in header_positions:
                        if header.startswith(key):
                            header_positions[key] = i
                            break
                sigv4_headers = {
                    "X-Amz-Content-Sha256": "X-Amz-Content-Sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                    "X-Amz-Date": "X-Amz-Date: %s" % amz_date,
                    "Authorization": "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
                        access_key, credential_scope, signed_headers, signature)
                }
                for key, value in sigv4_headers.items():
                    if header_positions[key] is not None:
                        new_headers[header_positions[key]] = value
                    else:
                        new_headers.append(value)
                return new_headers, sign_body, None

        except Exception, e:
            self.log("ERROR", "Signing failed - Access: %s, Secret: %s[...], Host: %s: %s" % (
                access_key, secret_key[:6] if secret_key else "None", host, str(e)))
            raise

    def manualSignAction(self, event):
        try:
            request_text = self.manual_request_area.getText()
            if not request_text:
                self.log("WARN", "No request provided")
                return
            request_bytes = self._helpers.stringToBytes(request_text)
            request_info = self._helpers.analyzeRequest(request_bytes)
            headers = request_info.getHeaders()
            body = request_bytes[request_info.getBodyOffset():].tostring()
            host = self.getHostFromHeaders(headers)
            new_headers, new_body, query_string = self.signRequest(headers, body, host, request_info.getMethod(), "/")
            if query_string:
                new_request_text = request_text.split("\n", 1)[0] + "?" + query_string + "\n" + "\n".join(request_text.split("\n")[1:])
                self.manual_request_area.setText(new_request_text)
            else:
                signed_request = self._helpers.buildHttpMessage(new_headers, new_body)
                self.manual_request_area.setText(self._helpers.bytesToString(signed_request))
            self.log("INFO", "Manual sign done (Method: %s)" % self.signing_method)
            self.updateLastSigned()
        except Exception, e:
            self.log("ERROR", "Manual sign failed: %s" % str(e))

    def extractCredentials(self, response_body):
        self.log("INFO", "Extracting creds")
        try:
            data = json.loads(response_body)
            access_key = self.getNestedValue(data, self.access_key_path_field.getText().split("."))
            secret_key = self.getNestedValue(data, self.secret_key_path_field.getText().split("."))
            if access_key and secret_key:
                self.access_key_field.setText(access_key)
                self.secret_key_field.setText(secret_key)
                self.log("INFO", "Extracted JSON: Access=%s, Secret=%s..." % (access_key, secret_key[:6]))
                return
        except ValueError, e:
            self.log("DEBUG", "JSON parse failed: %s" % str(e))

        try:
            root = ET.fromstring(response_body)
            namespace = "{https://iam.amazonaws.com/doc/2010-05-08/}"
            credentials = root.find(".//%sCredentials" % namespace)
            if credentials is not None:
                access_key = credentials.findtext("%sAccessKeyId" % namespace)
                secret_key = credentials.findtext("%sSecretAccessKey" % namespace)
                if access_key and secret_key:
                    self.access_key_field.setText(access_key)
                    self.secret_key_field.setText(secret_key)
                    self.log("INFO", "Extracted XML: Access=%s, Secret=%s..." % (access_key, secret_key[:6]))
        except ET.ParseError, e:
            self.log("DEBUG", "XML parse failed: %s" % str(e))

    def getHostFromHeaders(self, headers):
        for header in headers:
            if header.lower().startswith("host:"):
                return header.split(":", 1)[1].strip()
        self.log("DEBUG", "No Host header, using endpoint if set")
        endpoint = self.endpoint_field.getText().strip()
        return endpoint.split("://")[1].split("/")[0] if endpoint and "://" in endpoint else None

    def getNestedValue(self, data, keys):
        try:
            for key in keys:
                data = data[key]
            return data
        except (KeyError, TypeError):
            return None

    def log(self, level, message):
        if not self.logging_enabled:
            return
        prefix = "[%s] %s" % (level, time.strftime("%Y-%m-%d %H:%M:%S"))
        log_message = "%s - %s" % (prefix, message)
        if level == "ERROR":
            self._callbacks.printError(log_message)
        else:
            self._callbacks.printOutput(log_message)
        with self.lock:
            self.console_text += log_message + "\n"
            self.console_area.setText(self.console_text)
            self.console_area.setCaretPosition(self.console_area.getDocument().getLength())

    def updateLastSigned(self):
        self.last_signed = time.strftime("%Y-%m-%d %H:%M:%S")
        self.last_signed_label.setText("Last Signed: %s" % self.last_signed)

class SaveProfileAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        self.extender.saveProfile(self.extender.profile_name_field.getText())

class ProfileSelector(ItemListener):
    def __init__(self, extender):
        self.extender = extender
    def itemStateChanged(self, event):
        if event.getStateChange() == 1:
            self.extender.loadProfile(event.getItem())

class SigningMethodSelector(ItemListener):
    def __init__(self, extender):
        self.extender = extender
    def itemStateChanged(self, event):
        if event.getStateChange() == 1:
            self.extender.signing_method = event.getItem()
            self.extender.log("INFO", "Method set: %s" % self.extender.signing_method)
