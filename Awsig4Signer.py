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

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    """
    AwSigV4Signer - AWS Signature V4 Signing Plugin for Burp Suite
    Author: kymb0 and grok (mainly grok)
    Version: 1.5
    Description: Robust AWS SigV4 signing with auto-signing, credential extraction, and enhanced UI control.
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AwSigV4Signer")

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # Initial config
        self.profiles = {"Default": {
            "access_key": "Enter AWS Access Key",
            "secret_key": "Enter AWS Secret Key",
            "region": "us-east-1",
            "service": "iam",
            "auth_endpoint": "/get-credentials",
            "access_key_path": "Credentials.AccessKeyId",
            "secret_key_path": "Credentials.SecretAccessKey"
        }}
        self.current_profile = "Default"
        self.signing_enabled = False
        self.auto_extract_enabled = False
        self.scope_only = False
        self.logging_enabled = True
        self.tool_settings = {"Repeater": True}  # Default Repeater on
        self.console_text = ""
        self.last_signed = "Never"
        self.url_filter = ""  # Regex filter
        self.lock = threading.Lock()  # GUI thread safety

        # GUI fields
        self.access_key_field = JTextField(self.profiles["Default"]["access_key"], 20)
        self.secret_key_field = JTextField(self.profiles["Default"]["secret_key"], 20)
        self.region_field = JTextField(self.profiles["Default"]["region"], 20)
        self.service_field = JTextField(self.profiles["Default"]["service"], 20)
        self.auth_endpoint_field = JTextField(self.profiles["Default"]["auth_endpoint"], 20)
        self.access_key_path_field = JTextField(self.profiles["Default"]["access_key_path"], 20)
        self.secret_key_path_field = JTextField(self.profiles["Default"]["secret_key_path"], 20)
        self.profile_name_field = JTextField("NewProfile", 20)
        self.console_area = JTextArea(10, 50)
        self.console_area.setEditable(False)
        self.manual_request_area = JTextArea(10, 50)
        self.url_filter_field = JTextField("", 20)

        # Styling
        UIManager.put("Label.font", Font("Arial", Font.PLAIN, 12))
        UIManager.put("TextField.font", Font("Arial", Font.PLAIN, 12))
        UIManager.put("Button.font", Font("Arial", Font.BOLD, 12))

        # Load saved profiles
        saved_profiles = self._callbacks.loadExtensionSetting("sigv4_profiles")
        if saved_profiles:
            self.profiles = json.loads(saved_profiles)

        self._tab = self.createTabbedPane()
        callbacks.addSuiteTab(self)
        self.log("INFO", "AwSigV4Signer v1.5 loaded - Configure settings in the 'Config' tab.")

    def createTabbedPane(self):
        tabbed_pane = JTabbedPane()
        config_tab = self.createConfigTab()
        config_tab.setBorder(BorderFactory.createTitledBorder("Configuration"))
        tabbed_pane.addTab("Config", config_tab)

        console_panel = JPanel(BorderLayout(10, 10))
        console_panel.add(JScrollPane(self.console_area), BorderLayout.CENTER)
        self.toggle_logging = JCheckBox("Enable Logging", actionPerformed=self.toggleLogging)
        self.toggle_logging.setSelected(True)
        console_panel.add(self.toggle_logging, BorderLayout.SOUTH)
        console_panel.setBorder(BorderFactory.createTitledBorder("Log Output"))
        tabbed_pane.addTab("Console", console_panel)

        manual_tab = self.createManualSignTab()
        manual_tab.setBorder(BorderFactory.createTitledBorder("Manual Signature Generator"))
        tabbed_pane.addTab("Manual Sign", manual_tab)
        return tabbed_pane

    def createConfigTab(self):
        panel = JPanel(GridLayout(0, 3, 10, 10))
        fields = [
            ("Access Key:", self.access_key_field, "AWS Access Key ID"),
            ("Secret Key:", self.secret_key_field, "AWS Secret Access Key"),
            ("Region:", self.region_field, "AWS Region (e.g., us-east-1)"),
            ("Service:", self.service_field, "AWS Service (e.g., iam)"),
            ("Auth Endpoint:", self.auth_endpoint_field, "Endpoint for credential extraction"),
            ("Access Key Path:", self.access_key_path_field, "JSON/XML path to Access Key"),
            ("Secret Key Path:", self.secret_key_path_field, "JSON/XML path to Secret Key"),
        ]
        for label, field, tooltip in fields:
            lbl = JLabel(label)
            lbl.setToolTipText(tooltip)
            panel.add(lbl)
            panel.add(field)
            panel.add(JLabel(""))

        self.profile_combo = JComboBox(self.profiles.keys())
        self.profile_combo.addItemListener(ProfileSelector(self))
        panel.add(JLabel("Profile:"))
        panel.add(self.profile_combo)
        panel.add(JLabel(""))

        panel.add(JLabel("Profile Name:"))
        panel.add(self.profile_name_field)
        save_profile_button = JButton("Save")
        save_profile_button.addActionListener(SaveProfileAction(self))
        panel.add(save_profile_button)

        self.toggle_signing = JCheckBox("Enable Auto-Signing", actionPerformed=self.toggleSigning)
        self.signing_status = JLabel("Disabled", JLabel.CENTER)
        self.signing_status.setForeground(Color.RED)
        panel.add(self.toggle_signing)
        panel.add(JLabel(""))
        panel.add(self.signing_status)

        self.toggle_scope_only = JCheckBox("Sign Only In-Scope Traffic", actionPerformed=self.toggleScopeOnly)
        self.scope_status = JLabel("All Traffic", JLabel.CENTER)
        self.scope_status.setForeground(Color.BLUE)
        panel.add(self.toggle_scope_only)
        panel.add(JLabel(""))
        panel.add(self.scope_status)

        self.toggle_auto_extract = JCheckBox("Enable Auto-Extraction", actionPerformed=self.toggleAutoExtract)
        self.extract_status = JLabel("Disabled", JLabel.CENTER)
        self.extract_status.setForeground(Color.RED)
        panel.add(self.toggle_auto_extract)
        panel.add(JLabel(""))
        panel.add(self.extract_status)

        panel.add(JLabel("URL Filter (Regex):"))
        panel.add(self.url_filter_field)
        panel.add(JLabel("e.g., .*amazonaws.*"))

        self.last_signed_label = JLabel("Last Signed: Never")
        panel.add(JLabel("Status:"))
        panel.add(self.last_signed_label)
        panel.add(JLabel(""))

        return panel

    def createManualSignTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.add(JScrollPane(self.manual_request_area), BorderLayout.CENTER)
        sign_button = JButton("Generate Signature")
        sign_button.addActionListener(self.manualSignAction)
        panel.add(sign_button, BorderLayout.SOUTH)
        return panel

    def toggleSigning(self, event):
        self.signing_enabled = self.toggle_signing.isSelected()
        self.signing_status.setText("Enabled" if self.signing_enabled else "Disabled")
        self.signing_status.setForeground(Color.GREEN if self.signing_enabled else Color.RED)
        self.log("INFO", "Auto-Signing toggled to: {}".format(self.signing_enabled))

    def toggleScopeOnly(self, event):
        self.scope_only = self.toggle_scope_only.isSelected()
        self.scope_status.setText("In-Scope Only" if self.scope_only else "All Traffic")
        self.scope_status.setForeground(Color.GREEN if self.scope_only else Color.BLUE)
        self.log("INFO", "Scope-Only Signing toggled to: {}".format(self.scope_only))

    def toggleAutoExtract(self, event):
        self.auto_extract_enabled = self.toggle_auto_extract.isSelected()
        self.extract_status.setText("Enabled" if self.auto_extract_enabled else "Disabled")
        self.extract_status.setForeground(Color.GREEN if self.auto_extract_enabled else Color.RED)
        self.log("INFO", "Auto-Extraction toggled to: {}".format(self.auto_extract_enabled))

    def toggleLogging(self, event):
        self.logging_enabled = self.toggle_logging.isSelected()
        self.log("INFO", "Logging toggled to: {}".format(self.logging_enabled))

    def loadProfile(self, profile_name):
        if profile_name in self.profiles:
            profile = self.profiles[profile_name]
            self.access_key_field.setText(profile["access_key"])
            self.secret_key_field.setText(profile["secret_key"])
            self.region_field.setText(profile["region"])
            self.service_field.setText(profile["service"])
            self.auth_endpoint_field.setText(profile["auth_endpoint"])
            self.access_key_path_field.setText(profile["access_key_path"])
            self.secret_key_path_field.setText(profile["secret_key_path"])
            self.current_profile = profile_name
            self.log("INFO", "Loaded profile: {}".format(profile_name))

    def saveProfile(self, profile_name):
        if not profile_name:
            self.log("WARN", "Profile name cannot be empty")
            return
        self.profiles[profile_name] = {
            "access_key": self.access_key_field.getText(),
            "secret_key": self.secret_key_field.getText(),
            "region": self.region_field.getText(),
            "service": self.service_field.getText(),
            "auth_endpoint": self.auth_endpoint_field.getText(),
            "access_key_path": self.access_key_path_field.getText(),
            "secret_key_path": self.secret_key_path_field.getText()
        }
        self._callbacks.saveExtensionSetting("sigv4_profiles", json.dumps(self.profiles))
        if profile_name not in [self.profile_combo.getItemAt(i) for i in range(self.profile_combo.getItemCount())]:
            self.profile_combo.addItem(profile_name)
        self.current_profile = profile_name
        self.log("INFO", "Saved profile: {}".format(profile_name))

    def getTabCaption(self):
        return "AwSigV4Signer"

    def getUiComponent(self):
        return self._tab

    def createMenuItems(self, invocation):
        menu_list = []
        menu_item = JMenuItem("Sign Now!", actionPerformed=self.signNowAction(invocation))
        menu_list.append(menu_item)
        return menu_list

    def signNowAction(self, invocation):
        def action(event):
            self.signNow(invocation)
        return action

    def signNow(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            self.log("WARN", "No request selected for manual signing")
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
                    self.log("INFO", "Skipping out-of-scope URL: {}".format(url))
                    continue
                host = self.getHostFromHeaders(headers)
                new_headers, new_body = self.signRequest(headers, body, host, request_info.getMethod(), str(url.getPath()))
                new_request = self._helpers.buildHttpMessage(new_headers, new_body.encode())
                message.setRequest(new_request)
                self.log("INFO", "Manually signed request for {}".format(url))
                self.updateLastSigned()
            except Exception as e:
                self.log("ERROR", "Manual signing failed: {}".format(str(e)))

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
            except ValueError as e:
                self.log("ERROR", "Response parsing failed: {}".format(str(e)))
            return

        if not messageIsRequest or not self.signing_enabled:
            return

        if tool_name not in self.tool_settings or not self.tool_settings[tool_name]:
            self.log("DEBUG", "Skipping - Tool {} not enabled".format(tool_name))
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
                self.log("DEBUG", "URL {} does not match filter {}".format(url_str, self.url_filter))
                return
            headers = request_info.getHeaders()
            body = request[request_info.getBodyOffset():].tostring()
            host = self.getHostFromHeaders(headers)
            new_headers, new_body = self.signRequest(headers, body, host, request_info.getMethod(), str(url.getPath()))
            new_request = self._helpers.buildHttpMessage(new_headers, new_body.encode())
            messageInfo.setRequest(new_request)
            self.log("INFO", "Signed request for {} (Tool: {})".format(url, tool_name))
            self.updateLastSigned()
        except ValueError as e:
            self.log("ERROR", "Request parsing failed: {}".format(str(e)))

    def signRequest(self, headers, body, host, method, path):
        try:
            access_key = self.access_key_field.getText().strip()
            secret_key = self.secret_key_field.getText().strip()
            region = self.region_field.getText().strip()
            service = self.service_field.getText().strip()
            if not all([access_key, secret_key, region, service]):
                raise ValueError("Missing required fields: access_key, secret_key, region, or service")
            if access_key == "Enter AWS Access Key" or secret_key == "Enter AWS Secret Key":
                raise ValueError("Default placeholder credentials detected")

            sign_body = body or ""
            amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            date_stamp = amz_date[:8]
            content_sha256 = hashlib.sha256(sign_body.encode('utf-8')).hexdigest()

            canonical_headers = (
                "accept:application/json\n"
                "accept-language:*\n"
                "host:{}\n"
                "x-amz-content-sha256:{}\n"
                "x-amz-date:{}\n"
                "x-amz-user-agent:aws-sdk-js/2.1670.0\n".format(host, content_sha256, amz_date)
            )
            signed_headers = "accept;accept-language;host;x-amz-content-sha256;x-amz-date;x-amz-user-agent"
            canonical_request = "{}\n{}\n\n{}\n{}\n{}".format(
                method.upper(), path or "/", canonical_headers, signed_headers, content_sha256)
            canonical_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

            credential_scope = "{}/{}/{}/aws4_request".format(date_stamp, region, service)
            string_to_sign = "AWS4-HMAC-SHA256\n{}\n{}\n{}".format(amz_date, credential_scope, canonical_hash)

            k_date = hmac.new(("AWS4" + secret_key).encode('utf-8'), date_stamp.encode('utf-8'), hashlib.sha256).digest()
            k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
            k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
            k_signing = hmac.new(k_service, "aws4_request".encode('utf-8'), hashlib.sha256).digest()
            signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

            auth_header = "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
                access_key, credential_scope, signed_headers, signature)

            new_headers = list(headers)
            header_positions = {"X-Amz-Content-Sha256": None, "X-Amz-Date": None, "Authorization": None}
            for i, header in enumerate(new_headers):
                for key in header_positions:
                    if header.startswith(key):
                        header_positions[key] = i
                        break

            sigv4_headers = {
                "X-Amz-Content-Sha256": "X-Amz-Content-Sha256: {}".format(content_sha256),
                "X-Amz-Date": "X-Amz-Date: {}".format(amz_date),
                "Authorization": "Authorization: {}".format(auth_header)
            }
            for key, value in sigv4_headers.items():
                if header_positions[key] is not None:
                    new_headers[header_positions[key]] = value
                else:
                    new_headers.append(value)

            return new_headers, sign_body
        except ValueError as e:
            self.log("ERROR", "Validation failed: {}".format(str(e)))
            raise
        except UnicodeEncodeError as e:
            self.log("ERROR", "Encoding failed: {}".format(str(e)))
            raise

    def manualSignAction(self, event):
        try:
            request_text = self.manual_request_area.getText()
            if not request_text:
                self.log("WARN", "No request provided for manual signing")
                return
            request_bytes = self._helpers.stringToBytes(request_text)
            request_info = self._helpers.analyzeRequest(request_bytes)
            headers = request_info.getHeaders()
            body = request_bytes[request_info.getBodyOffset():].tostring()
            host = self.getHostFromHeaders(headers)
            new_headers, new_body = self.signRequest(headers, body, host, request_info.getMethod(), "/")
            signed_request = self._helpers.buildHttpMessage(new_headers, new_body.encode())
            self.manual_request_area.setText(self._helpers.bytesToString(signed_request))
            self.log("INFO", "Manual signature generated")
            self.updateLastSigned()
        except ValueError as e:
            self.log("ERROR", "Manual signing failed: {}".format(str(e)))

    def extractCredentials(self, response_body):
        self.log("INFO", "Extracting credentials")
        try:
            data = json.loads(response_body)
            access_key = self.getNestedValue(data, self.access_key_path_field.getText().split("."))
            secret_key = self.getNestedValue(data, self.secret_key_path_field.getText().split("."))
            if access_key and secret_key:
                self.access_key_field.setText(access_key)
                self.secret_key_field.setText(secret_key)
                self.log("INFO", "Extracted JSON creds: AccessKey={}, SecretKey={}".format(access_key, secret_key[:6] + "..."))
                return
        except json.JSONDecodeError as e:
            self.log("DEBUG", "JSON parsing failed: {}".format(str(e)))

        try:
            root = ET.fromstring(response_body)
            namespace = "{https://iam.amazonaws.com/doc/2010-05-08/}"
            credentials = root.find(".//{}Credentials".format(namespace))
            if credentials is not None:
                access_key = credentials.findtext("{}AccessKeyId".format(namespace))
                secret_key = credentials.findtext("{}SecretAccessKey".format(namespace))
                if access_key and secret_key:
                    self.access_key_field.setText(access_key)
                    self.secret_key_field.setText(secret_key)
                    self.log("INFO", "Extracted XML creds: AccessKey={}, SecretKey={}".format(access_key, secret_key[:6] + "..."))
        except ET.ParseError as e:
            self.log("DEBUG", "XML parsing failed: {}".format(str(e)))

    def getHostFromHeaders(self, headers):
        for header in headers:
            if header.lower().startswith("host:"):
                return header.split(":", 1)[1].strip()
        self.log("WARN", "Host header missing")
        return "unknown.host"

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
        prefix = "[{}] {}".format(level, time.strftime("%Y-%m-%d %H:%M:%S"))
        log_message = "{} - {}".format(prefix, message)
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
        self.last_signed_label.setText("Last Signed: {}".format(self.last_signed))

class SaveProfileAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    def actionPerformed(self, event):
        profile_name = self.extender.profile_name_field.getText()
        self.extender.saveProfile(profile_name)

class ProfileSelector(ItemListener):
    def __init__(self, extender):
        self.extender = extender
    def itemStateChanged(self, event):
        if event.getStateChange() == 1:  # SELECTED
            profile_name = event.getItem()
            self.extender.loadProfile(profile_name)
