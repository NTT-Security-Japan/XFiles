from chardet import detect
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography.x509 import load_der_x509_crl
from cryptography.x509 import load_pem_x509_certificates
from urllib.request import pathname2url
import json
import lxml.etree as ET
import os
import shutil
import tempfile
import zipfile


class XFiles:
    def __init__(self, path):
        if not os.path.exists(path):
            print("File Not Found.")
            exit()
            raise FileNotFoundError
        if not zipfile.is_zipfile(path):
            print("File is invalid or corrupted.")
            exit()
            raise zipfile.BadZipFile
        self._appx = zipfile.ZipFile(path)
        self.files = self._appx.namelist()
        self.publisherDisplayName = None
        self.displayName = None
        self.capabilities = None
        self.restricted_capabilities = None
        if not "config.json" in self.files:
            self._type="MSIX"
        else:
            self._type="MSIX(PSF)"
            with tempfile.TemporaryDirectory() as td:
                self._appx.extract("config.json", td)
                with open(os.path.join(td, "config.json")) as f:
                    self._msix_config = json.load(f)
        if "AppxManifest.xml" not in self.files:
            print("File is not valid AppX / MSIX File.")
            exit()
        with tempfile.TemporaryDirectory() as td:
            self._appx.extract("AppxManifest.xml", td)
            root=ET.parse(os.path.join(td, "AppxManifest.xml")).getroot()
            self._manifest = root
            props = root.find("Properties", root.nsmap)
            if len(props):
                self.publisherDisplayName = props.find("PublisherDisplayName", root.nsmap).text
                self.displayName = props.find("DisplayName", root.nsmap).text
            cap = root.find("Capabilities", root.nsmap)
            if len(cap):
                self.capabilities = [c.attrib.get("Name") for c in cap.findall("Capability", root.nsmap)]
                self.restricted_capabilities = [c.attrib.get("Name") for c in cap.findall("rescap:Capability", root.nsmap)]

            
    def __str__(self):
        return f"DisplayName : {self.displayName} / PublisherDisplayName : {self.publisherDisplayName}"


    def get_type(self):
        return self._type


    def get_manifest(self):
        return xml.dom.minidom.parseString(ET.tostring(self._manifest)).toprettyxml()


    def _check_msix(self):
        return self._type=="MSIX(PSF)" and bool(self._msix_config)
        # assert self._type=="MSIX", "May not MSIX Files"
        # assert self._msix_config, "Failed to extract msix configs"


    def get_psf_config(self):
        return self._msix_config


    def signature(self):
        cert = None
        with tempfile.TemporaryDirectory() as td:
            self._appx.extract("AppxSignature.p7x", td)
            with open(os.path.join(td,"AppxSignature.p7x"), mode="rb") as fb:
                cert=load_der_pkcs7_certificates(fb.read()[4:])
        return cert


    def detect_ps1s(self):
        return [f for f in self.files if f.lower().endswith(".ps1")]


    def get_all_scripts(self):
        scripts=[]
        ps1s = [f for f in self.files if f.lower().endswith(".ps1")]
        for ps1 in ps1s:
            with tempfile.TemporaryDirectory() as td:
                self._appx.extract(ps1, td)
                with open(os.path.join(td, ps1), mode="rb") as b:
                    enc = detect(b.read()) 
                with open(os.path.join(td, ps1), encoding=enc['encoding']) as f:
                    scripts.append(dict(path=ps1, script=f.read()))
        return scripts


    def get_psf_script(self):
        if not self._check_msix():
            return {}
        ss=None
        for app in self._msix_config["applications"]:
            if "startScript" in app.keys():
                ss = app["startScript"]
        if ss and "scriptPath" in ss.keys():
            with tempfile.TemporaryDirectory() as td:
                self._appx.extract(pathname2url(ss["scriptPath"]), td)
                with open(os.path.join(td, ps1), mode="rb") as b:
                    enc = detect(b.read()) 
                with open(os.path.join(td, ps1), encoding=enc['encoding']) as f:
                    return dict(path=pathname2url(ss["scriptPath"]), script=f.read())


    def get_vfs_path(self):
        return [f for f in self.files if "VFS" in f]
