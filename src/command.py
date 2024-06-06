from cryptography.hazmat.primitives.serialization import Encoding
import argparse
import json
import os
import xfiles

welcome = """
\033[34m
██╗░░██╗███████╗██╗██╗░░░░░███████╗░██████╗
╚██╗██╔╝██╔════╝██║██║░░░░░██╔════╝██╔════╝
░╚███╔╝░█████╗░░██║██║░░░░░█████╗░░╚█████╗░
░██╔██╗░██╔══╝░░██║██║░░░░░██╔══╝░░░╚═══██╗
██╔╝╚██╗██║░░░░░██║███████╗███████╗██████╔╝
╚═╝░░╚═╝╚═╝░░░░░╚═╝╚══════╝╚══════╝╚═════╝░
\033[0m
"""

def main():
    args = config_args()    
    xf=xfiles.XFiles(args.file_path)
    if not args.silent:
        print(welcome)
        analytics(args, xf)
    if args.extract_certs:
        extract_certs(args, xf)
    if args.extract_ps1s:
        extract_ps1s(args, xf)


def config_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('file_path', help='file path of MSIX/APPX')
    arg_parser.add_argument('--extract-certs', help="extract certifications", action='store_true')
    arg_parser.add_argument('--extract-ps1s', help="extract ps1 scripts", action='store_true')
    arg_parser.add_argument('--silent', help="silent mode", action='store_true')
    args = arg_parser.parse_args()
    return args


def extract_certs(args, xf):
    dir_name = os.path.splitext(os.path.basename(args.file_path))[0]
    dir_name += "_certs"
    os.makedirs(dir_name, exist_ok=True)
    for i, cert in enumerate(xf.signature()):
        pem_data = cert.public_bytes(Encoding.PEM)
        with open(os.path.join(dir_name,f'certificate_{i}.pem'), 'wb') as pem_file:
            pem_file.write(pem_data)


def extract_ps1s(args, xf):
    dir_name = os.path.splitext(os.path.basename(args.file_path))[0]
    dir_name += "_ps1s"
    os.makedirs(dir_name, exist_ok=True)
    for ps1 in xf.get_all_scripts():
        with open(os.path.join(dir_name,ps1["path"]), 'w') as ps1_file:
            ps1_file.write(ps1["script"])


def analytics(args, xf):
    print(f"💡 💾 Loaded : {args.file_path}")

    if xf._type=="MSIX":
        print(f"\n💡 💻 MSIX / APPX : " + str(xf))
    else:
        print(f"\n🚨 💻 MSIX (PSF Detected!!) : " + str(xf))
    
    ai = bool([f for f in xf.files if ("AI_STUBS" in f) or ("AiStubX64.exe" in f)])
    if ai:
        print(f"\n🚨 💻 Advanced Installer Detected !!")

    print("\n💡 ✅ Extracted Capabilities:")
    for cap in xf.capabilities:
        print(f"-- : {cap}")
    for cap in xf.restricted_capabilities:
        print(f"-- : {cap}")

    print("\n💡 💳 Extracted Certificates:")
    for sig in xf.signature():
        print(f"-- : {sig}")
    vfs = xf.get_vfs_path()

    if vfs:
        print(f"\n🚨 💽 {len(vfs)} VFS files Detected!!")
        for vf in range(min(10, len(vfs))):
            print(f"-- : 📁{vfs[vf]}")
        if len(vfs)>10:
            print(f"-- : 📁...")

    if xf.detect_ps1s():
        ps1s = xf.detect_ps1s()
        print(f"\n🚨 📝 {len(ps1s)} PS1 Scripts Detected!!")
        for ps1 in range(min(10, len(ps1s))):
            print(f"-- : 📝{ps1s[ps1]}")
        if len(vfs)>10:
            print(f"-- : 📝...")

    if xf._type!="MSIX":
        psf_conf = xf.get_psf_config()
        if psf_conf:
            print(f"\n🚨 📃 PSF Options Detected!!:")
            print("■□■□■□■□■□■□■□■□■□■□■□■□■□■□■□■□■□")
            print(json.dumps(psf_conf, indent=4))
            print("■□■□■□■□■□■□■□■□■□■□■□■□■□■□■□■□■□")
            if "applications" in psf_conf.keys():
                for psf_app in psf_conf["applications"]:
                    if "startScript" in psf_app.keys():
                        print(f"\n🚨 📝 PSF startScript Detected on APP ID {psf_app['id']}!!")
                        print(f"-- : 📝 {psf_app['startScript']['scriptPath']}")
                    if "endScript" in psf_app.keys():
                        print(f"\n🚨 📝 PSF endScript Detected on APP ID {psf_app['id']}!!")
                        print(f"-- : 📝 {psf_app['endScript']['scriptPath']}")


if __name__ == '__main__':
    main()
