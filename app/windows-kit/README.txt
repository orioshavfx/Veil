Veil for Windows — test build (app + system proxy + TUN)

What works: the Veil app (window + tray icon), subscriptions, all protocols
(VLESS/REALITY/Vision, VMess, Trojan, Shadowsocks, Hysteria2), Proxy mode with
the Windows system proxy, TUN mode, site and app rules.

Files: Veil.exe (the app), veil-cli.exe (command-line tool for the test script),
wintun.dll (TUN driver, needed for TUN mode), geo\ (site/IP lists).
Keep them together in one folder.

1. Unzip this folder anywhere (e.g. Documents\Veil).
2. Windows may block files downloaded from the internet. In PowerShell, in this folder:
       Get-ChildItem -Recurse | Unblock-File
   If SmartScreen warns: "More info" -> "Run anyway".

3. Automatic check (about a minute):
       powershell -ExecutionPolicy Bypass -File .\windows-test.ps1 -Subscription "https://your-subscription-url"

4. Check the app by hand:
   - Start Veil.exe. A window opens and a shield icon appears in the tray
     (it may be hidden under the ^ arrow next to the clock).
   - The servers from step 3 are already there (the app and the test share settings).
     Pick a server and press the power button.
   - Open https://api.ipify.org in Edge/Chrome: it should show the server's IP, not yours.
   - Settings -> Windows Settings -> Network & internet -> Proxy: "Use a proxy server" is on, 127.0.0.1.
   - Close the window with X: Veil keeps running in the tray. Left click on the
     tray icon opens the window, right click shows the menu.
   - Tray menu -> Quit Veil. The proxy setting in Windows Settings turns off again,
     and sites open normally without Veil.
   - Switch Windows between light and dark mode: the tray icon should stay visible.

5. TUN mode (all traffic, including apps that ignore the proxy):
   - wintun.dll must be next to Veil.exe, otherwise Veil says
     "wintun.dll not found next to Veil.exe".
   - Settings -> Mode -> TUN, then press the power button. Windows shows the
     UAC prompt; Veil restarts with administrator rights and connects by itself.
     If you decline the prompt, Veil stays as it was and shows
     "Administrator permission was declined".
   - Check https://api.ipify.org: it should show the server's IP. The system
     proxy stays off in TUN mode.
   - To undo everything: press the power button again or Quit Veil from the tray.
     If something went wrong, just close the app (the TUN adapter disappears with it).
     Next time you start Veil normally (no administrator) in Proxy mode.

6. Send back: veil-report.txt, %LOCALAPPDATA%\Veil\veil.log (paste that path
   into the Explorer address bar), and a note on anything that looked wrong.
