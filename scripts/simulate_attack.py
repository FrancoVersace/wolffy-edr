#!/usr/bin/env python3
"""Genera actividad inocua que debe disparar reglas de Wolffy EDR."""
import os, subprocess, sys, tempfile, time, base64

IS_WINDOWS = os.name == "nt"

def step(text):
    print(f"\n[sim] {text}", flush=True)

def run_cmd(cmd):
    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"      -> omitido, comando no encontrado: {cmd[0]}")

def main():
    print("Iniciando simulacion de ataques. Por favor revisa el dashboard de Wolffy en 10-15 segundos.")
    
    # Pruebas Cross-Platform (SQLi)
    step("WLF-2001: Ejecucion de herramienta SQL injection (falso sqlmap)")
    if IS_WINDOWS:
        run_cmd(["powershell", "-c", "New-Item -ItemType File -Path $env:TEMP\\sqlmap.exe -Force; Start-Process -FilePath $env:TEMP\\sqlmap.exe -NoNewWindow; Start-Sleep 2"])
    else:
        run_cmd(["sh", "-c", "cp /bin/ls /tmp/sqlmap && /tmp/sqlmap; sleep 2"])
        
    step("WLF-2002: Script con patrones SQL injection")
    run_cmd([sys.executable, "-c", "import time; print('UNION SELECT 1,2,3'); time.sleep(2)"])

    if IS_WINDOWS:
        step("WLF-1101: PowerShell con comando codificado")
        enc = base64.b64encode('Write-Host "Wolffy Test"; Start-Sleep 2'.encode('utf-16-le')).decode('utf-8')
        run_cmd(["powershell", "-EncodedCommand", enc])

        step("WLF-1104: Ejecucion sospechosa via mshta")
        # mshta se queda abierto hasta que se cierra el alert, le daremos un timeout
        subprocess.Popen(["mshta", "javascript:setTimeout(function(){close();}, 2000);"])
        time.sleep(1)

        step("WLF-1106: Intento de deshabilitar Windows Defender")
        run_cmd(["powershell", "-c", "Write-Host 'Set-MpPreference -DisableRealtimeMonitoring test'; Start-Sleep 2"])

        step("WLF-3010: Intento de agregar usuario a Administradores")
        run_cmd(["cmd", "/c", "net localgroup Administrators fakeuser /add & ping -n 3 127.0.0.1 >nul"])

        step("WLF-3009: Intento de borrar logs (wevtutil)")
        run_cmd(["cmd", "/c", "wevtutil cl System & ping -n 3 127.0.0.1 >nul"])

    else:
        step("WLF-1021: Uso sospechoso de sudo")
        run_cmd(["sudo", "-i", "ls"])

        step("WLF-3012: Creacion de archivo oculto en directorio del sistema")
        run_cmd(["touch", "/tmp/.hidden_wolffy_test"])

    step("WLF-1010/1011: Simulacion de ransomware")
    workdir = tempfile.mkdtemp(prefix="wolffy_sim_")
    try:
        for i in range(5):
            with open(os.path.join(workdir, f"doc_{i}.txt.locked"), "w") as f:
                f.write("x")
        with open(os.path.join(workdir, "HOW_TO_DECRYPT_FILES.txt"), "w") as f:
            f.write("test")
        time.sleep(2)
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n[sim] Listo. Las alertas deberian aparecer pronto.")

if __name__ == "__main__":
    main()
