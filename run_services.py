import subprocess
import time
import atexit
import sys
import os

# List of services to run. The key is a name for the service,
# and the value is the command to run it.
services = {
    "API Gateway": [os.path.join("api-gateway", "app.py")],
    "Users Service": [os.path.join("users-service", "app.py")],
    "Products Service": [os.path.join("products-service", "app.py")],
    "Admin Service": [os.path.join("admin-service", "app.py")],
    "Reports Service": [os.path.join("reports-service", "app.py")],
}

processes = []

def cleanup():
    """
    This function is registered to run at exit.
    It ensures all subprocesses are terminated.
    """
    print("\nTüm servisler kapatılıyor...")
    for p in processes:
        if p.poll() is None:  # Check if process is still running
            p.terminate() # or p.kill()
    print("Tüm servisler durduruldu.")

# Register the cleanup function to be called on script exit
atexit.register(cleanup)

try:
    print("Tüm servisler başlatılıyor...")
    for name, command in services.items():
        # Use sys.executable to be sure to use the same python interpreter.
        cmd = [sys.executable] + command
        
        # We will pipe the output to the main console to see logs from all services.
        process = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        
        processes.append(process)
        print(f"- {name} başlatıldı (PID: {process.pid})")
        # Give a little time for the service to start up
        time.sleep(1)

    print("\nTüm servisler çalışıyor. Durdurmak için Ctrl+C tuşlarına basın.")
    
    # Keep the main script alive until it's interrupted
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    # The cleanup function will be called automatically via atexit
    sys.exit(0) 