import subprocess
import os
import signal

def is_argus_server_running():
    output = subprocess.check_output(['ps', 'aux'], text=True)
    for line in output.splitlines():
        if 'argus' in line and 'grep' not in line:
            pid = int(line.split()[1])
            return True, pid
    return False, -1


def start_argus(
    path_to_argus: str = '/usr/local/sbin/argus',
    interface: str = 'ens33',
    server_port: int = 561
):
    is_running, pid = is_argus_server_running()
    if is_running:
        return False, pid
    
    cmd = [path_to_argus, '-i', interface, '-P', f'{server_port}', '-d']
    process = subprocess.Popen(cmd)
    
    return True, process


def kill_argus(argus_process = None):
    if argus_process and argus_process.poll() is None:
        os.kill(argus_process.pid, signal.SIGKILL)
        return
    
    is_running, pid = is_argus_server_running()
    if is_running:
        os.kill(pid, signal.SIGKILL)
