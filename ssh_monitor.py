#!/usr/bin/env python3
from bcc import BPF
from datetime import datetime
import pwd
import signal
import sys
from collections import defaultdict
import time

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>

// Data structure to store process information
struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char cmd[256];
    u64 timestamp;
    u8 is_ssh;
};

BPF_HASH(pidmap, u32, u8);  // Track SSH session PIDs
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.timestamp = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Get parent PID
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Check if this is an SSH-related process
    if (data.comm[0] == 's' && data.comm[1] == 's' && data.comm[2] == 'h') {
        data.is_ssh = 1;
        u8 val = 1;
        pidmap.update(&data.pid, &val);
    }
    
    // Check if parent is an SSH session
    u8 *is_ssh_parent = pidmap.lookup(&data.ppid);
    if (is_ssh_parent != NULL) {
        u8 val = 1;
        pidmap.update(&data.pid, &val);
        data.is_ssh = 2;  // Command from SSH session
        
        // Read command from args
        bpf_probe_read_str(&data.cmd, sizeof(data.cmd), (void *)args->filename);
    }
    
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

int trace_exit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    pidmap.delete(&pid);
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)

# Attach kprobe for exit
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="trace_exit")

# Store SSH sessions
ssh_sessions = defaultdict(dict)

# Initialize base time
start_real_time = time.time()
start_monotonic_time = time.monotonic()

def process_cmdline(cmd_bytes):
    """Process the command line bytes into a readable string."""
    try:
        # Split on null bytes and take all parts to reconstruct full command
        parts = cmd_bytes.decode('utf-8', 'replace').split('\x00')
        # Filter out empty strings and join with spaces
        cmd_parts = [p for p in parts if p.strip()]
        return ' '.join(cmd_parts) if cmd_parts else ''
    except:
        return cmd_bytes.decode('utf-8', 'replace').strip()

def print_event(cpu, data, size):
    event = b["events"].event(data)
    try:
        username = pwd.getpwuid(event.uid).pw_name
    except KeyError:
        username = str(event.uid)
    
    # Calculate corrected timestamp
    monotonic_event_time = event.timestamp / 1e9
    real_event_time = start_real_time + (monotonic_event_time - start_monotonic_time)
    timestamp = datetime.fromtimestamp(real_event_time).strftime("%Y-%m-%d %H:%M:%S")
    
    process_name = event.comm.decode('utf-8', 'replace')
    
    if event.is_ssh == 1:  # SSH connection
        print(f"\n{timestamp} - SSH CONNECTION - User: {username} (UID: {event.uid}) Process: {process_name} PID: {event.pid}")
        ssh_sessions[event.pid] = {
            'username': username,
            'uid': event.uid,
            'start_time': timestamp
        }
    elif event.is_ssh == 2:  # Command execution in SSH session
        cmd = process_cmdline(event.cmd)
        if cmd and not cmd.startswith('/bin/bash') and not cmd == '-bash':
            session_info = ssh_sessions.get(event.ppid, {})
            session_user = session_info.get('username', username)
            session_uid = session_info.get('uid', event.uid)
            print(f"{timestamp} - COMMAND - User: {session_user} (UID: {session_uid}) Command: {cmd}")
            
def signal_handler(signal, frame):
    print("\nDetaching probes and exiting...")
    b.cleanup()
    sys.exit(0)

def print_header():
    print("\nSSH Activity Monitor with Command Tracking")
    print("=========================================")
    print("Monitoring SSH connections and commands...")
    print("Press Ctrl+C to exit\n")

if __name__ == '__main__':
    print_header()
    
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, signal_handler)
    
    # Loop with callback
    b["events"].open_perf_buffer(print_event)
    
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)