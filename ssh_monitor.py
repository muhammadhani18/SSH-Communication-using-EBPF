#!/usr/bin/env python3

from bcc import BPF  
from datetime import datetime  
import pwd  
import signal  
import sys  
from collections import defaultdict  
import time  


bpf_text = """
#include <uapi/linux/ptrace.h>  // Provides definitions for tracing
#include <linux/sched.h>        // Access to task_struct
#include <linux/fs.h>           // File system-related structures
#include <linux/nsproxy.h>      // Namespace-related structures

// Define a data structure to hold process information
struct data_t {
    u32 pid;                   // Process ID
    u32 ppid;                  // Parent Process ID
    u32 uid;                   // User ID
    char comm[TASK_COMM_LEN];  // Process name
    char cmd[256];             // Command executed (if applicable)
    u64 timestamp;             // Event timestamp
    u8 is_ssh;                 // Flag for SSH-related activity (1 for SSH, 2 for command)
};

// Define eBPF maps:
// pidmap: Tracks PIDs associated with SSH sessions
BPF_HASH(pidmap, u32, u8);  
// events: Outputs data to user space
BPF_PERF_OUTPUT(events);

// Hook to monitor process execution (execve syscall)
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};  // Initialize the data structure
    u64 pid_tgid = bpf_get_current_pid_tgid();  // Get PID and TGID
    data.pid = pid_tgid >> 32;  // Extract the PID
    data.timestamp = bpf_ktime_get_ns();  // Get the event timestamp (nanoseconds)
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  // Get the user ID
    
    // Get parent PID from task_struct
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;  // Get the TGID of the parent task
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));  // Get the process name
    
    // Detect if the process is `ssh`
    if (data.comm[0] == 's' && data.comm[1] == 's' && data.comm[2] == 'h') {
        data.is_ssh = 1;  // Mark as SSH process
        u8 val = 1;
        pidmap.update(&data.pid, &val);  // Add PID to pidmap
    }
    
    // Check if the parent process belongs to an SSH session
    u8 *is_ssh_parent = pidmap.lookup(&data.ppid);
    if (is_ssh_parent != NULL) {  // Parent is an SSH session
        u8 val = 1;
        pidmap.update(&data.pid, &val);  // Mark current process as SSH-related
        data.is_ssh = 2;  // This is a command executed within an SSH session
        
        // Read the command being executed
        bpf_probe_read_str(&data.cmd, sizeof(data.cmd), (void *)args->filename);
    }
    
    // Send the collected data to user space
    events.perf_submit(args, &data, sizeof(data));
    return 0;  // Exit the probe
}

// Hook to monitor process exit
int trace_exit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;  // Get the PID
    pidmap.delete(&pid);  // Remove the PID from pidmap
    return 0;
}
"""

# Initialize the BPF program
b = BPF(text=bpf_text)

# Attach the `trace_exit` function to the `exit_group` syscall
b.attach_kprobe(event=b.get_syscall_fnname("exit_group"), fn_name="trace_exit")

# Dictionary to store active SSH sessions
ssh_sessions = defaultdict(dict)

# Store the start times for aligning timestamps
start_real_time = time.time()  # Real-world time
start_monotonic_time = time.monotonic()  # Kernel monotonic time

def process_cmdline(cmd_bytes):
    """Convert raw command-line bytes into a readable string."""
    try:
        # Split by null bytes and filter non-empty strings
        parts = cmd_bytes.decode('utf-8', 'replace').split('\x00')
        cmd_parts = [p for p in parts if p.strip()]
        return ' '.join(cmd_parts) if cmd_parts else ''
    except:
        return cmd_bytes.decode('utf-8', 'replace').strip()

def print_event(cpu, data, size):
    """Process and display events received from the BPF program."""
    event = b["events"].event(data)  # Read the event data
    try:
        username = pwd.getpwuid(event.uid).pw_name  # Resolve user ID to username
    except KeyError:
        username = str(event.uid)  # Default to UID if username is not found
    
    # Calculate and format the event timestamp
    monotonic_event_time = event.timestamp / 1e9  # Convert nanoseconds to seconds
    real_event_time = start_real_time + (monotonic_event_time - start_monotonic_time)
    timestamp = datetime.fromtimestamp(real_event_time).strftime("%Y-%m-%d %H:%M:%S")
    
    process_name = event.comm.decode('utf-8', 'replace')  # Decode process name
    
    if event.is_ssh == 1:  # SSH connection detected
        print(f"\n{timestamp} - SSH CONNECTION - User: {username} (UID: {event.uid}) Process: {process_name} PID: {event.pid}")
        # Store session details
        ssh_sessions[event.pid] = {
            'username': username,
            'uid': event.uid,
            'start_time': timestamp
        }
    elif event.is_ssh == 2:  # Command executed in SSH session
        cmd = process_cmdline(event.cmd)
        if cmd and not cmd.startswith('/bin/bash') and not cmd == '-bash':  # Ignore shell prompts
            session_info = ssh_sessions.get(event.ppid, {})  # Get parent SSH session info
            session_user = session_info.get('username', username)
            session_uid = session_info.get('uid', event.uid)
            print(f"{timestamp} - COMMAND - User: {session_user} (UID: {session_uid}) Command: {cmd}")

def signal_handler(signal, frame):
    """Handle Ctrl+C to clean up resources."""
    print("\nDetaching probes and exiting...")
    b.cleanup()  # Detach BPF probes
    sys.exit(0)  # Exit the program

def print_header():
    """Print program header."""
    print("\nSSH Activity Monitor with Command Tracking")
    print("=========================================")
    print("Monitoring SSH connections and commands...")
    print("Press Ctrl+C to exit\n")

# Entry point of the script
if __name__ == '__main__':
    print_header()  # Display the header
    
    # Handle SIGINT (Ctrl+C) to exit gracefully
    signal.signal(signal.SIGINT, signal_handler)
    
    # Open the perf buffer and process events in a loop
    b["events"].open_perf_buffer(print_event)
    
    while True:
        try:
            b.perf_buffer_poll()  # Poll for events
        except KeyboardInterrupt:  # Handle Ctrl+C
            signal_handler(signal.SIGINT, None)
