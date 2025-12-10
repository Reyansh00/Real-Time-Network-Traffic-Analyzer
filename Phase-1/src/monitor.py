import psutil
from typing import List, Dict, Optional
import socket


def get_process_info(pid: Optional[int]) -> Dict[str, str]:
    """
    Get process information for a given PID.
    
    Args:
        pid: Process ID (can be None for system/kernel processes)
        
    Returns:
        Dictionary with process name and executable path
    """
    # Handle system/kernel processes with no PID
    if pid is None:
        return {
            'name': 'System/Kernel',
            'exe': 'System/Kernel'
        }
    
    try:
        process = psutil.Process(pid)
        return {
            'name': process.name(),
            'exe': process.exe()
        }
    except psutil.NoSuchProcess:
        return {
            'name': 'Unknown (closed)',
            'exe': 'Process terminated'
        }
    except psutil.AccessDenied:
        return {
            'name': 'Access Denied',
            'exe': 'Access Denied'
        }
    except Exception as e:
        return {
            'name': f'Error: {str(e)}',
            'exe': 'Unknown'
        }


def get_active_connections() -> List[Dict]:
    """
    Get all active network connections with their process information.
    
    Returns:
        List of dictionaries containing connection and process details
    """
    connections = []
    
    # Check permissions first - fail fast if we don't have access
    try:
        net_connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Access denied! Run with sudo/admin privileges!")
        exit(1)
    except Exception as e:
        print(f"Error accessing network connections: {str(e)}")
        exit(1)
    
    for conn in net_connections:
        # Filter for established connections only
        if conn.status != 'ESTABLISHED':
            continue
        
        # Determine connection type
        conn_type = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
        
        # Extract local address info
        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        
        # Extract remote address info
        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        
        # Get process information (handles None PIDs and closed processes)
        process_info = get_process_info(conn.pid)
        
        # Build connection dictionary
        connection_data = {
            'local_address': local_addr,
            'remote_address': remote_addr,
            'pid': conn.pid if conn.pid is not None else 'N/A',
            'status': conn.status,
            'type': conn_type,
            'process_name': process_info['name'],
            'process_path': process_info['exe']
        }
        
        connections.append(connection_data)
    
    return connections


def display_connections(connections: List[Dict]) -> None:
    """
    Display connections in a formatted way.
    
    Args:
        connections: List of connection dictionaries
    """
    if not connections:
        print("No active connections found.")
        return
    
    print(f"\nFound {len(connections)} active connections:\n")
    print("-" * 120)
    
    for i, conn in enumerate(connections, 1):
        print(f"Connection #{i}")
        print(f"  Type:           {conn['type']}")
        print(f"  Status:         {conn['status']}")
        print(f"  Local:          {conn['local_address']}")
        print(f"  Remote:         {conn['remote_address']}")
        print(f"  PID:            {conn['pid']}")
        print(f"  Process:        {conn['process_name']}")
        print(f"  Path:           {conn['process_path']}")
        print("-" * 120)


if __name__ == "__main__":
    print("Scanning for active network connections...")
    active_conns = get_active_connections()
    display_connections(active_conns)