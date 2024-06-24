import winreg
import subprocess
import platform
import psutil
import os.path
import time
from usbpast import PastUSB

# This is a program that allows creating Log files of the system in txt files.
# The code can be modified to suit your architecture or distribution, by default
# it is for Windows but can easily be adapted for Linux or Mac depending on the use for this tool,
# I am not responsible for the malicious use that its use may cause, I only provide the forensic tool for computer analysis
# However, it's not a super tool either.
# @author: Rawier

# Function to view installed programs.
def get_installed_programs():
    installed_programs = []
    uninstall_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    for i in range(0, winreg.QueryInfoKey(uninstall_key)[0]):
        try:
            keyname = winreg.EnumKey(uninstall_key, i)
            subkey = winreg.OpenKey(uninstall_key, keyname)
            value = winreg.QueryValueEx(subkey, "DisplayName")[0]
            installed_programs.append(value)
            winreg.CloseKey(subkey)
        except WindowsError:
            pass
    winreg.CloseKey(uninstall_key)
    return installed_programs

# Function to view running processes.
def get_running_processes():
    processes = []
    for process in psutil.process_iter():
        try:
            process_name = process.name()
            processes.append(process_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

# Function to view running services.
def get_running_services():
    services = []
    for service in psutil.win_service_iter():
        try:
            if service.status() == "running":
                services.append(service.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return services

# Function to display DNS cache.
def get_dns_cache():
    dns_cache = subprocess.check_output(["ipconfig", "/displaydns"]).decode("ISO-8859-1")
    return dns_cache

# Function to display system information.
def get_system_info():
    system_info = f"Operating System: {platform.system()} {platform.release()} {platform.version()}\n"
    system_info += f"Architecture: {platform.machine()}\n"
    system_info += f"Processor: {platform.processor()}\n"
    system_info += f"Available RAM: {psutil.virtual_memory().available / (1024 ** 3):.2f} GB\n"
    system_info += f"CPU Usage: {psutil.cpu_percent()}%\n"
    system_info += f"Architecture: {platform.architecture()}%\n"
    return system_info

# Function to display Host file.
def get_host_content():
    host_content = subprocess.check_output(["findstr", "/V", "#", r"C:\Windows\System32\drivers\etc\hosts"]).decode(
        "utf-8")
    return host_content

# Function to display active NetBios connections.
def get_netbios_established():
    connections = psutil.net_connections(kind="udp")
    netbios_established = [conn for conn in connections if conn.status == "ESTABLISHED" and "netbios" in conn.laddr]
    netbios_established_str = "\n".join([f"{conn.laddr[0]}:{conn.laddr[1]} -> {conn.raddr[0]}:{conn.raddr[1]}" for conn in netbios_established])
    return netbios_established_str

# Function to display ARP cache.
def get_arp_cache():
    arp_cache = subprocess.check_output(["arp", "-a"], encoding="latin-1")
    return arp_cache

# 𝕽♛
# Function to display active processes.
def get_scheduled_tasks():
    scheduled_tasks = subprocess.check_output(["schtasks.exe", "/query", "/fo", "LIST"], encoding="cp1252")
    return scheduled_tasks

# Function to display active connections.
def get_active_connections():
    active_connections = subprocess.check_output(["netstat", "-ano"]).decode("latin-1")
    return active_connections

# Function to display disk usage info.
def get_disk_info():
    disk_path = os.path.abspath("C:\\")
    created_time = time.ctime(os.path.getctime(disk_path))
    modified_time = time.ctime(os.path.getmtime(disk_path))
    accessed_time = time.ctime(os.path.getatime(disk_path))
    return f"Disk Creation Time: {created_time}\nDisk Modification Time: {modified_time}\nLast Disk Access: {accessed_time}"

# Function to display network and WIFI information.
def get_network_info():
    network_info = ""
    # Get network information
    if_addrs = psutil.net_if_addrs()
    for interface_name, interface_addresses in if_addrs.items():
        network_info += f"Interface: {interface_name}\n"
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                network_info += f"  IPv4 Address: {address.address}\n"
                network_info += f"  IPv4 Netmask: {address.netmask}\n"
            elif str(address.family) == 'AddressFamily.AF_INET6':
                network_info += f"  IPv6 Address: {address.address}\n"
                network_info += f"  IPv6 Netmask: {address.netmask}\n"

    # Get WIFI information
    wifi_info = psutil.net_io_counters(pernic=True)
    if 'Wi-Fi' in wifi_info:
        network_info += "Wi-Fi Information:\n"
        network_info += f"  Bytes Received: {wifi_info['Wi-Fi'].bytes_recv}\n"
        network_info += f"  Bytes Sent: {wifi_info['Wi-Fi'].bytes_sent}\n"
    return network_info

# Function to display mapped drives.
def view_drives():
    drives = os.popen("wmic logicaldisk get caption").read()
    print(drives)
    with open("drives.txt", "w") as f:
        f.write(drives)
    print("File exported as 'drives.txt'")

# Function to create all txt files into one.
def create_all_scan():
    with open("processes.txt", "r") as f:
        processes = f.read()
    with open("programs.txt", "r") as f:
        programs = f.read()
    with open("services.txt", "r") as f:
        services = f.read()
    with open("cache_dns.txt", "r") as f:
        cache_dns = f.read()
    with open("system_info.txt", "r") as f:
        system_info = f.read()
    with open("host.txt", "r") as f:
        host = f.read()
    with open("netbios_establish.txt", "r") as f:
        netbios_establish = f.read()
    with open("arp.txt", "r") as f:
        arp = f.read()
    with open("scheduled_tasks.txt", "r") as f:
        scheduled_tasks = f.read()
   

    with open("active_connections.txt", "r") as f:
        active_connections = f.read()
    with open("disk_info.txt", "r") as f:
        disk_info = f.read()
    with open("network_info.txt", "r") as f:
        network_info = f.read()
    with open("drives.txt", "r") as f:
        drives = f.read()

    # Create an "all_scan.txt" file and write all gathered information
    with open("all_scan.txt", "w") as f:
        f.write("PROCESS INFORMATION:\n\n" + processes + "\n")
        f.write("PROGRAM INFORMATION:\n\n" + programs + "\n")
        f.write("SERVICE INFORMATION:\n\n" + services + "\n")
        f.write("DNS CACHE INFORMATION:\n\n" + cache_dns + "\n")
        f.write("SYSTEM INFORMATION:\n\n" + system_info + "\n")
        f.write("HOST INFORMATION:\n\n" + host + "\n")
        f.write("NETBIOS ESTABLISHED CONNECTIONS INFORMATION:\n\n" + netbios_establish + "\n")
        f.write("ARP CACHE INFORMATION:\n\n" + arp + "\n")
        f.write("SCHEDULED TASKS INFORMATION:\n\n" + scheduled_tasks + "\n")
        f.write("ACTIVE CONNECTIONS OR OPEN PORTS INFORMATION:\n\n" + active_connections + "\n")
        f.write("DISK ROOT CREATION, MODIFICATION, AND LAST ACCESS INFORMATION:\n\n" + disk_info + "\n")
        f.write("NETWORK AND WIFI INFORMATION:\n\n" + network_info + "\n")
        f.write("MAPPED DRIVES INFORMATION:\n\n" + drives + "\n")

    print("File exported as 'all_scan.txt'")

while True:
    ascii_message = ".s5SSSs.                .s                            \n      SS. s.  .s5SSSs.            .s5SSSs.  .s5SSSs.  \n sS    `:; SS.       SS. sS              SS.       SS. \n SS        S%S sS    `:; SS        sS    S%S sS    `:; \n`:;;;;.   S%S `:;;;;.   SS        SS    S%S SS        \n      ;;. S%S       ;;. SS        SS    S%S SS        \n      `:; `:;       `:; SS        SS    `:; SS   ``:; \n.,;   ;,. ;,. .,;   ;,. SS    ;,. SS    ;,. SS    ;,. \n`:;;;;;:' ;:' `:;;;;;:' `:;;;;;:' `:;;;;;:' `:;;;;;:'"
    print(ascii_message)
    print("Created by DINAKAR S & GOKKULAMOORTHY S R")
    print("Welcome, what would you like to do?")
    print(" ")
    print("1. View installed programs")
    print("2. View running processes")
    print("3. View running services")
    print("4. View DNS cache")
    print("5. View ARP cache")
    print("6. View system information")
    print("7. View Host file")
    print("8. View established NetBios connections")
    print("9. View scheduled tasks")
    print("10. View active connections or open ports")
    print("11. View root disk creation, modification, and last access")
    print("12. View network and WIFI information")
    print("13. View mapped drives")
    print("14. Create all")
    print("15. USB Past Information")
    print("16. Exit")
    choice = input("Enter the number of your choice: ")

    if choice == "1":
        # Show installed programs and save them to a text file
        programs = get_installed_programs()
        with open("programs.txt", "w") as f:
            for program in programs:
                f.write(program + "\n")
        print(f"{len(programs)} programs installed. Program names have been saved in the file programs.txt.")

    elif choice == "2":
        # Show running processes and save them to a text file
        processes = get_running_processes()
        with open("processes.txt", "w") as f:
            for process in processes:
                f.write(process + "\n")
        print(f"{len(processes)} running processes. Process names have been saved in the file processes.txt.")

    elif choice == "3":
        # Show running services and save them to a text file
        services = get_running_services()
        with open("services.txt", "w") as f:
            for service in services:
                f.write(service + "\n")
        print(f"{len(services)} running services. Service names have been saved in the file services.txt.")

    elif choice == "4":
        # Show DNS cache and save it to a text file
        dns_cache = get_dns_cache()
        with open("cache_dns.txt", "w") as f:
            f.write(dns_cache)
        print("DNS cache has been saved in the file cache_dns.txt.")

    elif choice == "5":
        # Show ARP cache and save it to a text file
        arp_cache = get_arp_cache()
        with open("arp.txt", "w") as f:
            f.write(arp_cache)
        print("ARP cache has been saved in the file arp.txt.")

    elif choice == "6":
        # Show system information and save it to a text file
        system_info = get_system_info()
        with open("system_info.txt", "w") as f:
            f.write(system_info)
        print("System information has been saved in the file system_info.txt.")

    elif choice == "7":
        # Show Host file content and save it to a text file
        host_content = get_host_content()
        with open("host.txt", "w") as f:
            f.write(host_content)
        print("Host file content has been saved in the file host.txt.")

    elif choice == "8":
        # Show established NetBios connections and save them to a text file
        netbios_established = get_netbios_established()
        with open("netbios_establish.txt", "w") as f:
            f.write(netbios_established)
        print("Established NetBios connections have been saved in the file netbios_establish.txt.")

    elif choice == "9":
        # Show scheduled tasks and save them to a text file
        scheduled_tasks = get_scheduled_tasks()
        with open("scheduled_tasks.txt", "w") as f:
            f.write(scheduled_tasks)
        print("Scheduled tasks have been saved in the file scheduled_tasks.txt.")

    elif choice == "10":
        # Show active connections or open ports and save them to a text file
        active_connections = get_active_connections()
        with open("active_connections.txt", "w") as f:
            f.write(active_connections)
        print("Active connections or open ports have been saved in the file active_connections.txt.")

    elif choice == "11":
        # Show disk info and save it to a text file
        disk_info = get_disk_info()
        with open("disk_info.txt",

 "w") as f:
            f.write(disk_info)
        print("Disk information has been saved in the file disk_info.txt.")

    elif choice == "12":
        # Show network and WIFI info and save it to a text file
        network_info = get_network_info()
        with open("network_info.txt", "w") as f:
            f.write(network_info)
        print("Network and WIFI information has been saved in the file network_info.txt.")

    elif choice == "13":
        # Show mapped drives
        view_drives()

    elif choice == "14":
        # Create all files into one
        create_all_scan()

    elif choice == "15":
        try:
            usb_history = PastUSB()
            with open("usb_history.txt", "w") as f:
                for device in usb_history:
                    f.write(device.get_details())
                    f.write("\n\n")
            print("USB device history has been saved in the file usb_history.txt.")
        except Exception as e:
            print("Error occurred while retrieving USB device history:", e)


    elif choice == "16":
        # Exit
        break

    else:
        print("Invalid choice. Please enter a valid number.")

