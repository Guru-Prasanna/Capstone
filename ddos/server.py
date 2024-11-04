import socket
import threading
import time
import joblib
import numpy as np

CONNECTION_LIMIT = 30
WINDOW_SIZE_SECONDS = 10
connections = []
ip_connection_count = {}
suspicious_ips = []

knn = joblib.load('KNN.joblib')
lr = joblib.load('LogisticRegression.joblib')

def ip_to_int(ip):
    return int(ip.replace('.', ''))

def process_models(conn_data):
    """
    Process the incoming connection data through the models.
    Expects conn_data to be a list or numpy array containing the features:
    [Source_IP, Destination_IP, Source_Port, Destination_Port, Protocol, Packet_Size, flag]
    """
    print(conn_data)
    conn_data = np.array(conn_data).reshape(1, -1)

    knn_prediction = knn.predict(conn_data)
    lr_prediction = lr.predict(conn_data)

    print("Model predictions:")
    print(f"KNN: {knn_prediction[0]}")
    print(f"Logistic Regression: {lr_prediction[0]}")

    return {
        'knn': knn_prediction[0],
        'logistic_regression': lr_prediction[0],
    }

def detect_ddos():
    while True:
        time.sleep(WINDOW_SIZE_SECONDS)
        current_time = time.time()
        # Filter connections within the time window
        active_connections = [conn_time for conn_time in connections if current_time - conn_time < WINDOW_SIZE_SECONDS]
        if len(active_connections) > CONNECTION_LIMIT:
            print(f"Possible DDoS attack detected: {len(active_connections)} connections within {WINDOW_SIZE_SECONDS} seconds")
            # Example data to pass into the models (this should be the actual data you collect)
            example_conn_data = [19216801, 19216802, 8080, 80, 6, 512]  # This needs to be the actual connection data
            process_models(example_conn_data)

def start_server(port):
    ddos_thread = threading.Thread(target=detect_ddos)
    ddos_thread.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', port))
    server.listen(100)

    print(f"Server listening on port {port}")

    try:
        while True:
            client_socket, addr = server.accept()
            print(f"Accepted connection from {addr}")

            source_ip = ip_to_int(addr[0])
            source_port = addr[1]
            destination_ip = ip_to_int(server.getsockname()[0])
            destination_port = server.getsockname()[1]
            protocol = client_socket.proto
            packet_size = len(client_socket.recv(4096))

            predictions = process_models([source_ip, destination_ip, source_port, destination_port, protocol, packet_size])

            if (predictions['knn'] == 1 or predictions['logistic_regression'] == 1) and addr[0] not in suspicious_ips:
                suspicious_ips.append(addr[0])

            connections.append(time.time())

            # Update the connection count for the source IP
            if source_ip in ip_connection_count:
                ip_connection_count[source_ip] += 1
            else:
                ip_connection_count[source_ip] = 1

            # Check if any IP exceeds the connection limit
            for ip, count in ip_connection_count.items():
                if count > CONNECTION_LIMIT:
                    print(f"Possible DDoS attack detected from IP {ip}: {count} connections")

            response = b"Hello, World!\n"
            client_socket.send(response)

            client_socket.close()

            # Decrement the connection count for the source IP after closing the connection
            ip_connection_count[source_ip] -= 1

    except KeyboardInterrupt:
        print("Server stopped due to keyboard interrupt.")
        for ip, count in ip_connection_count.items():
            if count > CONNECTION_LIMIT:
                print(f"IP possibly trying DDoS attack: {ip}")
        print("Suspicious IPs detected by models:")
        for ip in suspicious_ips:
            print(ip)

    finally:
        server.close()

if __name__ == "__main__":
    port_number = 8080
    start_server(port_number)
