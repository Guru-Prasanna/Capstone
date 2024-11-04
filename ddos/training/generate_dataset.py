import csv
import random
import numpy as np

def write_to_csv(file_path, data):
    with open(file_path, 'w', newline='') as csv_file:
        fieldnames = ['Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 'Protocol', 'Packet_Size']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(data)

def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def generate_dataset(num_rows):
    dataset = []
    for _ in range(num_rows):
        row = {
            'Source_IP': generate_random_ip(),
            'Destination_IP': generate_random_ip(),
            'Source_Port': random.randint(1024, 65535),
            'Destination_Port': random.randint(1024, 65535),
            'Protocol': random.choice(['TCP', 'UDP']),
            'Packet_Size': int(np.random.normal(800, 200))
        }
        dataset.append(row)
    return dataset


normal_traffic_file = 'normal_traffic.csv'
attack_traffic_file = 'attack_traffic.csv'

num_rows = 500  
normal_traffic_data = generate_dataset(num_rows)
attack_traffic_data = generate_dataset(num_rows)

write_to_csv(normal_traffic_file, normal_traffic_data)
write_to_csv(attack_traffic_file, attack_traffic_data)

print(f'Dataset files created: {normal_traffic_file}, {attack_traffic_file}')
