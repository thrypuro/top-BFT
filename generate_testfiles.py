#!/usr/bin/env python3

import sys
import json

default_ip = "127.0.0.1"

def save_json_file( json_file , filename):
    with open(filename, 'w') as file:
        json.dump(json_file, file, indent=4)

def generate_root_committee_json(total_node_addresses,
                                 partition_num,
                                 replica_num, passive_num, message_counter, message_size,
                                 leader_failure_rate, all_failure_rate):

    root = {}
    root["Primary_nodes"] = partition_num
    root["Replica_nodes"] = replica_num
    root["Passive_nodes"] = passive_num
    root["Message_counter"] = message_counter
    root["Message_size"] = message_size
    root["Leader_failure_rate"] = leader_failure_rate
    root["All_failure_rate"] = all_failure_rate
    root["Total_node_address"] = total_node_addresses
    return root


"""
Total_nodes_address=9
Msg_size=1024
MsgUintSize=1024
"""
def generate_replica_json(total_node_addresses, Msg_size):
    replica = {}
    replica["Total_node_address"] = total_node_addresses
    replica["Message_size"] = Msg_size
    return replica




"""
Sample file generated:
{
  "0" : 
    
    {
      "ip": "127.0.0.1",
      "port" : "8081"
    }
}
"""
def generate_node_addresses(total_node_addresses, start_port=8081):
    node_addresses = {}
    for i in range(total_node_addresses):
        node_addresses[i] = {}
        node_addresses[i]["ip"] = default_ip
        node_addresses[i]["port"] = start_port
        start_port += 1
    return node_addresses

def main():
    # check atleast 2 arguments are passed
    if len(sys.argv) < 4 or sys.argv[1] == "-h":
        print("Usage: python3 generate_json.py <Partition-Num> <Replica-Num> <Passive-Num> <Message_counter> <Message-size> <Leader-Failure-rate> <All-Failure-rate>")
        print("Partition Number, Replica number, Passive number are mandatory")
        print("Message counter, Message size, Leader failure rate, All failure rate are optional")
        sys.exit(1)

    # get the arguments
    partition_num = int(sys.argv[1])
    replica_num = int(sys.argv[2])
    passive_num = int(sys.argv[3])
    message_counter = 100
    message_size = 1024
    leader_failure_rate = 0
    all_failure_rate = 0

    if len(sys.argv) > 4:
        message_counter = int(sys.argv[4])
    if len(sys.argv) > 5:
        message_size = int(sys.argv[5])
    if len(sys.argv) > 6:
        leader_failure_rate = int(sys.argv[6])
    if len(sys.argv) > 7:
        all_failure_rate = int(sys.argv[7])

    # Each partition has 1 leader and (replica_num + passive_num) followers, and 1 Root committee
    total_node_addresses = partition_num * (replica_num + passive_num + 1)

    nodes = generate_node_addresses(total_node_addresses)

    # generate the json file
    save_json_file(nodes, "node_addresses.json")

    # generate the config file

    root_committee = generate_root_committee_json(total_node_addresses,
                                                  partition_num, replica_num, passive_num, message_counter, message_size, leader_failure_rate, all_failure_rate)
    save_json_file(root_committee, "Primary_config.json")
    client_nodes = generate_node_addresses(1, start_port=9000)

    save_json_file(client_nodes, "client_addresses.json")
    # replica = generate_replica_json(total_node_addresses, message_size)
    #
    # save_json_file(replica, "Replica_config.json")
    #
    # passive = generate_replica_json(total_node_addresses, message_size)
    # save_json_file(passive, "Passive_config.json")



if __name__ == "__main__":
    main()

