# MRBE-and-Web-3.0-Communications

## Python version 3.11 
Server with an AMD Ryzen 9 7945HX with Radeon Graphics and NVIDIA GeForce RTX 4070

## Overview
The MRBE System is a cryptographic and blockchain simulation framework designed for secure data storage and processing. It integrates several cryptographic modules (TesRBE, MRBE_P, MTesRBE, Improve_MTesRBE) and simulates blockchain operations for data management.

## Modules
main.py: The entry point for the system. It integrates the blockchain simulation and cryptographic modules.

TesRBE.py: Implements the MRBE cryptographic protocol.

MRBE_P.py: Implements the MRBE-P cryptographic protocol.

MTesRBE.py: Another cryptographic module for advanced data processing.

Improve_MTesRBE.py: A modified or improved version of the MTesRBE.py module for enhanced performance.

## Blockchain Class
The Blockchain class provides functionality to simulate blockchain operations, including:

add_block(data): Adds a new block containing data to the blockchain.

display_chain(): Displays the current blockchain.

## Data Files
blockchain_data.json: Stores the simulated blockchain data.

registered_users.json: Contains data about registered users.

user_blockchain.json: Maps users to their blockchain data.

parameter_blockchain.json: Stores parameters for the blockchain.

## Run the System:
To simulate the blockchain and cryptographic operations, run the main.py.
