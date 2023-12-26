import csv
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter
import math
from scipy.stats import pearsonr

# Path to the CSV file
csv_file_path = "/Users/fatimasohail/Documents/Network Security/pseudonyms.csv"


# Function to convert hex string to byte values
def hex_to_bytes(hex_str):
    return [int(hex_str[i : i + 2], 16) for i in range(0, len(hex_str), 2)]


# Read the pseudonyms from the CSV file
pseudonyms = []
with open(csv_file_path, "r") as file:
    csv_reader = csv.reader(file)
    for row in csv_reader:
        if len(row) >= 3:  # Ensure row has sufficient columns
            pseudonyms.extend(hex_to_bytes(row[2]))


# Count the frequency of each byte value
byte_counts = np.bincount(pseudonyms, minlength=256)

# Plotting
plt.figure(figsize=(10, 6))
plt.bar(range(256), byte_counts, color="blue")
plt.xlabel("Byte Value")
plt.ylabel("Frequency")
plt.title("Frequency of Byte Values in Pseudonyms")


plt.xlim(0, 255)  # Byte values range from 0 to 255
plt.show()
