import os
import pandas as pd
import matplotlib.pyplot as plt

RESULTS_DIR = "results/csv"
GRAPH_DIR = "results/graphs"

os.makedirs(GRAPH_DIR, exist_ok=True)

protocol_data = {}

# Load CSV files
for file in os.listdir(RESULTS_DIR):
    if file.endswith(".csv"):

        protocol = file.replace("_results.csv", "").replace(".csv", "")
        path = os.path.join(RESULTS_DIR, file)

        df = pd.read_csv(path, skipinitialspace=True)

        # Convert values to numeric
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        protocol_data[protocol] = df

print("Protocols detected:", list(protocol_data.keys()))


def plot_metric(metric, ylabel):

    for protocol, df in protocol_data.items():

        if metric not in df.columns:
            continue

        plt.figure(figsize=(8,5))

        plt.plot(df["Time"], df[metric], marker='o')
        plt.xlabel("Time (s)")
        plt.ylabel(ylabel)
        plt.title(f"{protocol.upper()} - {ylabel} vs Time")
        plt.grid(True)

        filename = f"{protocol}_{metric.lower()}_vs_time.png"
        save_path = os.path.join(GRAPH_DIR, filename)

        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        plt.close()


# Generate graphs
plot_metric("Throughput", "Throughput (Kbps)")
plot_metric("PDR", "Packet Delivery Ratio")
plot_metric("AvgDelay", "Average Delay (s)")
plot_metric("RxPackets", "Received Packets")
plot_metric("TxPackets", "Transmitted Packets")