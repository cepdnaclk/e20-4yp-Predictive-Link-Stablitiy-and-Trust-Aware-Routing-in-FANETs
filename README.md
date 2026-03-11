1. Add the simulation.cc file to ./scratch folder
2. Add the plot_grphs.py to the root directory of ns-3 
3. Add the QBR protocol to the ./src directory
3. Create results folder in the root directory and add animations, csv and graphs subfolders
4. Run the simulation.cc using the following commands (only three protocols are used in the simulation): 
    ./ns3 run "scratch/simulation --protocol=qbr"
    ./ns3 run "scratch/simulation --protocol=olsr"
    ./ns3 run "scratch/simulation --protocol=aodv"

5. Run the plot_graphs.py to generate graphs using all the csv files in the ./reuslts/csv
    IMPORTANT: In wsl some python dependancies can't be installed. Use a virtual environment activate it (source ~/ns3-venv/bin/activate)
6. Open generated graphs in the ./reuslts/graphs 