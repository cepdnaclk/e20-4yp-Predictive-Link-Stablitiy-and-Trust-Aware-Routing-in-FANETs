# Predictive Link Stability and Trust-Aware Routing in FANETs

#### Team

- E/20/035, K.C.H.N.A.W.M.R.C.J.N. Bandara, [email](mailto:e20035@eng.pdn.ac.lk)
- E/20/173, P.A.S.V. Jayasooriya, [email](mailto:e20173@eng.pdn.ac.lk)
- E/20/178, N.K.D.P. Jayawardena, [email](mailto:e20178@eng.pdn.ac.lk)

#### Supervisors

- Dr. Suneth Namal Karunarathna, [email](mailto:namal@eng.pdn.ac.lk)
- Dr. Upul Jayasinghe, [email](mailto:upuljm@eng.pdn.ac.lk)

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