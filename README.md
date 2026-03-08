# mAIpper
Takes input from tools, analyze with ollama and create note cards / canvas in obsidian.

Scan results should be saved in the working directory in a "scans" folder, or point to the scan folder with the --scans-dir option.  Organize scans by tool type.  Currently only nmap is supported. 

You must start ollama prior to running this version and the API must be accessible.  Defaults to localhost.  

Running "python mAIpper-v04.py -v" will analyze the nmap scans with Ollama using the qwen2.5:14b-instruct-q5_K_M model (or specify other model).  It will then generate notes on a per host basis and create a Canvas for visualizing the scanned assets.  



