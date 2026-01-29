HexHunter
A high‑performance, multi‑core hexadecimal key‑space scanner designed for speed, transparency, and user control. HexHunter provides a fully instrumented scanning engine, real‑time telemetry, performance presets, and a complete control panel for tuning CPU affinity, process priority, batch size, and system behavior.
HexHunter is built to hunt for bitcoin prive key search of reduced bit spaces containing funded addresses in the 1000 btc puzzle challenge. Every component is designed to be reversible, safe, and observable.

Features
High‑Performance Scanning Engine
Multi‑core parallel scanning with efficient batch distribution
Linear and random scanning modes
Optimized buffer reuse and minimized overhead
Real‑time key throughput measurement (keys per second)
Total keys scanned counter with live updates
Performance Control Panel:
-HexHunter includes a dedicated performance tab that allows users to tune the engine in real time.
CPU Affinity Controls
-Select which CPU cores HexHunter is allowed to use.
Process Priority Controls
-Choose between Normal, High, and Realtime priority levels.
Batch Size Slider
-Adjust how many keys each worker processes per cycle.
GUI Refresh Rate
-Control how frequently the interface updates telemetry.
Linear Step Size
-Fine‑tune how the linear scanner increments through the key space.

Optional and reversible optimizations that reduce background noise and improve throughput.
Preset Profiles
HexHunter comes with multiple performance presets:
Balanced Mode – Stable performance with minimal system impact
High‑Performance Mode – Increased priority and optimized batch sizes
Maximum Overdrive – Full CPU utilization, aggressive batching, and reduced background interference
Real‑Time Telemetry
          
 The interface provides continuous insight into the engine. It shows:
Keys per second
Total keys scanned
CPU usage per core
Active preset
Current priority level
Affinity mask
                          
 The interface has toggles for:
Hard‑stop button for immediate shutdown
Optional session auto‑save
Reversible system tweaks
Clear logging and instrumentation

                      
Installation
1. 	Install Python 3.10 or newer.
2. 	Install required dependencies:

3. 	Run HexHunter:

If using the standalone compiled build, simply run the provided executable.

Usage
Starting a Scan
1. 	Choose a scanning mode (Linear or Random).
2. 	Set your key range or random seed parameters.
3. 	Adjust performance settings or select a preset.
4. 	Press Start Scan.
Performance adjustments:
The Performance tab allows real‑time adjustment without restartng the scan.
Changes to affinity, priority, batch size, and refresh rate take effect immediately.
Use the Stop button to halt all workers safely. Keys scanned counter will stay paused and remain
visible so you can make note of the progress 
Contributions, suggetions, and criticism are welcome.
If you want to add new presets, improve the scanning engine, or expand telemetry, or report problems 
feel free to open a pull request or start a discussion.

License
HexHunter is released under the MIT License.
See  for details.
