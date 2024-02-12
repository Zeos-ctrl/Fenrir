import subprocess
import time
import psutil

def run_program():
    # Replace 'your_program.exe' with the actual command to run your program
    subprocess.run(['./fenrir.out'])

def get_running_core(pid):
    process = psutil.Process(pid)
    affinity = process.cpu_affinity()
    return affinity[0] if affinity else None

def monitor_cpu_power_draw(output_file, max_runtime):
    with open(output_file, 'w') as file:
        start_time = time.time()

        while (time.time() - start_time) < max_runtime and psutil.pid_exists(pid) and psutil.Process(pid).is_running():
            # Poll CPU power draw or energy consumption for all cores
            power_draw = psutil.cpu_percent(interval=0.01, percpu=True)

            # Get the running core for the process
            running_core = get_running_core(pid)

            # Save the result to the file
            elapsed_time = time.time() - start_time
            file.write(f"{elapsed_time:.2f}, {running_core}, {power_draw}\n")

            time.sleep(0.01)

if __name__ == "__main__":
    runs = 10
    run_interval = 60  # seconds
    max_runtime = 75  # seconds (adjust as needed)
    output_file = 'power_draw_results.csv'

    for i in range(runs):
        print(f"Running program {i + 1}/{runs}")
        process = subprocess.Popen(['./fenrir.out'])  # Start the program
        pid = process.pid  # Get the process ID

        if i < runs - 1:
            print(f"Waiting for {run_interval} seconds before the next run...")
            time.sleep(run_interval)
            process.terminate()  # Terminate the program after the interval

    print("Monitoring CPU power draw for the entire runtime...")
    monitor_cpu_power_draw(output_file, max_runtime)

    print("Program completed.")

