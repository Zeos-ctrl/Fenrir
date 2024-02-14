import subprocess
import time
import psutil

def run_program():
    subprocess.run(['./../fenrir.out'])

def get_running_core(pid):
    process = psutil.Process(pid)
    affinity = process.cpu_affinity()
    return affinity[0] if affinity else None

def get_cpu_temperature():
    try:
        temperatures = psutil.sensors_temperatures()
        cpu_temperature = temperatures['k10temp'][0].current  # Adjust the sensor name as needed
        return cpu_temperature
    except (AttributeError, KeyError, IndexError):
        return None  # Return None if temperature information is not available

def monitor_cpu_power_draw(output_file, max_runtime):
    with open(output_file, 'w') as file:
        start_time = time.time()

        while (time.time() - start_time) < max_runtime and psutil.pid_exists(pid) and psutil.Process(pid).is_running():
            power_draw = psutil.cpu_percent(interval=0.01, percpu=True)

            cpu_temperature = get_cpu_temperature()

            running_core = get_running_core(pid)

            elapsed_time = time.time() - start_time
            file.write(f"{elapsed_time:.2f}, {power_draw}, {cpu_temperature}\n")

            time.sleep(0.01)

if __name__ == "__main__":
    runs = 1
    run_interval = 60  # seconds
    max_runtime = 75  # seconds (adjust as needed)
    output_file = 'power_draw_results.csv'

    for i in range(runs):
        print(f"Running program {i + 1}/{runs}")
        process = subprocess.Popen(['./../fenrir.out'])  # Start the program
        pid = process.pid  # Get the process ID

        if i < runs - 1:
            print(f"Waiting for {run_interval} seconds before the next run...")
            time.sleep(run_interval)
            process.terminate()  # Terminate the program after the interval

    print("Monitoring CPU power draw for the entire runtime...")
    monitor_cpu_power_draw(output_file, max_runtime)

    print("Program completed.")

