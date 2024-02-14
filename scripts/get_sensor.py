import psutil

def print_available_sensors():
    try:
        temperatures = psutil.sensors_temperatures()
        for sensor, entries in temperatures.items():
            for entry in entries:
                print(f"Sensor: {sensor}, Entry: {entry.label}, Current Temperature: {entry.current} °C")
    except (AttributeError, KeyError, IndexError):
        print("Temperature information is not available.")

print_available_sensors()

