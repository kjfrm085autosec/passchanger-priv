import subprocess

def run_command(command):
"""Run a shell command and print its output."""
print(f"Running: {command}")
process = subprocess.run(command, shell=True, text=True)
if process.returncode != 0:
print(f"Command failed: {command}")
exit(1)

def run_command_capture(command):
"""Run a shell command and return its output."""
result = subprocess.run(command, shell=True, capture_output=True, text=True)
if result.returncode != 0:
print(f"Command failed: {command}")
exit(1)
return result.stdout.strip()

def install_dependencies():
run_command("sudo apt update")
run_command("sudo apt install -y wget curl unzip gnupg")

def install_google_chrome():
run_command("wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/chrome.deb")
run_command("sudo apt install -y /tmp/chrome.deb")

def install_chromedriver():
# Get Chrome version
chrome_version = run_command_capture("google-chrome --version").split()[-1]
major_version = chrome_version.split(".")[0]
print(f"Detected Chrome version: {chrome_version} (major: {major_version})")

# Download matching ChromeDriver
run_command(f"wget https://chromedriver.storage.googleapis.com/{major_version}.0.0.0/chromedriver_linux64.zip -O /tmp/chromedriver.zip")
run_command("unzip /tmp/chromedriver.zip -d /tmp/")
run_command("sudo mv /tmp/chromedriver /usr/local/bin/")
run_command("sudo chmod +x /usr/local/bin/chromedriver")

def print_versions():
chrome_ver = run_command_capture("google-chrome --version")
chromedriver_ver = run_command_capture("chromedriver --version")
print("\nInstalled Versions:")
print(f"Google Chrome: {chrome_ver}")
print(f"ChromeDriver: {chromedriver_ver}")

def main():
install_dependencies()
install_google_chrome()
install_chromedriver()
print_versions()
print("\nInstallation complete!")

if __name__ == "__main__":
main()
