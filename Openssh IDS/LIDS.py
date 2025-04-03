import time
import colorama
from colorama import Fore, Style
from datetime import datetime, timedelta
from tqdm import tqdm
import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import random
import ipaddress
import getpass
import requests

colorama.init(autoreset=True)
registered_users = {}
LOG_TIME_FORMAT = '%d-%m-%Y %H:%M:%S'

SENDER_EMAIL = "notankitsmail@gmail.com"
SENDER_PASSWORD = "cwft oiai jdws odzz"

IPSTACK_API_KEY = "7a88371e025bafe95827f84c8fa9ac0e"

def is_valid_gmail(email):
    # regen check
    pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    return re.match(pattern, email)


def encrypt_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed


def generate_otp():
    return str(random.randint(100000, 999999))


def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password)


def send_otp_email(receiver_email, otp):
    print(f"{Fore.GREEN}Generating OTP...")
    try:
        # Set up the SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)

        # Create the email content
        message = MIMEMultipart()
        message['From'] = SENDER_EMAIL
        message['To'] = receiver_email
        message['Subject'] = 'Your OTP for Login'
        body = f"""
            Hello!

            Your One-Time Password (OTP) for login is: {otp}

            Best regards,
            LIDS
            """
        message.attach(MIMEText(body, 'plain'))

        # Send the email
        server.sendmail(SENDER_EMAIL, receiver_email, message.as_string())
        server.quit()
        print(f"{Fore.GREEN}OTP sent successfully to {receiver_email}")
    except Exception as e:
        print(f"{Fore.RED}Failed to send OTP. Error: {e}")


def registerUser():
    name = input("Enter your name: ")
    email = input("Enter your email: ")

    if not is_valid_gmail(email):
        print(f"{Fore.RED}Invalid Gmail address. Please enter a valid @gmail.com address.")
        return

    if name in registered_users:
        print(f"{Fore.CYAN}User name is already registered.")
    else:
        password = getpass.getpass("Enter your password: ")
        encrypted_password = encrypt_password(password)
        registered_users[name] = {'email': email, 'password': encrypted_password}
        print(f"{Fore.GREEN}User has been registered successfully!")


def UserLogin():
    name = input("Enter your name: ")
    if name not in registered_users:
        print(f"{Fore.RED}User not found. Please register first.")
        return
    password = getpass.getpass("Enter your password: ")
    stored_password = registered_users[name]['password']
    if verify_password(stored_password, password):
        email = registered_users[name]['email']
        otp = generate_otp()
        send_otp_email(email, otp)

        # OTP Verification
        entered_otp = input("Enter the OTP sent to your email: ")
        if entered_otp == otp:
            print(f"{Fore.GREEN}Login successful! Welcome, {name}.")
            UserLoginPage(name)
        else:
            print(f"{Fore.RED}Incorrect OTP. Login failed.")

    else:
        print(f"{Fore.RED}Incorrect password. Try again.")
    # UserLoginPage(name)



def UserLoginPage(name):
    time.sleep(1)
    print(f"{Fore.CYAN}1. Detect log intrusions")
    time.sleep(0.5)
    print(f"{Fore.CYAN}2. Geotrack IP addresses")
    time.sleep(0.5)
    print(f"{Fore.CYAN}3. Logout")
    time.sleep(0.5)
    choice = input(f"{Fore.YELLOW}Select an option: {Style.RESET_ALL}")

    if choice == '1':
        scan_login_attempts(name)
    elif choice == '2':
        geotrack_ips(name)
    elif choice == '3':
        print(f"{Fore.CYAN}Logging out...")
        time.sleep(2)
        return
    else:
        print(f"{Fore.RED}Invalid option. Please select again.{Style.RESET_ALL}")


def validate_ip_address(ip_str):
    """Validate if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def process_ssh_logs(file_path):
    """
    Process SSH log file and validate IP addresses.
    Args:
        file_path (str): Path to the SSH log file
    Returns:
        dict: Dictionary containing valid and invalid IPs with their counts
    """
    # Initialize result dictionary
    results = {
        'valid_ips': {},  # Store valid IPs with their count
        'invalid_ips': {},  # Store invalid IPs with their count
        'total_lines': 0,  # Count total lines processed
    }

    # Regular expression to extract IP addresses from log lines
    ip_pattern = r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    try:
        with open(file_path, 'r') as file:
            for line in file:
                results['total_lines'] += 1
                # Extract IP address from the line
                match = re.search(ip_pattern, line)
                if match:
                    ip = match.group(1)
                    # Validate the IP address
                    if validate_ip_address(ip):
                        results['valid_ips'][ip] = results['valid_ips'].get(ip, 0) + 1
                    else:
                        results['invalid_ips'][ip] = results['invalid_ips'].get(ip, 0) + 1

    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return None

    return results


def print_validation_report(results):
    if not results:
        return

    print(f"{Fore.GREEN}\n=== SSH Log IP Validation Report ===")
    print(f"{Fore.GREEN}Total lines processed: {results['total_lines']}")

    print(f"{Fore.GREEN}\nValid IP Addresses:")
    print("-" * 50)
    for ip, count in sorted(results['valid_ips'].items(), key=lambda x: x[1], reverse=True):
        print(f"IP: {ip:<15} Count: {count}")

    if results['invalid_ips']:
        print(f"{Fore.RED}\nInvalid IP Addresses:")
        print(f"{Fore.RED}-" * 50)
        for ip, count in sorted(results['invalid_ips'].items(), key=lambda x: x[1], reverse=True):
            print(f"IP: {ip:<15} Count: {count}")
    else:
        print("\nNo invalid IP addresses found")


def scan_login_attempts(username):
    total_duration = 4  # in seconds
    steps = 100
    delay = total_duration / steps

    if not registered_users:
        print(f"{Fore.RED}No registered users. Please register before using this feature.")
        return
    if username in registered_users:
        log_file_path = input(f"\n{Fore.YELLOW}Enter the path of the log file: {Style.RESET_ALL}")
        print(f"{Fore.GREEN}Scanning event logs...")
        for _ in tqdm(range(steps), desc="Loading", unit="step"):
            time.sleep(delay)
        detect_multiple_login_attempts(log_file_path, username)
        validation_results = process_ssh_logs(log_file_path)  # Process the log file
        print_validation_report(validation_results)  # Print the report
        UserLoginPage(username)
    else:
        print(f"{Fore.RED}User {username} is not registered. Please register before using this feature.")


def detect_multiple_login_attempts(log_file, username):
    try:
        with open(log_file, 'r') as file:
            logs = file.readlines()

        login_attempts = []

        for line in logs:
            if f"Failed password for {username}" in line:
                log_time_str = line.split('\t')[1]
                log_time = datetime.strptime(log_time_str, LOG_TIME_FORMAT)
                login_attempts.append(log_time)

        if len(login_attempts) > 2:
            for i in range(1, len(login_attempts)):
                time_diff = login_attempts[i] - login_attempts[i - 2]

                # Check if the time difference is less than or equal to 5 minutes
                if time_diff <= timedelta(minutes=5):
                    print(
                        f"\n{Fore.RED}ALERT: Multiple failed login attempts for user '{username}' within 5 minutes at {login_attempts[i]} and {login_attempts[i - 2]}.")
                    break
            else:
                print(
                    f"\n{Fore.GREEN}No suspicious multiple login attempts detected for user '{username}' within 5 minutes.")
        else:
            print(f"\n{Fore.RED}No login attempts detected for user '{username}'.")

    except FileNotFoundError:
        print(f"\n{Fore.RED}The file '{log_file}' was not found.")
    except Exception as e:
        print(f"\n{Fore.RED}An error occurred: {e}")


def geotrack_ips(username):
    if not registered_users:
        print(f"{Fore.RED}No registered users. Please register before using this feature.")
        return
    if username in registered_users:
        log_file_path = input(f"\n{Fore.YELLOW}Enter the path of the log file: {Style.RESET_ALL}")
        print(f"{Fore.GREEN}Analyzing IP addresses...")

        validation_results = process_ssh_logs(log_file_path)
        geotrack_valid_ips(validation_results['valid_ips'])
        UserLoginPage(username)
    else:
        print(f"{Fore.RED}User {username} is not registered. Please register before using this feature.")


def geotrack_valid_ips(valid_ips):
    """
    Geotrack the valid IP addresses using the ipstack API.
    Args:
        valid_ips (dict): Dictionary of valid IPs with their counts
    """
    for ip, count in valid_ips.items():
        try:
            response = requests.get(f"http://api.ipstack.com/{ip}?access_key={IPSTACK_API_KEY}")
            data = response.json()
            if response.status_code == 200:
                print(f"{Fore.GREEN}IP: {ip} | Country: {data['country_name']} | City: {data['city']} | Visits: {count}")
            else:
                print(f"{Fore.RED}Failed to geotrack IP: {ip} | Error: {data['error']['info']}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error geotracking IP: {ip} | {e}")
        except KeyError as ke:
            print(f"{Fore.RED}Error parsing response for IP: {ip} | {ke}")

def main_menu():
    while True:
        print(f"\n{Fore.CYAN}--- LOG INTRUSION DETECTION SYSTEM ---{Style.RESET_ALL}")
        time.sleep(0.5)
        print(f"{Fore.CYAN}1. User Registration")
        time.sleep(0.5)
        print(f"{Fore.CYAN}2. User Login")
        time.sleep(0.5)
        print(f"{Fore.CYAN}3. Exit")
        time.sleep(0.5)
        choice = input(f"{Fore.YELLOW}Select an option: {Style.RESET_ALL}")

        if choice == '1':
            registerUser()
        elif choice == '2':
            UserLogin()
        elif choice == '3':
            print(f"\n{Fore.GREEN}Thank you for using LIDS!{Style.RESET_ALL}")
            break
        else:
            print(f"\n{Fore.RED}Invalid option. Please select again.{Style.RESET_ALL}")


if __name__ == "__main__":
    main_menu()