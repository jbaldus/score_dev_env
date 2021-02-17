#!/usr/bin/python3

import subprocess, shlex
from collections import namedtuple
import datetime
import os, pwd, re, glob

# Set up a method for easily formatting output: To use, simply print a format 
# string and surround the text you want to be bold with {s.bold} and {s.reset}
from colorama import Style
from colorama import Fore
from types import SimpleNamespace as _
s = _(bold = Style.BRIGHT+Fore.YELLOW, reset = Style.RESET_ALL )

def bold(text):
    return f"{s.bold}{text}{s.reset}"


def run(command, is_shell=False):
    """Runs a shell command and returns the stdout response"""
    return subprocess.run(shlex.split(command),
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          shell=is_shell,
                          ).stdout.decode('utf-8')

def password_status(user):
    PasswordStatus = namedtuple('PasswordStatus', 
                    ['user', 'is_locked', 'last_change', 'min_age', 
                    'max_age', 'warning', 'inactivity'])
    output = run(f"passwd -S {user}")
    output = output.split()
    d = output[2].split('/')
    output[2] = datetime.date(int(d[2]), int(d[0]), int(d[1]))
    output[3] = int(output[3])
    output[4] = int(output[4])
    output[5] = int(output[5])
    output[6] = int(output[6])
    ps = PasswordStatus(*output)    
    return ps
       

def is_user_in_passwd(user):
    pass_line = run(f"grep {user} /etc/passwd")
    return user in pass_line

def is_user_home_removed(user):
    try:
        return not os.path.isdir(f"/home/{user}")
    except:
        return True

def is_user_removed(user):
    return is_user_home_removed(user) and not is_user_in_passwd(user)

def is_root_login_disabled():
    ps = password_status('root')
    return ps.is_locked == 'L'


def is_root_ssh_login_disabled():
    permit_root_login = run("grep ^PermitRootLogin /etc/ssh/sshd_config")
    is_yes = "yes" in permit_root_login
    return not is_yes

def is_user_in_admin(user):
    return 'sudo' in run(f"groups {user}")

def is_media_files_deleted(directory, filetype):
    files = glob.glob(f"{directory}/*.{filetype}")
    return len(files) == 0

def is_program_installed(program):
    which = run(f"which {program}")
    return which.strip() != ''

def is_guest_session_disabled():
    config_line = run("grep allow-guest /etc/lightdm/lightdm.conf.d/*")
    is_guest_allowed = config_line.split('=')[1]
    is_yes = re.match("true", is_guest_allowed, re.IGNORECASE)
    return is_yes == None

def is_service_running(service):
    active_line = run(f"systemctl is-active {service}")
    is_active = "inactive" not in active_line
    return is_active

def is_service_enabled(service):
    enabled_line = run(f"systemctl is-enabled {service}")
    is_enabled = "disabled" not in enabled_line
    return is_enabled

def is_service(service):
    return is_service_running(service) and is_service_enabled(service)

def is_ufw_enabled():
    enabled_line = run("ufw status")
    is_enabled = "inactive" not in enabled_line
    return is_enabled

def is_removed_service(service):
    return not is_service_running(service) and not is_service_enabled(service)

def is_daily_update_checked():
    update_package_list = run("grep 'APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/*")
    return '1' in update_package_list

def is_auto_upgrade():
    unattended_upgrade = run("grep 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/*")
    return '1' in unattended_upgrade

def is_hypnotoad_not_sudo():
    hypnotoad_line = run("grep hypnotoad /etc/sudoers")
    return "hypnotoad" not in hypnotoad_line

def is_user_sudoer(user):
    return "not allowed" not in run(f"sudo -l -U {user}")

def is_user_password_expired(user):
    password_info = password_status(user)


def is_forensic_question_answered(forensic_file, answer):
    if not os.path.exists(forensic_file):
        print(f"Forensics file {forensic_file} not found. This is an error of the scoring engine.")
        return False
    # In the command below, the \K of the regex will lookup the previous pattern, but not include it in the
    # matching result. The -Po options to grep cause it to return only the matching pattern
    command = f'grep -Po \'^Answer: *\K.*\' "{forensic_file}"'
    answer_line = run(command).strip()
    return answer == answer_line

class Task:
    def __init__(self, function, arguments, success, description, points = 5):
        self.points = points
        self.function = function
        if not type(arguments) is list and not type(arguments) is tuple:
            self.args = [arguments]
        else:
            self.args = arguments
        self.success = success
        self.description = description
        
    def check(self):
        global score
        global found_items
        if len(self.args)==1 and self.args[0]==None:
            value = (self.function() == self.success)
        else:
            value = (self.function(*self.args) == self.success)
        if value:
            score += self.points
            found_items += 1
            print(f"{s.bold}{self.points} points{s.reset} {self.description}")
            
        


points = [
    #Points, function, arguments, truth, description
    Task(is_root_login_disabled, None, True, "Disabled root user login."),
    Task(is_root_ssh_login_disabled, None, True, "Disallowed root from login in through ssh."),
    Task(is_user_removed, "donbot", True, "Removed unauthorized user donbot."),
    Task(is_user_removed, "mom", True, "Removed unauthorized user mom."),
    Task(is_user_removed, "wernstrom", True, "Removed unauthorized user wernstrom."),
    Task(is_user_removed, "hypnotoad", True, "Removed unauthorized user hypnotoad."),
    Task(is_user_in_admin, "cubert", False, "Removed cubert from Administrators."),
    Task(is_user_in_admin, "donbot", False, "Removed donbot from Administrators."),
    Task(is_user_in_admin, "wernstrom", False, "Removed wernstrom from Administrators."),
    Task(is_user_in_admin, "leela", True, "Added leela to Administrators."),
    Task(is_media_files_deleted, ["/home/scruffy/Pictures", "*"], True, "Removed unauthorized media files from user scruffy."),
    Task(is_service, "auditd", True, "Installed and enabled auditd service."),
    Task(is_removed_service, "xrdp", True, "Stopped and disabled Remote Desktop Protocol service."),
    Task(is_program_installed, "aircrack-ng", False, "Removed hacking tool aircrack-ng."),
    Task(is_program_installed, "nmap", False, "Removed hacking tool nmap."),
    Task(is_user_sudoer, "hypnotoad", False, "Removed hypnotoad's sudo access."),
    Task(is_ufw_enabled, None, True, "Firewall enabled."),
    Task(is_daily_update_checked, None, True, "Set to check for updates daily."),
    Task(is_auto_upgrade, None, True, "Set to upgrade automatically."),
    Task(is_forensic_question_answered, ["/home/bender/Desktop/Forensic\ Question\ 1.txt", "scruffy"], True, "Answered forensic question 1"),
    Task(is_program_installed, "clamav", True, "Installed anti-malware tools."),
    ]
    

if __name__ == "__main__":
    if pwd.getpwuid( os.getuid() ).pw_name != 'root':
        print("""Since the scoring software needs to access system configurations,
                it must be run with elevated privileges. Try again with 'sudo'.
            """)
        exit()
    
    print("")
    total_possible_points = 0
    score = 0
    found_items = 0
    for point in points:
        total_possible_points += point.points
        point.check()
        
    print(f"\nYou have found {bold(found_items)} out of {bold(len(points))}, \nearning {bold(f'{score} points out of {total_possible_points} points')}.")
    

