#!/usr/bin/env uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "psutil",
#     "rich",
#     "scramp",
#     "simplepam",
# ]
# ///

import base64
import hashlib
import subprocess
import shlex
import shutil
import os
from pathlib import Path
import pwd
import math
import re 
from multiprocessing import cpu_count
from socket import gethostname


try:
    import psutil
    import simplepam
    import scramp
except ImportError:
    help_msg = """
This program requires a couple of Python packages to be installed using pip. 
You can take care of installing everything you need with these commands:

sudo apt install python3-pip (on Debian-based systems)
sudo dnf install python3-pip (on Fedora-based systems)
sudo pacman -S python-pip    (on Arch-based systems)

And then run:

sudo pip install -r requirements.txt
    """
    print(help_msg)
    exit()



try:
    from rich import print
    from rich import box
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.console import Console, Group, RenderResult

    use_rich = True

    def bold(text):
        return f"[bold yellow]{text}[/bold yellow]"

except ImportError:
    use_rich = False

    def bold(text):
        return text

alerts = []

def run(command, is_shell=False):
    """Runs a shell command and returns the stdout response"""
    result = subprocess.run(shlex.split(command),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=is_shell,
                            )
    result.stdout = result.stdout.decode('utf-8')
    result.stderr = result.stderr.decode('utf-8')
    return result.stdout.strip()


def check_password(user, pw):
    return simplepam.authenticate(user, pw)


def main_user(uid):
    return pwd.getpwuid(uid).pw_name


def main_user_name_ish(user, uid):
    try:
        username = main_user(uid)
        return user in username
    except KeyError:
        return False


def is_user(user):
    try:
        pwd.getpwnam(user)
        return True
    except KeyError:
        return False

def get_user_sudo_perms(user):
    if not is_user(user):
        return set()
    commands = set()
    sudo_response = run(f"sudo -ll -U {user}").splitlines()
    in_commands = False
    for line in sudo_response:
        if line.strip() == "Commands:":
            in_commands = True
            continue
        if in_commands:
            if line.strip() == line:
                in_commands = False
                continue
            else:
                commands.add(line.strip())
    return commands


def check_sudo_commands(user:str, deb_commands: set, rh_commands: set, arch_commands: set) -> bool:
    global alerts
    if is_program_installed("apt"):
        commands = deb_commands
    elif is_program_installed("dnf"):
        commands = rh_commands
    elif is_program_installed("pacman"):
        commands = arch_commands
    configured_commands = get_user_sudo_perms(user)
    if configured_commands == deb_commands and commands != deb_commands:
        nl = "\n"
        nltab = "\n\t"
        text = f"You have correctly configured newguy's sudo commands, but they should be changed to reflect this distribution. \nPlease update them to be these commands:\n\n{nl.join(commands)}"
        if use_rich:
            title = Text("Alert", justify='center')
            text = f"You have correctly configured newguy's sudo commands for a Debian-based system, but they should be changed to reflect this distribution. \n\nPlease update them to be these commands:\n\n\t{nltab.join(commands)}"
            panel_text = Group(title, text, '', 'then run the score again')
            panel = Panel(panel_text, highlight=True, border_style="yellow", width=100, style="bold yellow")
            alerts.append(panel)
        else:
            alerts.append(text)
    return configured_commands == commands


def is_user_home_existing(user):
    try:
        user_password = pwd.getpwnam(user)
        return os.path.isdir(user_password.pw_dir)
    except KeyError:
        return False


def is_login_disabled(user = 'root'):
    if not is_user(user):
        return True
    status_line = run(f"sudo passwd -S {user}")
    password_status = status_line.split(' ')[1]
    return password_status == "L"


def is_root_ssh_login_disabled():
    permit_root_login = run("grep ^PermitRootLogin /etc/ssh/sshd_config")
    is_yes = "yes" in permit_root_login
    return not is_yes


def is_user_in_admin(user, admin_group='sudo'):
    return admin_group in run(f"groups {user}")


def get_partition_size_bytes(partition):
    if "/dev/sd" in partition:
        partitions = psutil.disk_partitions(all=True)
        part_info = next((x for x in partitions if x.device == partition), None)
        if part_info is None:
            raise KeyError(f"Partition {partition} is not mounted.")
        mountpoint = part_info.mountpoint
    else:
        mountpoint = partition
    return psutil.disk_usage(mountpoint).total


def pg_run(sql):
    return run(f'sudo -u postgres psql -t -c "{sql}"')


def pg_user_exists(user):
    sql = f"select usename from pg_user where usename='{user}';"
    result = pg_run(sql)
    return result.strip() != ""


def pg_database_exists(db):
    sql = f"select datname from pg_database where datname='{db}';"
    result = pg_run(sql)
    return result.strip() != ""


def pg_database_owner(db, owner):
    sql = f"select pg_get_userbyid(datdba) from pg_database where datname='{db}';"
    result = pg_run(sql)
    return result.strip() == owner


def pg_user_pwhash(user):
    sql = f"select passwd from pg_shadow where usename='{user}';"
    return pg_run(sql).strip()


def pg_user_password(user, password):
    return new_pg_user_password(user, password) or old_pg_user_password(user, password)


def new_pg_user_password(user, password):
    pwhash = pg_user_pwhash(user)
    mechanism = pwhash.split('$')[0]
    if 'SCRAM' not in mechanism:
        return pwhash == password
    rounds, salt = pwhash.split('$')[1].split(':')
    rounds = int(rounds)
    salt = base64.b64decode(salt)
    mechanism = scramp.ScramMechanism()
    computed = mechanism.make_auth_info(password, rounds, salt)
    computed_stored_key = base64.b64encode(computed[1]).decode('utf-8')
    computed_server_key = base64.b64encode(computed[2]).decode('utf-8')
    return pwhash.split('$')[2] == f"{computed_stored_key}:{computed_server_key}"


def old_pg_user_password(user, password):
    pwhash = pg_user_pwhash(user)
    calculated_hash = hashlib.md5(f"{password}{user}".encode('utf-8')).hexdigest()
    return pwhash == "md5" + calculated_hash


def is_program_installed(*program):
    return any(map(shutil.which, program))


def resolve_command(command):
    split_command = shlex.split(command)
    cmd = split_command[0]
    resolved_cmd = shutil.which(cmd)
    if resolved_cmd is None:
        return None
    args = " ".join(split_command[1:])
    return f"{resolved_cmd} {args}"


def is_program_uptodate(program):
    if is_program_installed("apt"):
        result = run(f"apt list {program}")
        return not "upgradable" in result
    elif is_program_installed("pacman"):
        result = run(f"pacman -Qu {program}")
        return result == ""
    elif is_program_installed("yum"):
        result = run(f"yum check-update {program}")
        return not program in result
    else:
        raise NotImplementedError("Scoring can only run on systems with apt or pacman or yum")


def is_software_uptodate():
    if is_program_installed("apt"):
        result = run("apt list --upgradable")
        return result.strip() != ""
    elif is_program_installed("pacman"):
        result = run("pacman -Qu")
        return result.strip() == ""
    elif is_program_installed("yum"):
        result = run("yum check-update | grep updates")
        return len(result.split("\n")) == 1
    else:
        raise NotImplementedError("Scoring can only run on systems with apt or pacman")


def is_service_running(service):
    active_line = run(f"systemctl is-active {service}")
    is_active = "inactive" not in active_line
    return is_active


def is_service_enabled(service):
    enabled_line = run(f"systemctl is-enabled {service}")
    is_enabled = "disabled" not in enabled_line
    return is_enabled


def is_service_removed(service):
    return not is_service_running(service) and not is_service_enabled(service)


def is_ufw_enabled():
    # Only for Ubuntu-ish distros
    if not is_program_installed("ufw"):
        return False
    enabled_line = run("ufw status")
    is_enabled = "inactive" not in enabled_line
    return is_enabled


def is_cron_job_set(command, frequency = "daily"):
    crondir = Path(f"/etc/cron.{frequency}")
    if crondir.exists():
        cronlinks = [f for f in crondir.iterdir() if f.is_file() and f.is_symlink() ]
        for link in cronlinks:
            if os.readlink(link) == shutil.which(command):
                return True
    return cron_job_search_text(command, frequency)


def cron_job_search_text(search_text, frequency = "daily"):
    grep = run(f"grep -Rl '{search_text}' /etc/cron.{frequency}").strip()
    executable = os.access(grep, os.X_OK)
    if grep != "" and executable:
        return True
    grep = run(f"grep '{search_text}' /etc/crontab")
    if grep != "":
        return True
    grep = run(f"grep -R '{search_text}' /var/spool/cron")
    return grep != ""


def is_daily_update_checked():
    if not is_program_installed("apt"):
        return False
    # Only works for Debian-based distros
    update_package_list = run("grep 'APT::Periodic::Update-Package_Lists' /etc/apt/apt.conf.d/*")
    return '1' in update_package_list


def is_auto_upgrade_enabled():
    if not is_program_installed("apt"):
        return False
    # Only works for Debian-based distros
    unattended_upgrade = run("grep 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/*")
    return '1' in unattended_upgrade


def GiB(bytes):
    return bytes/1024.0**3


def part_info(mountpoint):
    partitions = psutil.disk_partitions()
    return next((x for x in partitions if x.mountpoint == mountpoint), None)


def part_fs(mountpoint):
    info = part_info(mountpoint)
    if info is None:
        return info
    return info.fstype


def part_exists(mountpoint):
    return part_info(mountpoint) is not None


def check_partition_size(mountpoint, size):
    total_size = GiB(psutil.disk_usage(mountpoint).total)
    return math.isclose(size, total_size, rel_tol = 0.2) or (math.isclose(size, total_size, rel_tol = 0.2) and total_size > size)


def test_3G_of_memory():
    memory = GiB(psutil.virtual_memory().total)
    return math.isclose(memory, MEMORY_GB, abs_tol=0.2)


def test_2_processors():
    procs = psutil.cpu_count(logical=False)
    return procs == PROCESSORS


class Task:
    def __init__(self, name, function, arguments=None, expected=True, failmsg=None, print_if_failed=True):
        self.name = name
        self.function = function
        if isinstance(arguments, list) or isinstance(arguments, tuple):
            self.args = list(arguments)
        else:
            self.args = [arguments]
        self.expected = expected
        if failmsg is None:
            self.failmsg = f"Function {self.function.__name__} with arguments {self.args} was not {expected} as expected."
        else:
            self.failmsg = failmsg
        self.print_if_failed = print_if_failed


    def check(self):
        if len(self.args)==1 and self.args[0] is None:
            value = (self.function() == self.expected)
        else:
            value = (self.function(*self.args) == self.expected)
        return value


    def report_table(self):
        result = self.check()
        msg = "" if result else self.failmsg
        return result, self.name, msg, self.print_if_failed


    def report(self):
        result = self.check()
        icon = "\N{heavy check mark}" if result else "\N{heavy ballot x}"
        msg = "" if result else self.failmsg
        line = f"[{icon}]  {self.name: <35}   {msg}"
        return result, line


class TestSuite:
    def __init__(self, name="", tasks=None):
        self.name = name
        self.tasks = tasks if tasks is not None else []
        self.results = []

    
    def _is_secret(self):
        tasks_hidden = [not x.print_if_failed for x in self.tasks]
        return all(tasks_hidden)


    def report(self):
        if use_rich:
            self.rich_report()
        else:
            self.plain_report()

    def plain_report(self):
        results = []
        for task in self.tasks:
            result, report = task.report()
            results.append( (result, report, task.print_if_failed) )
        
        successes = [x[0] for x in results]
        
        if not self._is_secret() or any(successes):
            print(self.__doc__)
            for result, report, pif in results:
                if not result and not pif:
                    continue
                print(report)
            success_num = successes.count(True)
            summary_line = f"{success_num} Successful out of {len(results)}"
            print(summary_line)
        return successes


    def rich_report(self):
        results = [task.report_table() for task in self.tasks]
        successes = [x[0] for x in results]

        if not self._is_secret() or any(successes):
            table = Table.grid(expand=True, padding=(0, 2))
            table.add_column()
            table.add_column()
            table.add_column(style='red', overflow='fold', ratio=1)
            for result, name, msg, print_if_failed in results:
                if not print_if_failed and not result:
                    continue
                emoji = ":green_heart:" if result else ":no_entry_sign:"
                name = f"[green]{name}" if result else f"[red]{name}"
                table.add_row(f"[{emoji}]", name, msg)
            if self.name == "":
                title = Text(self.__doc__, justify='center')
            else:
                title = Text(self.name, justify='center')
            success_num = successes.count(True)
            summary_line = Text(f"{success_num} Successful out of {len(results)}", justify='right')
            panel_text = Group(title, table, '', summary_line)
            border_style = "green" if all(successes) else "red"
            panel = Panel(panel_text, highlight=True, border_style=border_style, width=100)
            print(panel)
        return successes



def TestSystemSpecifications():
    return TestSuite(
    """
    ================================================
    =               VM SPECIFICATION               =
    ================================================
    """,
    tasks = [
        Task("Memory Size", test_3G_of_memory, failmsg="Not 3G of memory"),
        Task("Processors", test_2_processors, failmsg="Should have 2 processors"),
        Task("Home Partition Exists", part_exists, "/home", failmsg="There is no separate home partition"),
        Task("Root Partition Size", check_partition_size, ["/", ROOT_SIZE_GB], failmsg="Root partition is wrong size"),
        Task("Home Partition Size", check_partition_size, ["/home", HOME_SIZE_GB], failmsg="Home partition is wrong size"),
        Task("Root Partition Filesystem", part_fs, "/", expected="ext4", failmsg="Root partition should be ext4 filesystem"),
        Task("Home Partition Filesystem", part_fs, "/home", expected="ext4", failmsg="Home partition should be ext4 filesystem"),
        Task("Hostname set", gethostname, expected="newguyscomp", failmsg="Hostname should be 'newguyscomp'"),
    ])


def TestUserSetup():
    return TestSuite(
    """
    ================================================
    =              USER CONFIGURATION              =
    ================================================
    """,
    tasks = [
        Task("Main user is named 'adminx'", main_user_name_ish, ["admin", 1000], failmsg="Main user should be 'adminx'"),
        Task("Admin password", check_password, [main_user(1000), "slotHMammoth7!"], failmsg="Admin password should be 'slotHMammoth7!'"),
        Task("Newguy User Exists", is_user, "newguy", failmsg="User 'newguy' doesn't exist"),
        Task("Newguy password", check_password, ["newguy", "guynew#5%"], failmsg="Newguy's password should be 'guynew#5%'"),
        Task("Newguy's sudo commands", check_sudo_commands, ["newguy", DEB_SUDO_COMMANDS, RH_SUDO_COMMANDS, ARCH_SUDO_COMMANDS], failmsg="Newguy's sudo commands incorrect"),
    ])


def TestSoftwareInstallations():
    tasks = [
        Task("Software is updated", is_software_uptodate,  failmsg="Software is not all upgraded"),
        Task("Yakuake or Guake installed", is_program_installed, ['yakuake', 'guake'], failmsg=f"Yakuake or Guake should be installed, depending on your desktop"),
    ]
    
    programs_to_install = {'Git': 'git', 'Vim': 'vim', 'BPython': 'bpython', 'Node.js': 'node', 'Visual Studio Code': 'code', 'Google Chrome': ['google-chrome', 'google-chrome-stable']}
    for prog, command in programs_to_install.items():
        tasks.append(
            Task(f"Program {prog} installed", is_program_installed, command, failmsg=f"Program {prog} should be installed")
        )
    tasks.append(
        Task("Cron job to run updatedb", is_cron_job_set, "updatedb", failmsg="Cron job should be set to run updatedb every day")
    )
    return TestSuite(
    """
    =================================================
    =             SOFTWARE INSTALLATION             = 
    =================================================
    """,
    tasks)
    

def TestPostgresSetup():
    return TestSuite(
    """
    =================================================
    =            DATABASE CONFIGURATION             = 
    =================================================
    """,
    tasks = [
        Task("Postgres service should be running", is_service_running, "postgresql", failmsg="Postgres server not running"),
        Task("Database user newguydb exists", pg_user_exists, "newguydb", failmsg="Postgres should have a user named newguydb"),
        Task("Database user has correct password", pg_user_password, ["newguydb", "postgresRulez!"], failmsg="Postgres user newguydb should have password 'postgresRulez!"),
        Task("Database widget_test exists", pg_database_exists, "widget_test", failmsg="Postgres database 'widget_test' should be created"),
        Task("Database owner correct", pg_database_owner, ["widget_test", "newguydb"], failmsg="Postgres database 'widget_test' should be owned by 'newguydb'"),
    ])


def TestBonusPoints():
    return TestSuite(
    """
    =================================================
    =                 BONUS POINTS                  = 
    =================================================
    """,
    tasks = [
        Task("Firewall Enabled", is_ufw_enabled, failmsg="Firewall not enabled", print_if_failed = False),
        Task("Check for updates daily", is_daily_update_checked, failmsg="Should automatically check for updates every day", print_if_failed = False),
        Task("Auto-upgrade", is_auto_upgrade_enabled, failmsg="Should automatically upgrade", print_if_failed = False)
    ])



#Requirements
MEMORY_GB = 3
PROCESSORS = 2
HOME_SIZE_GB = 5
ROOT_SIZE_GB = 20
PG_PASSWD_HASH = 'md51efb824c86d1810d4dc8cec3d54148a2'
DEB_SUDO_COMMANDS = {'/usr/bin/apt update', '/usr/bin/apt upgrade', '/usr/bin/systemctl restart postgresql'}
ARCH_SUDO_COMMANDS = {'/usr/bin/pacman -Sy', '/usr/bin/pacman -Syu', '/usr/bin/systemctl restart postgresql'}
RH_SUDO_COMMANDS = {'/usr/bin/dnf update', '/usr/bin/dnf upgrade', '/usr/bin/systemctl restart postgresql'}
NODE_VERSION = 14





if __name__ == "__main__":
    if pwd.getpwuid( os.getuid() ).pw_name != 'root':
        print("""Since the scoring software needs to access system configurations,
                it must be run with elevated privileges. Try again with 'sudo'.
            """)
        exit()
        

    tests = [
        TestSystemSpecifications(),
        TestUserSetup(),
        TestSoftwareInstallations(),
        TestPostgresSetup(),
        TestBonusPoints(),
    ]

    for test in tests:
        test.report()
    for alert in alerts:
        print(alerts)
